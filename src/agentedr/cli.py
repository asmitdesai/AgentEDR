"""Command-line interface (SPEC section 14).

M0 provides ``agentedr run``: start the sensor and print agent session starts
and ends (and, with ``--show-events``, every event of a tagged session).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from agentedr.config import Config, ConfigError, load_config
from agentedr.models import Event, ExecEvent, ExitEvent
from agentedr.supervisor import SensorError, Supervisor

app = typer.Typer(
    help="AgentEDR: kernel-level detection for hijacked AI coding agents.",
    no_args_is_help=True,
    add_completion=False,
)
log = logging.getLogger("agentedr")

EXIT_ERROR = 1
EXIT_USAGE = 2


class Mode(StrEnum):
    auto = "auto"
    lsm = "lsm"
    fentry = "fentry"


ConfigOpt = Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")]
DevOpt = Annotated[bool, typer.Option("--dev", help="Use ./.agentedr/ for all writable paths.")]


def _setup_logging(config: Config) -> None:
    logging.basicConfig(
        level=config.logging.level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _load(config_path: Path | None, dev: bool) -> Config:
    try:
        return load_config(config_path, dev=dev)
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(EXIT_USAGE) from exc


@app.callback()
def main() -> None:
    """AgentEDR command-line interface."""


@dataclass
class _SessionPrinter:
    """Minimal M0 session view: start on session_start EXEC, end on root EXIT.

    Full session lifecycle (descendant tracking, TTL, interrupted) is M1.
    """

    config: Config
    show_events: bool
    sessions: dict[int, tuple[str, int]] = field(default_factory=dict)

    def __call__(self, ev: Event) -> None:
        if isinstance(ev, ExecEvent) and ev.untagged:
            return  # argv matching (tagger) arrives in M1
        kind = self.config.agent_kind_name(ev.agent_kind)
        if isinstance(ev, ExecEvent) and ev.session_start:
            self.sessions[ev.session_id] = (kind, ev.pid)
            typer.echo(
                f"SESSION START  session={ev.session_id} agent={kind} pid={ev.pid} "
                f"exe={ev.filename} argv={_fmt_argv(ev.argv)}"
            )
        elif self.show_events:
            typer.echo(_fmt_event(ev))
        if isinstance(ev, ExitEvent) and ev.is_root:
            self.sessions.pop(ev.session_id, None)
            typer.echo(
                f"SESSION END    session={ev.session_id} agent={kind} pid={ev.pid} "
                f"exit_code={ev.exit_code}"
            )


def _fmt_argv(argv: list[str], limit: int = 160) -> str:
    text = " ".join(argv)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _fmt_event(ev: Event) -> str:
    head = f"{ev.type:<5} session={ev.session_id} pid={ev.pid} ppid={ev.ppid} comm={ev.comm}"
    if isinstance(ev, ExecEvent):
        return f"{head} argv={_fmt_argv(ev.argv)}"
    return f"{head} exit_code={ev.exit_code}"


async def _run(config: Config, mode: str | None, allow_nonroot: bool, show_events: bool) -> int:
    sup = Supervisor(
        config,
        _SessionPrinter(config, show_events),
        mode=mode,
        allow_nonroot=allow_nonroot,
    )
    try:
        await sup.start()
    except SensorError as exc:
        log.error("%s", exc)
        return EXIT_ERROR

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    stop_task = asyncio.create_task(stop.wait())
    exit_task = asyncio.create_task(sup.wait())
    await asyncio.wait({stop_task, exit_task}, return_when=asyncio.FIRST_COMPLETED)
    for task in (stop_task, exit_task):
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    if stop.is_set():
        log.info("shutting down")
        await sup.stop()
        return 0
    log.error("sensor exited unexpectedly with code %s", sup.returncode)
    return EXIT_ERROR


@app.command()
def run(
    config_path: ConfigOpt = None,
    dev: DevOpt = False,
    mode: Annotated[Mode | None, typer.Option("--mode", help="Sensor mode override.")] = None,
    allow_nonroot: Annotated[
        bool, typer.Option("--allow-nonroot", help="Development only: skip the root check.")
    ] = False,
    show_events: Annotated[
        bool, typer.Option("--show-events", help="Print every event of tagged sessions.")
    ] = False,
) -> None:
    """Start the sensor and engine in the foreground."""
    config = _load(config_path, dev)
    _setup_logging(config)
    code = asyncio.run(_run(config, mode.value if mode else None, allow_nonroot, show_events))
    raise typer.Exit(code)
