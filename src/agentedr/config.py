"""Configuration loading and validation (SPEC section 10).

Defaults live in the packaged ``data/default_config.yaml``. A user file is
deep-merged on top of it (mappings merge key by key; lists and scalars
replace) and the result is validated by the pydantic models below, which
reject unknown keys so typos fail loudly.
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

DEFAULT_CONFIG_PATH = Path("/etc/agentedr/config.yaml")
DEV_DIR = Path(".agentedr")

# Limits imposed by the sensor's BPF maps (SPEC 6.2, 7.2).
MAX_MATCHERS = 16
MAX_BASENAME_LEN = 15
MAX_PATH_FILTERS = 16
MAX_PATH_PREFIX_LEN = 63

Severity = Literal["info", "low", "medium", "high", "critical"]


class ConfigError(Exception):
    """Raised when the configuration file cannot be read or is invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AgentMatch(_Strict):
    exe_basename: list[str] = Field(default_factory=list)
    argv_contains: list[str] = Field(default_factory=list)

    @field_validator("exe_basename")
    @classmethod
    def _basename_fits_kernel(cls, v: list[str]) -> list[str]:
        for name in v:
            if not name or "/" in name or len(name.encode()) > MAX_BASENAME_LEN:
                raise ValueError(
                    f"exe_basename {name!r} must be 1-{MAX_BASENAME_LEN} bytes without '/'"
                )
        return v


class AgentConfig(_Strict):
    kind: str
    match: AgentMatch
    config_paths: list[str] = Field(default_factory=list)


class SensorConfig(_Strict):
    binary: Path | None
    mode: Literal["auto", "lsm", "fentry"]
    ringbuf_kib: int
    stats_interval_s: int = Field(gt=0)
    kernel_path_filter: list[str]

    @field_validator("ringbuf_kib")
    @classmethod
    def _power_of_two(cls, v: int) -> int:
        if v < 4 or v & (v - 1):
            raise ValueError("ringbuf_kib must be a power of two >= 4")
        return v

    @field_validator("kernel_path_filter")
    @classmethod
    def _filter_fits_kernel(cls, v: list[str]) -> list[str]:
        if len(v) > MAX_PATH_FILTERS:
            raise ValueError(f"at most {MAX_PATH_FILTERS} kernel path filters")
        for p in v:
            if not p or len(p.encode()) > MAX_PATH_PREFIX_LEN:
                raise ValueError(f"path filter {p!r} must be 1-{MAX_PATH_PREFIX_LEN} bytes")
        return v


class EngineConfig(_Strict):
    userspace_path_ignore: list[str]
    session_idle_ttl_s: int = Field(gt=0)
    workspace_root: Literal["root_cwd", "git_root"]


class RulesConfig(_Strict):
    builtin: bool
    extra_dirs: list[Path]
    disabled: list[str]
    severity_overrides: dict[str, Severity]


class EgressConfig(_Strict):
    allow: list[str]
    allow_loopback: bool
    allow_private: bool
    refresh_interval_s: int = Field(gt=0)


class AlertsConfig(_Strict):
    suppress_window_s: int = Field(ge=0)


class OutputConfig(_Strict):
    dir: Path
    db_path: Path
    events: Literal["none", "retained", "all"]
    rotate_mib: int = Field(gt=0)
    rotate_keep: int = Field(ge=0)
    record_raw: Path | None


class LoggingConfig(_Strict):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    format: Literal["text", "json"]


class Config(_Strict):
    version: Literal[1]
    agents: list[AgentConfig]
    sensor: SensorConfig
    engine: EngineConfig
    rules: RulesConfig
    egress: EgressConfig
    alerts: AlertsConfig
    output: OutputConfig
    logging: LoggingConfig

    @field_validator("agents")
    @classmethod
    def _matchers_fit_kernel(cls, v: list[AgentConfig]) -> list[AgentConfig]:
        n = sum(len(a.match.exe_basename) for a in v)
        if n > MAX_MATCHERS:
            raise ValueError(f"at most {MAX_MATCHERS} exe_basename matchers in total, got {n}")
        kinds = [a.kind for a in v]
        if len(set(kinds)) != len(kinds):
            raise ValueError("agent kinds must be unique")
        return v

    def kernel_matchers(self) -> list[dict[str, str | int]]:
        """Matchers for SET_MATCHERS. ``kind`` is the agent's index in ``agents``."""
        return [
            {"basename": name, "kind": idx}
            for idx, agent in enumerate(self.agents)
            for name in agent.match.exe_basename
        ]

    def agent_kind_name(self, kind: int) -> str:
        """Map a kernel ``agent_kind`` index back to the configured kind name."""
        if 0 <= kind < len(self.agents):
            return self.agents[kind].kind
        return f"unknown-{kind}"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_yaml(text: str, source: str) -> dict[str, Any]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{source}: invalid YAML: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{source}: top level must be a mapping")
    return data


def default_config_dict() -> dict[str, Any]:
    text = resources.files("agentedr").joinpath("data/default_config.yaml").read_text("utf-8")
    return _load_yaml(text, "default_config.yaml")


def load_config(path: Path | None = None, *, dev: bool = False) -> Config:
    """Load configuration.

    ``path=None`` reads ``/etc/agentedr/config.yaml`` if it exists, else uses
    defaults only. An explicitly given path must exist. ``dev`` redirects all
    writable paths under ``./.agentedr/`` (SPEC section 5).
    """
    data = default_config_dict()
    if path is not None or DEFAULT_CONFIG_PATH.exists():
        src = path or DEFAULT_CONFIG_PATH
        try:
            text = src.read_text("utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read config {src}: {exc}") from exc
        data = _deep_merge(data, _load_yaml(text, str(src)))
    if dev:
        data = _deep_merge(
            data, {"output": {"dir": str(DEV_DIR), "db_path": str(DEV_DIR / "sessions.db")}}
        )
    try:
        return Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration:\n{exc}") from exc
