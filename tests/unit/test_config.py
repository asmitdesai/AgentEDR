from __future__ import annotations

from pathlib import Path

import pytest

from agentedr.config import DEV_DIR, ConfigError, load_config


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(text)
    return p


def test_defaults_match_spec(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, ""))
    assert [a.kind for a in cfg.agents] == ["claude-code", "codex", "gemini-cli", "cursor-agent"]
    assert cfg.sensor.mode == "auto"
    assert cfg.sensor.ringbuf_kib == 256
    assert cfg.sensor.binary is None
    assert cfg.engine.workspace_root == "root_cwd"
    assert cfg.output.events == "retained"
    assert cfg.output.dir == Path("/var/log/agentedr")
    assert "api.anthropic.com" in cfg.egress.allow


def test_kernel_matchers_use_agent_index_as_kind(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, ""))
    assert cfg.kernel_matchers() == [
        {"basename": "claude", "kind": 0},
        {"basename": "codex", "kind": 1},
        {"basename": "cursor-agent", "kind": 3},
    ]
    assert cfg.agent_kind_name(0) == "claude-code"
    assert cfg.agent_kind_name(3) == "cursor-agent"
    assert cfg.agent_kind_name(99) == "unknown-99"


def test_override_merges_mappings_and_replaces_lists(tmp_path: Path) -> None:
    cfg = load_config(
        write(
            tmp_path,
            "sensor:\n  mode: fentry\n  kernel_path_filter: ['/proc/']\nlogging:\n  level: DEBUG\n",
        )
    )
    assert cfg.sensor.mode == "fentry"
    assert cfg.sensor.ringbuf_kib == 256  # untouched sibling key keeps its default
    assert cfg.sensor.kernel_path_filter == ["/proc/"]
    assert cfg.logging.level == "DEBUG"


def test_agents_list_replaces_defaults(tmp_path: Path) -> None:
    cfg = load_config(
        write(tmp_path, "agents:\n  - kind: mine\n    match:\n      exe_basename: [myagent]\n")
    )
    assert [a.kind for a in cfg.agents] == ["mine"]
    assert cfg.kernel_matchers() == [{"basename": "myagent", "kind": 0}]


def test_dev_mode_redirects_writable_paths(tmp_path: Path) -> None:
    cfg = load_config(write(tmp_path, ""), dev=True)
    assert cfg.output.dir == DEV_DIR
    assert cfg.output.db_path == DEV_DIR / "sessions.db"


@pytest.mark.parametrize(
    "text",
    [
        "bogus_key: 1\n",
        "sensor:\n  mode: turbo\n",
        "sensor:\n  ringbuf_kib: 300\n",
        "sensor:\n  kernel_path_filter: ['" + "x" * 64 + "']\n",
        "agents:\n  - kind: a\n    match:\n      exe_basename: ['sixteen-chars-xx']\n",
        "agents:\n  - kind: a\n    match:\n      exe_basename: ['bin/claude']\n",
        "agents:\n  - kind: a\n    match: {}\n  - kind: a\n    match: {}\n",
        "agents:\n  - kind: a\n    match:\n      exe_basename: ["
        + ",".join(f"n{i}" for i in range(17))
        + "]\n",
        "version: 2\n",
        "- just\n- a list\n",
        "sensor: [unclosed\n",
    ],
)
def test_invalid_configs_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, text))


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_yaml_tags_are_not_executed(tmp_path: Path) -> None:
    # safe_load refuses arbitrary Python object tags.
    with pytest.raises(ConfigError):
        load_config(write(tmp_path, "version: !!python/object/apply:os.system ['true']\n"))
