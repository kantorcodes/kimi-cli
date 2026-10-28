import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

_PATH = Path(__file__).parents[2] / "examples" / "hooks" / "hol_guard_pre_tool.py"
_spec = importlib.util.spec_from_file_location("hol_guard_pre_tool", _PATH)
assert _spec and _spec.loader
module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(module)


def _event(command: str = "git status") -> dict:
    return {"hook_event_name": "PreToolUse", "tool_name": "Shell", "tool_input": {"command": command}}


@pytest.mark.parametrize(("returncode", "output", "expected"), [
    (0, '{"classification":{"explicitly_benign":true},"minimum_action":"allow"}', 0),
    (0, '{"classification":{"explicitly_benign":false},"minimum_action":"allow"}', 2),
    (0, '{"classification":{"explicitly_benign":true},"minimum_action":"review"}', 2),
    (1, "", 2),
])
def test_guard_decisions(monkeypatch, returncode: int, output: str, expected: int) -> None:
    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/hol-guard")
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=returncode, stdout=output))
    assert module.evaluate(_event()) == expected


def test_missing_command_or_guard_blocks(monkeypatch) -> None:
    assert module.evaluate(_event("")) == 2
    monkeypatch.setattr(module.shutil, "which", lambda _: None)
    assert module.evaluate(_event()) == 2


@pytest.mark.parametrize("command", ["-n", "--help", "echo 'hello world'", "printf 'a\\nb'"])
def test_guard_command_remains_one_positional_argument(monkeypatch, command: str) -> None:
    """Prevent a command starting with '-' from becoming a Guard CLI option."""
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(
            returncode=0,
            stdout='{"classification":{"explicitly_benign":true},"minimum_action":"allow"}',
        )

    monkeypatch.setattr(module.shutil, "which", lambda _: "/usr/bin/hol-guard")
    monkeypatch.setattr(module.subprocess, "run", fake_run)
    assert module.evaluate(_event(command)) == 0
    assert calls == [["/usr/bin/hol-guard", "command", "test", "--json", "--", command]]
