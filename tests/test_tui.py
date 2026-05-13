from vaultsieve import tui
from vaultsieve.errors import VaultSieveError


def test_tui_menu_exit_returns_zero(monkeypatch) -> None:
    monkeypatch.setattr(tui.Prompt, "ask", lambda *args, **kwargs: "3")

    assert tui.run_tui() == 0


def test_tui_controlled_error_returns_one(monkeypatch) -> None:
    responses = iter(["1"])
    monkeypatch.setattr(tui.Prompt, "ask", lambda *args, **kwargs: next(responses))

    def fail_audit(_console) -> None:
        raise VaultSieveError("controlled failure")

    monkeypatch.setattr(tui, "_run_guided_audit", fail_audit)

    assert tui.run_tui() == 1
