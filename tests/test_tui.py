from vaultsieve import tui
from vaultsieve.errors import VaultSieveError


def test_tui_menu_exit_returns_zero(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VAULTSIEVE_CONFIG_PATH", str(config_path))
    monkeypatch.setattr(tui.Prompt, "ask", lambda *args, **kwargs: "4")

    assert tui.run_tui() == 0


def test_tui_controlled_error_returns_one(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("VAULTSIEVE_CONFIG_PATH", str(config_path))
    responses = iter(["1"])
    monkeypatch.setattr(tui.Prompt, "ask", lambda *args, **kwargs: next(responses))

    def fail_audit(_console) -> None:
        raise VaultSieveError("controlled failure")

    monkeypatch.setattr(tui, "_run_guided_audit", fail_audit)

    assert tui.run_tui() == 1


def test_tui_first_run_writes_config(monkeypatch, tmp_path) -> None:
    config_path = tmp_path / "config.json"
    monkeypatch.setenv("VAULTSIEVE_CONFIG_PATH", str(config_path))
    prompt_responses = iter(["4", "16", "12", "", "all", "4"])

    monkeypatch.setattr(tui.Confirm, "ask", lambda *args, **kwargs: kwargs["default"])
    monkeypatch.setattr(
        tui.Prompt,
        "ask",
        lambda *args, **kwargs: next(prompt_responses, kwargs.get("default", "")),
    )

    assert tui.run_tui() == 0
    assert config_path.exists()
