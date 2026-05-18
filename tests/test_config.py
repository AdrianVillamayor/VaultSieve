from vaultsieve.config import AppConfig, config_path, load_config, reset_config, set_config_value


def test_config_reset_restores_defaults(tmp_path) -> None:
    path = tmp_path / "config.json"
    set_config_value("check_domains", "true", path)

    reset_config(path)

    assert load_config(path) == AppConfig()
    assert load_config(path).check_domains is False


def test_config_path_can_be_overridden(monkeypatch, tmp_path) -> None:
    path = tmp_path / "custom.json"
    monkeypatch.setenv("VAULTSIEVE_CONFIG_PATH", str(path))

    assert config_path() == path
