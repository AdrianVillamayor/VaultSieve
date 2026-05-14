import json

import pytest

from vaultsieve.errors import VaultSieveError
from vaultsieve.importers.bitwarden import import_bitwarden
from vaultsieve.importers.csv_generic import import_csv


def test_import_bitwarden_login_items(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "type": 1,
                        "name": "Example",
                        "login": {
                            "username": "alice",
                            "password": "Secret123!",
                            "uris": [{"uri": "https://example.com"}],
                        },
                    },
                    {"type": 2, "name": "Secure note"},
                ]
            }
        ),
        encoding="utf-8",
    )

    credentials = import_bitwarden(path)

    assert len(credentials) == 1
    assert credentials[0].id == "bitwarden:0"
    assert credentials[0].urls == ("https://example.com",)


def test_import_bitwarden_marks_passkeys_and_ssh_keys(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "type": 1,
                        "name": "Passkey",
                        "login": {
                            "username": "alice",
                            "fido2Credentials": [{"credentialId": "abc"}],
                        },
                    },
                    {
                        "type": 5,
                        "name": "Server key",
                        "sshKey": {"privateKey": "secret"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    credentials = import_bitwarden(path)

    assert credentials[0].has_passkey is True
    assert credentials[0].is_ssh_key is False
    assert credentials[1].is_ssh_key is True


def test_import_csv_requires_columns(tmp_path) -> None:
    path = tmp_path / "bad.csv"
    path.write_text("name,url,username\nExample,https://example.com,alice\n", encoding="utf-8")

    with pytest.raises(VaultSieveError, match="password"):
        import_csv(path)


def test_import_csv_credentials(tmp_path) -> None:
    path = tmp_path / "passwords.csv"
    path.write_text(
        "name,url,username,password\nExample,https://example.com,alice,Secret123!\n",
        encoding="utf-8",
    )

    credentials = import_csv(path)

    assert len(credentials) == 1
    assert credentials[0].source == "csv"
    assert credentials[0].password == "Secret123!"
