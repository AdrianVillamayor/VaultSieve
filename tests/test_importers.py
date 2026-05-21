import json

import pytest

from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.errors import VaultSieveError
from vaultsieve.importers.bitwarden import import_bitwarden
from vaultsieve.importers.csv_generic import import_csv
from vaultsieve.models import AuditOptions


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
                            "totp": "otpauth://totp/example",
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
    assert credentials[0].has_totp is True
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


def test_import_bitwarden_empty_items(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"items": []}), encoding="utf-8")

    assert import_bitwarden(path) == ()


def test_import_bitwarden_missing_items_key(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")

    with pytest.raises(VaultSieveError, match="items"):
        import_bitwarden(path)


def test_import_bitwarden_invalid_json(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text("not json", encoding="utf-8")

    with pytest.raises(VaultSieveError, match="Invalid Bitwarden JSON"):
        import_bitwarden(path)


def test_import_bitwarden_skips_non_login_types(tmp_path) -> None:
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps(
            {
                "items": [
                    {"type": 2, "name": "Secure note"},
                    {"type": 3, "name": "Card"},
                    {"type": 4, "name": "Identity"},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert import_bitwarden(path) == ()


def test_import_csv_empty_file_with_headers(tmp_path) -> None:
    path = tmp_path / "passwords.csv"
    path.write_text("name,url,username,password\n", encoding="utf-8")

    assert import_csv(path) == ()


def test_import_csv_handles_null_values(tmp_path) -> None:
    path = tmp_path / "passwords.csv"
    path.write_text("name,url,username,password\n,,,\n", encoding="utf-8")

    credentials = import_csv(path)

    assert len(credentials) == 1
    assert credentials[0].name == ""
    assert credentials[0].username == ""
    assert credentials[0].password == ""
    assert credentials[0].urls == ()


# --- LastPass ---


def test_lastpass_csv_import(tmp_path):
    path = tmp_path / "lastpass.csv"
    path.write_text(
        "url,username,password,totp,extra,name,grouping,fav\n"
        "https://github.com,alice,Secret123!,,note,GitHub,Dev,0\n"
        "https://gmail.com,bob,Pass456!,JBSWY3DPEHPK3PXP,,Gmail,,1\n",
        encoding="utf-8",
    )
    report = run_audit(path, "lastpass", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].name == "GitHub"
    assert report.credentials[0].urls == ("https://github.com",)
    assert report.credentials[1].has_totp is True
    assert report.credentials[0].has_totp is False


def test_lastpass_missing_columns(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("url,password\nhttps://x.com,pass\n", encoding="utf-8")
    with pytest.raises(VaultSieveError, match="missing required columns"):
        run_audit(path, "lastpass", AuditOptions())


# --- Dashlane ---


def test_dashlane_csv_import(tmp_path):
    path = tmp_path / "dashlane.csv"
    path.write_text(
        "username,username2,username3,title,password,note,url,category,otpUrl\n"
        "alice,,,GitHub,Secret123!,,https://github.com,Dev,\n"
        "bob,,,Gmail,Pass456!,,https://gmail.com,Email,otpauth://totp/test\n",
        encoding="utf-8",
    )
    report = run_audit(path, "dashlane", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].name == "GitHub"
    assert report.credentials[0].username == "alice"
    assert report.credentials[1].has_totp is True


def test_dashlane_json_import(tmp_path):
    path = tmp_path / "dashlane.json"
    data = {
        "AUTHENTIFIANT": [
            {
                "title": "GitHub",
                "domain": "github.com",
                "login": "alice",
                "password": "Secret123!",
                "otpSecret": "",
            },
            {
                "title": "Gmail",
                "domain": "gmail.com",
                "login": "bob",
                "password": "Pass456!",
                "otpSecret": "TOTP123",
            },
        ]
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    report = run_audit(path, "dashlane", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].urls == ("https://github.com",)
    assert report.credentials[1].has_totp is True


def test_dashlane_json_invalid_structure(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"items": "not a list"}', encoding="utf-8")
    with pytest.raises(VaultSieveError, match="AUTHENTIFIANT"):
        run_audit(path, "dashlane", AuditOptions())


# --- 1Password ---


def test_onepassword_csv_import(tmp_path):
    path = tmp_path / "1password.csv"
    path.write_text(
        "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
        "GitHub,https://github.com,alice,Secret123!,,false,false,,dev account\n",
        encoding="utf-8",
    )
    report = run_audit(path, "1password", AuditOptions())
    assert len(report.credentials) == 1
    assert report.credentials[0].name == "GitHub"
    assert report.credentials[0].source == "1password"


# --- KeePass ---


def test_keepass_csv_import(tmp_path):
    path = tmp_path / "keepass.csv"
    path.write_text(
        "Group,Title,Username,Password,URL,Notes,TOTP\n"
        "Root/Banking,MyBank,alice,Secret123!,https://bank.com,,\n"
        "Root/Email,Gmail,bob,Pass456!,https://gmail.com,,otpauth://totp/test\n",
        encoding="utf-8",
    )
    report = run_audit(path, "keepass", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].name == "MyBank"
    assert report.credentials[1].has_totp is True


def test_keepass_xml_import(tmp_path):
    path = tmp_path / "keepass.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        "<KeePassFile><Root><Group><Name>Root</Name>\n"
        "<Entry><String><Key>Title</Key><Value>GitHub</Value></String>"
        "<String><Key>UserName</Key><Value>alice</Value></String>"
        "<String><Key>Password</Key><Value>Secret123!</Value></String>"
        "<String><Key>URL</Key><Value>https://github.com</Value></String>"
        "<String><Key>Notes</Key><Value></Value></String></Entry>\n"
        "<Group><Name>Recycle Bin</Name>"
        "<Entry><String><Key>Title</Key><Value>Deleted</Value></String>"
        "<String><Key>UserName</Key><Value>gone</Value></String>"
        "<String><Key>Password</Key><Value>nope</Value></String>"
        "<String><Key>URL</Key><Value>https://gone.com</Value></String>"
        "</Entry></Group>\n"
        "</Group></Root></KeePassFile>",
        encoding="utf-8",
    )
    report = run_audit(path, "keepass", AuditOptions())
    assert len(report.credentials) == 1
    assert report.credentials[0].name == "GitHub"


def test_keepass_xml_invalid(tmp_path):
    path = tmp_path / "bad.xml"
    path.write_text("<KeePassFile><Root></Root></KeePassFile>", encoding="utf-8")
    with pytest.raises(VaultSieveError, match="Root/Group"):
        run_audit(path, "keepass", AuditOptions())


# --- Keeper ---


def test_keeper_csv_import_headerless(tmp_path):
    path = tmp_path / "keeper.csv"
    path.write_text(
        '"Finance","MyBank","alice","Secret123!","https://bank.com","",""\n'
        '"Email","Gmail","bob","Pass456!","https://gmail.com","","otpauth://totp/test"\n',
        encoding="utf-8",
    )
    report = run_audit(path, "keeper", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].name == "MyBank"
    assert report.credentials[0].username == "alice"
    assert report.credentials[1].has_totp is True


def test_keeper_csv_import_with_headers(tmp_path):
    path = tmp_path / "keeper.csv"
    path.write_text(
        "Folder,Title,Login,Password,Website Address,Notes,TOTP\n"
        "Finance,MyBank,alice,Secret123!,https://bank.com,,\n",
        encoding="utf-8",
    )
    report = run_audit(path, "keeper", AuditOptions())
    assert len(report.credentials) == 1
    assert report.credentials[0].name == "MyBank"


def test_keeper_json_import(tmp_path):
    path = tmp_path / "keeper.json"
    data = {
        "records": [
            {
                "title": "GitHub",
                "login": "alice",
                "password": "Secret123!",
                "login_url": "https://github.com",
                "totp": "",
            },
            {
                "title": "Gmail",
                "login": "bob",
                "password": "Pass456!",
                "login_url": "https://gmail.com",
                "totp": "otpauth://totp/test",
            },
        ]
    }
    path.write_text(json.dumps(data), encoding="utf-8")
    report = run_audit(path, "keeper", AuditOptions())
    assert len(report.credentials) == 2
    assert report.credentials[0].urls == ("https://github.com",)
    assert report.credentials[1].has_totp is True


def test_keeper_json_invalid_structure(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"data": []}', encoding="utf-8")
    with pytest.raises(VaultSieveError, match="records"):
        run_audit(path, "keeper", AuditOptions())


# --- RoboForm ---


def test_roboform_csv_import_with_bom(tmp_path):
    path = tmp_path / "roboform.csv"
    text = (
        "Name,Url,MatchUrl,Login,Pwd,Note,Folder,RfFieldsV2\n"
        "GitHub,https://github.com,https://github.com,alice,Secret123!,,Dev,\n"
    )
    path.write_bytes(b"\xef\xbb\xbf" + text.encode("utf-8"))
    report = run_audit(path, "roboform", AuditOptions())
    assert len(report.credentials) == 1
    assert report.credentials[0].name == "GitHub"
    assert report.credentials[0].username == "alice"


# --- Clean output for new formats ---


def test_clean_output_lastpass(tmp_path):
    input_path = tmp_path / "lastpass.csv"
    output_path = tmp_path / "clean.csv"
    input_path.write_text(
        "url,username,password,totp,extra,name,grouping,fav\n"
        "https://x.com,alice,Same123!,,,Dup1,,0\n"
        "https://x.com,alice,Same123!,,,Dup1,,0\n",
        encoding="utf-8",
    )
    report = run_audit(input_path, "lastpass", AuditOptions())
    removed = write_clean_output(
        input_path, output_path, "lastpass", report.credentials,
        duplicate_remove_ids={"lastpass:1"},
    )
    assert removed == 1
    lines = output_path.read_text(encoding="utf-8").strip().split("\n")
    assert len(lines) == 2
    assert "url,username,password,totp,extra,name,grouping,fav" in lines[0]


def test_clean_output_dashlane_json(tmp_path):
    input_path = tmp_path / "dashlane.json"
    output_path = tmp_path / "clean.json"
    data = {
        "AUTHENTIFIANT": [
            {"title": "Dup", "login": "a", "password": "Same123!", "domain": "x.com"},
            {"title": "Dup", "login": "a", "password": "Same123!", "domain": "x.com"},
        ]
    }
    input_path.write_text(json.dumps(data), encoding="utf-8")
    report = run_audit(input_path, "dashlane", AuditOptions())
    removed = write_clean_output(
        input_path, output_path, "dashlane", report.credentials,
        duplicate_remove_ids={"dashlane:1"},
    )
    assert removed == 1
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(result["AUTHENTIFIANT"]) == 1


def test_clean_output_keeper_json(tmp_path):
    input_path = tmp_path / "keeper.json"
    output_path = tmp_path / "clean.json"
    data = {
        "records": [
            {"title": "Dup", "login": "a", "password": "Same123!", "login_url": "https://x.com"},
            {"title": "Dup", "login": "a", "password": "Same123!", "login_url": "https://x.com"},
        ]
    }
    input_path.write_text(json.dumps(data), encoding="utf-8")
    report = run_audit(input_path, "keeper", AuditOptions())
    removed = write_clean_output(
        input_path, output_path, "keeper", report.credentials,
        duplicate_remove_ids={"keeper:1"},
    )
    assert removed == 1
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(result["records"]) == 1
