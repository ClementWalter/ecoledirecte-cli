"""Unit tests for ecoledirecte_cli's pure, network-free logic.

Covers the parts easy to get subtly wrong: the ``data=<json>`` body encoding,
student resolution by id/name, module gating, and account shape handling. No
network — the HTTP client and login flow are exercised live via `login`.
"""

import base64
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import ecoledirecte_cli  # noqa: E402
from ecoledirecte_cli import (  # noqa: E402
    EDError,
    decode_b64_text,
    encode_body,
    get_password,
    html_to_text,
    list_students,
    mailbox_path,
    module_enabled,
    primary_account,
    require_module,
    resolve_student,
    safe_filename,
    student_name,
)


# ---- fixtures -------------------------------------------------------------


@pytest.fixture
def student_thalie():
    """A student with only some modules enabled (mirrors the live account)."""
    return {
        "id": 16030,
        "prenom": "Thalie",
        "nom": "WALTER",
        "classe": {"libelle": "Terminale"},
        "modules": [
            {"code": "NOTES", "enable": False},
            {"code": "EDT", "enable": False},
            {"code": "DOCUMENTS_ELEVE", "enable": True},
        ],
    }


@pytest.fixture
def student_leo():
    return {
        "id": 20001,
        "prenom": "Léo",
        "nom": "WALTER",
        "modules": [{"code": "NOTES", "enable": True}],
    }


@pytest.fixture
def parent_cfg(student_thalie, student_leo):
    """A parent (typeCompte '1') account with two children."""
    return {
        "token": "tok",
        "accounts": [
            {
                "id": 15306,
                "main": True,
                "typeCompte": "1",
                "prenom": "Clément",
                "nom": "WALTER",
                "profile": {"eleves": [student_thalie, student_leo]},
            }
        ],
    }


@pytest.fixture
def student_cfg(student_leo):
    """A student (typeCompte 'E') account — it is itself the one student."""
    return {"token": "tok", "accounts": [{**student_leo, "main": True, "typeCompte": "E"}]}


# ---- encode_body ----------------------------------------------------------


def test_encode_body_wraps_json_in_data_field():
    assert encode_body({"a": 1}) == {"data": json.dumps({"a": 1})}


def test_encode_body_none_is_empty_object():
    assert encode_body(None) == {"data": "{}"}


def test_encode_body_preserves_special_password_chars():
    # A password with +, %, & must survive because the server url-decodes `data`.
    body = encode_body({"motdepasse": "a+b%c&d"})
    assert json.loads(body["data"])["motdepasse"] == "a+b%c&d"


# ---- primary_account ------------------------------------------------------


def test_primary_account_picks_main_flag(parent_cfg):
    assert primary_account(parent_cfg)["id"] == 15306


def test_primary_account_raises_without_accounts():
    with pytest.raises(EDError):
        primary_account({"accounts": []})


# ---- list_students --------------------------------------------------------


def test_list_students_parent_returns_children(parent_cfg):
    assert [s["id"] for s in list_students(parent_cfg)] == [16030, 20001]


def test_list_students_student_account_returns_self(student_cfg):
    assert list_students(student_cfg)[0]["id"] == 20001


# ---- resolve_student ------------------------------------------------------


def test_resolve_student_by_id(parent_cfg):
    assert resolve_student(parent_cfg, "20001")["prenom"] == "Léo"


def test_resolve_student_by_name_substring(parent_cfg):
    assert resolve_student(parent_cfg, "thal")["id"] == 16030


def test_resolve_student_ambiguous_requires_choice(parent_cfg):
    with pytest.raises(EDError):
        resolve_student(parent_cfg, None)


def test_resolve_student_single_defaults(student_cfg):
    assert resolve_student(student_cfg, None)["id"] == 20001


def test_resolve_student_unknown_raises(parent_cfg):
    with pytest.raises(EDError):
        resolve_student(parent_cfg, "nobody")


# ---- module gating --------------------------------------------------------


def test_module_enabled_true_when_on(student_leo):
    assert module_enabled(student_leo, "NOTES") is True


def test_module_enabled_false_when_off(student_thalie):
    assert module_enabled(student_thalie, "NOTES") is False


def test_module_enabled_false_when_absent(student_leo):
    assert module_enabled(student_leo, "EDT") is False


def test_require_module_raises_when_disabled(student_thalie):
    with pytest.raises(EDError):
        require_module(student_thalie, "NOTES", "Notes")


def test_require_module_passes_when_enabled(student_leo):
    assert require_module(student_leo, "NOTES", "Notes") is None


# ---- student_name ---------------------------------------------------------


def test_student_name_combines_first_last(student_leo):
    assert student_name(student_leo) == "Léo WALTER"


def test_student_name_falls_back_to_id():
    assert student_name({"id": 42}) == "42"


# ---- password storage precedence ------------------------------------------


def test_get_password_prefers_keychain(monkeypatch):
    monkeypatch.setattr(ecoledirecte_cli, "fetch_password", lambda ident: "from-keychain")
    assert get_password({"identifiant": "u", "password": "from-config"}) == "from-keychain"


def test_get_password_falls_back_to_config(monkeypatch):
    monkeypatch.setattr(ecoledirecte_cli, "fetch_password", lambda ident: None)
    assert get_password({"identifiant": "u", "password": "from-config"}) == "from-config"


def test_get_password_none_when_nothing_stored(monkeypatch):
    monkeypatch.setattr(ecoledirecte_cli, "fetch_password", lambda ident: None)
    assert get_password({"identifiant": "u"}) is None


# ---- message body decoding ------------------------------------------------


def test_decode_b64_text_decodes_base64():
    encoded = base64.b64encode("Bonjour".encode()).decode()
    assert decode_b64_text(encoded) == "Bonjour"


def test_decode_b64_text_passes_through_plain():
    # Non-base64 (has a space) is returned unchanged rather than crashing.
    assert decode_b64_text("hello world !!") == "hello world !!"


def test_html_to_text_breaks_on_block_tags():
    assert html_to_text("<p>Line 1</p><p>Line 2</p>") == "Line 1\nLine 2"


def test_html_to_text_unescapes_entities():
    assert html_to_text("caf&eacute; &amp; th&eacute;") == "café & thé"


def test_html_to_text_converts_br_to_newline():
    assert html_to_text("a<br>b<br/>c") == "a\nb\nc"


# ---- safe_filename --------------------------------------------------------


def test_safe_filename_keeps_normal_name():
    assert safe_filename("Coupon 2025.pdf", "fallback") == "Coupon 2025.pdf"


def test_safe_filename_strips_path_traversal():
    assert safe_filename("../../etc/passwd", "fallback") == "passwd"


def test_safe_filename_uses_fallback_when_empty():
    assert safe_filename("", "attachment_9") == "attachment_9"


# ---- mailbox_path ---------------------------------------------------------


def test_mailbox_path_parent_uses_familles():
    assert mailbox_path({"typeCompte": "1", "id": 15306}) == "familles/15306"


def test_mailbox_path_student_uses_eleves():
    assert mailbox_path({"typeCompte": "E", "id": 20001}) == "eleves/20001"


# ---- 2FA base64 round-trip (the shape doubleauth relies on) ---------------


def test_doubleauth_answer_base64_roundtrip():
    answer = "Jean Dupont"
    encoded = base64.b64encode(answer.encode()).decode()
    assert base64.b64decode(encoded).decode() == answer
