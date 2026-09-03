"""Unit tests for ecoledirecte_cli's pure, network-free logic.

Covers the parts easy to get subtly wrong: the ``data=<json>`` body encoding,
student resolution by id/name, module gating, account shape handling, and the
message composition layer (HTML body, entity escaping, recipients, payload).
No network — the HTTP client, login flow and the send/upload endpoints are
exercised live (``--draft`` saves without sending).
"""

import base64
import json
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))
import ecoledirecte_cli  # noqa: E402
from ecoledirecte_cli import (  # noqa: E402
    EDError,
    build_message,
    cli,
    decode_b64_text,
    encode_body,
    encode_message_content,
    escape_html_entities,
    get_password,
    group_recipients,
    html_to_text,
    is_read,
    is_self,
    list_students,
    mailbox_path,
    module_enabled,
    primary_account,
    quote_original,
    read_body,
    recipient,
    reply_subject,
    require_module,
    resolve_recipient,
    resolve_student,
    safe_filename,
    student_name,
    text_to_html,
)


# ---- fixtures -------------------------------------------------------------


@pytest.fixture
def student_alice():
    """A student with only some modules enabled (mirrors the live account)."""
    return {
        "id": 1001,
        "prenom": "Alice",
        "nom": "DUPONT",
        "classe": {"libelle": "Terminale"},
        "modules": [
            {"code": "NOTES", "enable": False},
            {"code": "EDT", "enable": False},
            {"code": "DOCUMENTS_ELEVE", "enable": True},
        ],
    }


@pytest.fixture
def student_bob():
    return {
        "id": 1002,
        "prenom": "Bob",
        "nom": "DUPONT",
        "modules": [{"code": "NOTES", "enable": True}],
    }


@pytest.fixture
def parent_cfg(student_alice, student_bob):
    """A parent (typeCompte '1') account with two children."""
    return {
        "token": "tok",
        "accounts": [
            {
                "id": 2001,
                "main": True,
                "typeCompte": "1",
                "prenom": "Jean",
                "nom": "DUPONT",
                "profile": {"eleves": [student_alice, student_bob]},
            }
        ],
    }


@pytest.fixture
def student_cfg(student_bob):
    """A student (typeCompte 'E') account — it is itself the one student."""
    return {"token": "tok", "accounts": [{**student_bob, "main": True, "typeCompte": "E"}]}


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
    assert primary_account(parent_cfg)["id"] == 2001


def test_primary_account_raises_without_accounts():
    with pytest.raises(EDError):
        primary_account({"accounts": []})


# ---- list_students --------------------------------------------------------


def test_list_students_parent_returns_children(parent_cfg):
    assert [s["id"] for s in list_students(parent_cfg)] == [1001, 1002]


def test_list_students_student_account_returns_self(student_cfg):
    assert list_students(student_cfg)[0]["id"] == 1002


# ---- resolve_student ------------------------------------------------------


def test_resolve_student_by_id(parent_cfg):
    assert resolve_student(parent_cfg, "1002")["prenom"] == "Bob"


def test_resolve_student_by_name_substring(parent_cfg):
    assert resolve_student(parent_cfg, "ali")["id"] == 1001


def test_resolve_student_ambiguous_requires_choice(parent_cfg):
    with pytest.raises(EDError):
        resolve_student(parent_cfg, None)


def test_resolve_student_single_defaults(student_cfg):
    assert resolve_student(student_cfg, None)["id"] == 1002


def test_resolve_student_unknown_raises(parent_cfg):
    with pytest.raises(EDError):
        resolve_student(parent_cfg, "nobody")


# ---- module gating --------------------------------------------------------


def test_module_enabled_true_when_on(student_bob):
    assert module_enabled(student_bob, "NOTES") is True


def test_module_enabled_false_when_off(student_alice):
    assert module_enabled(student_alice, "NOTES") is False


def test_module_enabled_false_when_absent(student_bob):
    assert module_enabled(student_bob, "EDT") is False


def test_require_module_raises_when_disabled(student_alice):
    with pytest.raises(EDError):
        require_module(student_alice, "NOTES", "Notes")


def test_require_module_passes_when_enabled(student_bob):
    assert require_module(student_bob, "NOTES", "Notes") is None


# ---- student_name ---------------------------------------------------------


def test_student_name_combines_first_last(student_bob):
    assert student_name(student_bob) == "Bob DUPONT"


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


# ---- is_read (the API sends read as a string) -----------------------------


def test_is_read_true_string():
    assert is_read({"read": "True"}) is True


def test_is_read_false_string_is_not_read():
    # The bug this guards: "False" is a truthy string, so a naive check misfires.
    assert is_read({"read": "False"}) is False


def test_is_read_missing_is_not_read():
    assert is_read({}) is False


# ---- safe_filename --------------------------------------------------------


def test_safe_filename_keeps_normal_name():
    assert safe_filename("Coupon 2025.pdf", "fallback") == "Coupon 2025.pdf"


def test_safe_filename_strips_path_traversal():
    assert safe_filename("../../etc/passwd", "fallback") == "passwd"


def test_safe_filename_uses_fallback_when_empty():
    assert safe_filename("", "attachment_9") == "attachment_9"


# ---- mailbox_path ---------------------------------------------------------


def test_mailbox_path_parent_uses_familles():
    assert mailbox_path({"typeCompte": "1", "id": 2001}) == "familles/2001"


def test_mailbox_path_student_uses_eleves():
    assert mailbox_path({"typeCompte": "E", "id": 1002}) == "eleves/1002"


# ---- 2FA base64 round-trip (the shape doubleauth relies on) ---------------


def test_doubleauth_answer_base64_roundtrip():
    answer = "Jean Dupont"
    encoded = base64.b64encode(answer.encode()).decode()
    assert base64.b64decode(encoded).decode() == answer


# ---- stale-token recovery (retry-once on 520/525) -------------------------


@pytest.fixture
def flaky_client(parent_cfg, monkeypatch):
    """A client whose first call fails with a given code, second call succeeds.

    Records whether ``_reauth`` ran, so a test can assert the recovery path
    without any network or credential access.
    """

    def make(code):
        client = ecoledirecte_cli.EDClient(parent_cfg, session=object())
        calls = {"posts": 0, "reauth": 0}

        def fake_post_once(path, payload, verbe, extra):
            calls["posts"] += 1
            if calls["posts"] == 1:
                raise EDError("Token invalide !", code=code)
            return {"ok": True}

        monkeypatch.setattr(client, "_post_once", fake_post_once)
        monkeypatch.setattr(client, "_reauth", lambda: calls.__setitem__("reauth", 1))
        monkeypatch.setattr(ecoledirecte_cli, "get_password", lambda cfg: "hunter2")
        return client, calls

    return make


def test_post_retries_after_invalid_token_520(flaky_client):
    client, calls = flaky_client(520)
    assert client.post("familles/1/messages.awp") == {"ok": True}


def test_post_reauths_once_on_invalid_token_520(flaky_client):
    client, calls = flaky_client(520)
    client.post("familles/1/messages.awp")
    assert calls["reauth"] == 1


def test_post_retries_after_expired_token_525(flaky_client):
    client, calls = flaky_client(525)
    assert client.post("familles/1/messages.awp") == {"ok": True}


def test_post_does_not_retry_other_errors(flaky_client):
    client, calls = flaky_client(505)
    with pytest.raises(EDError):
        client.post("familles/1/messages.awp")


# ---- CLI surface ----------------------------------------------------------


@pytest.fixture
def runner():
    """Click's in-process invoker, so help/version need no subprocess."""
    return CliRunner()


def test_short_help_flag_is_accepted(runner):
    assert runner.invoke(cli, ["-h"]).exit_code == 0


def test_help_lists_every_command(runner):
    listed = runner.invoke(cli, ["-h"]).output
    assert {name for name in cli.commands} <= set(listed.split())


def test_version_flag_prints_version(runner):
    assert ecoledirecte_cli.__version__ in runner.invoke(cli, ["--version"]).output


# ---- message composition --------------------------------------------------


@pytest.fixture
def staff_contact():
    """A directory entry as `messagerie/contacts/personnels` returns it."""
    return {
        "civilite": "Mme",
        "prenom": "Marie",
        "particule": "",
        "nom": "MARTIN",
        "id": 301,
        "type": "A",
        "fonction": {"id": 10, "libelle": "Comptabilité"},
        "classe": {"id": 0, "code": "-", "libelle": "-"},
        "responsable": {"id": 0},
    }


@pytest.fixture
def directory(staff_contact):
    """Two staff members sharing a function word, to exercise ambiguity."""
    return [
        staff_contact,
        {**staff_contact, "id": 302, "prenom": "Sophie", "nom": "DURAND",
         "fonction": {"id": 11, "libelle": "Responsable Comptable"}},
    ]


@pytest.fixture
def received_message():
    """A received message as `messages/<id>.awp` returns it (content base64 HTML)."""
    return {
        "id": 200,
        "subject": "Circulaire",
        "date": "2026-09-01 16:05:30",
        "content": base64.b64encode(b"<p>Bonne rentr&#233;e</p>").decode(),
        "from": {"nom": "BERNARD", "prenom": "A.", "civilite": "Mme", "role": "A",
                 "id": 303, "fonctionPersonnel": "Secrétariat"},
        "to": [],
    }


def test_text_to_html_blank_line_splits_paragraphs():
    assert text_to_html("a\n\nb") == "<p>a</p><p>b</p>"


def test_text_to_html_single_newline_is_br():
    assert text_to_html("a\nb") == "<p>a<br/>b</p>"


def test_text_to_html_escapes_markup():
    assert text_to_html("1 < 2") == "<p>1 &lt; 2</p>"


def test_escape_html_entities_encodes_accents():
    assert escape_html_entities("é") == "&#233;"


def test_escape_html_entities_encodes_dollar_and_percent():
    assert escape_html_entities("5$ 10%") == "5&#36; 10&#37;"


def test_escape_html_entities_leaves_ascii_markup():
    assert escape_html_entities("<p>ok</p>") == "<p>ok</p>"


def test_encode_message_content_is_base64_of_escaped_html():
    assert base64.b64decode(encode_message_content("<p>é</p>")) == b"<p>&#233;</p>"


def test_reply_subject_adds_prefix():
    assert reply_subject("Circulaire") == "Re: Circulaire"


def test_reply_subject_does_not_stack_prefix():
    assert reply_subject("Re: Circulaire") == "Re: Circulaire"


def test_quote_original_wraps_decoded_body_in_blockquote(received_message):
    assert "<blockquote><p>Bonne rentr&#233;e</p></blockquote>" in quote_original(received_message)


def test_quote_original_names_sender_with_function(received_message):
    assert "<b>De Mme A. BERNARD (Secrétariat)</b>" in quote_original(received_message)


def test_recipient_maps_participant_role_to_type(received_message):
    assert recipient(received_message["from"])["type"] == "A"


def test_recipient_defaults_to_the_to_slot(staff_contact):
    assert recipient(staff_contact)["to_cc_cci"] == "to"


def test_recipient_copies_staff_label_into_fonction(received_message):
    assert recipient(received_message["from"])["fonction"]["libelle"] == "Secrétariat"


def test_recipient_keeps_contact_fonction(staff_contact):
    assert recipient(staff_contact)["fonction"] == {"id": 10, "libelle": "Comptabilité"}


def test_group_recipients_one_group_per_type(staff_contact):
    groups = group_recipients([recipient(staff_contact), recipient({"id": 1, "role": "P"})])
    assert [g["selection"]["type"] for g in groups] == ["A", "P"]


def test_group_recipients_same_type_share_a_group(directory):
    groups = group_recipients([recipient(c) for c in directory])
    assert len(groups[0]["destinataires"]) == 2


def test_build_message_sender_is_the_account(parent_cfg, staff_contact):
    acc = primary_account(parent_cfg)
    msg = build_message(acc, "S", "<p>b</p>", [recipient(staff_contact)], [])
    assert msg["from"] == {"role": "1", "id": 2001, "read": True}


def test_build_message_is_not_a_draft_by_default(parent_cfg, staff_contact):
    msg = build_message(primary_account(parent_cfg), "S", "<p>b</p>", [recipient(staff_contact)], [])
    assert msg["brouillon"] is False


def test_build_message_draft_flag(parent_cfg, staff_contact):
    msg = build_message(primary_account(parent_cfg), "S", "<p>b</p>", [recipient(staff_contact)], [], draft=True)
    assert msg["brouillon"] is True


def test_build_message_reply_carries_response_id(parent_cfg, staff_contact):
    msg = build_message(primary_account(parent_cfg), "S", "<p>b</p>", [recipient(staff_contact)], [], response_id="200")
    assert msg["responseId"] == 200


def test_build_message_new_has_no_response_id(parent_cfg, staff_contact):
    msg = build_message(primary_account(parent_cfg), "S", "<p>b</p>", [recipient(staff_contact)], [])
    assert "responseId" not in msg


def test_build_message_content_is_encoded(parent_cfg, staff_contact):
    msg = build_message(primary_account(parent_cfg), "S", "<p>é</p>", [recipient(staff_contact)], [])
    assert msg["content"] == encode_message_content("<p>é</p>")


def test_is_self_matches_account_id_and_role(parent_cfg):
    assert is_self(primary_account(parent_cfg), {"id": 2001, "role": "1"})


def test_is_self_rejects_same_id_other_role(parent_cfg):
    assert not is_self(primary_account(parent_cfg), {"id": 2001, "role": "E"})


def test_resolve_recipient_by_type_id_uses_directory_entry(directory):
    assert resolve_recipient("A:302", directory)["nom"] == "DURAND"


def test_resolve_recipient_by_type_id_unknown_still_builds(directory):
    assert resolve_recipient("P:99", directory)["type"] == "P"


def test_resolve_recipient_by_name_substring(directory):
    assert resolve_recipient("martin", directory)["id"] == 301


def test_resolve_recipient_by_function_substring(directory):
    assert resolve_recipient("responsable", directory)["id"] == 302


def test_resolve_recipient_cc_slot(directory):
    assert resolve_recipient("martin", directory, "cc")["to_cc_cci"] == "cc"


def test_resolve_recipient_ambiguous_raises(directory):
    with pytest.raises(EDError, match="ambiguous"):
        resolve_recipient("compta", directory)


def test_resolve_recipient_unknown_raises(directory):
    with pytest.raises(EDError, match="No contact"):
        resolve_recipient("nobody", directory)


def test_read_body_prefers_inline_text():
    assert read_body("hello", None) == "hello"


def test_read_body_reads_file(tmp_path):
    f = tmp_path / "body.txt"
    f.write_text("from file", encoding="utf-8")
    assert read_body(None, str(f)) == "from file"


def test_read_body_rejects_both_sources():
    with pytest.raises(EDError, match="not both"):
        read_body("a", "b.txt")


def test_read_body_rejects_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("   ", encoding="utf-8")
    with pytest.raises(EDError, match="empty"):
        read_body(None, str(f))


def test_send_without_yes_is_a_dry_run(runner, monkeypatch, parent_cfg, staff_contact):
    """The default path must stop before any upload or post."""
    monkeypatch.setattr(ecoledirecte_cli, "require_login", lambda: parent_cfg)
    monkeypatch.setattr(ecoledirecte_cli, "fetch_contacts", lambda c, cfg, acc: ([staff_contact], []))
    monkeypatch.setattr(ecoledirecte_cli.EDClient, "upload", lambda self, p: pytest.fail("uploaded"))
    monkeypatch.setattr(ecoledirecte_cli.EDClient, "post", lambda self, *a, **k: pytest.fail("posted"))
    result = runner.invoke(cli, ["send", "--to", "A:301", "--subject", "S", "--body", "hi"])
    assert "Dry run" in result.output
