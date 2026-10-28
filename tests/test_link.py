#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pytest==9.1.1",
#     "click==8.4.2",
#     "curl_cffi==0.15.0",
#     "rich==15.0.0",
# ]
#
# [tool.uv]
# exclude-newer = "2026-10-13T00:00:00Z"
# ///
"""Signing in without a terminal: the security-question chooser and the link page's flow. No network."""

import base64
import contextlib
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
import ecoledirecte_cli as ed  # noqa: E402

QUESTION = "Quelle est votre année de naissance ?"
PROPOSITIONS = ["1980", "1981", "1982"]
ACCOUNT = {"prenom": "Ada", "nom": "Lovelace"}


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class StubSession:
    """Answers the double-auth GET with QUESTION and records the POSTed answer."""

    def __init__(self):
        self.answer = None

    def post(self, url, data=None, headers=None, timeout=None):
        if "verbe=get" in url:
            body = {"code": 200, "data": {"question": b64(QUESTION), "propositions": [b64(p) for p in PROPOSITIONS]}}
        else:
            self.answer = ed.json.loads(data["data"])["choix"]
            body = {"code": 200, "data": {"cn": "cn", "cv": "cv"}}
        return SimpleNamespace(json=lambda: body, headers={})


def wait_for(flow: ed.LinkFlow, step: str) -> dict:
    for _ in range(200):
        if flow.state.get("step") == step:
            return flow.state
        time.sleep(0.01)
    raise AssertionError(f"flow never reached {step}: {flow.state}")


@pytest.fixture
def saved(monkeypatch):
    """Logins persisted by the flow, in order."""
    results: list[dict] = []

    def save(result: dict) -> dict:
        results.append(result)
        return ACCOUNT

    monkeypatch.setattr(ed, "_save_login", save)
    return results


def asking_login(identifiant, password, fa, choose):
    """A login that needs the right password, then asks QUESTION and needs 1981."""
    if password != "right":
        raise ed.EDError("Invalid identifiant or password.")
    if PROPOSITIONS[choose(QUESTION, PROPOSITIONS)] != "1981":
        raise ed.EDError("The 2FA answer was rejected.")
    return {"identifiant": identifiant, "token": "t", "accounts": [ACCOUNT]}


@pytest.fixture
def running(saved):
    """A LinkFlow running `asking_login` in a thread, as the helper runs it."""
    flow = ed.LinkFlow("parent", None, timeout=1)

    def run():
        # A test that stops before `done` leaves the flow waiting until its timeout.
        with contextlib.suppress(ed.EDError):
            flow.run(login=asking_login)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    yield flow
    thread.join(timeout=2)


def test_terminal_free_question_points_to_link(monkeypatch):
    monkeypatch.setattr(ed.sys.stdin, "isatty", lambda: False)
    with pytest.raises(ed.EDError, match="call the `link` tool"):
        ed.prompt_choice(QUESTION, PROPOSITIONS)


def test_double_auth_sends_the_chosen_proposition():
    session = StubSession()
    ed._double_auth(session, "x", "2fa", choose=lambda question, propositions: 2)
    assert session.answer == b64("1982")


def test_double_auth_shows_the_decoded_question():
    asked = []
    ed._double_auth(StubSession(), "x", "2fa", choose=lambda question, propositions: asked.append(question) or 0)
    assert asked == [QUESTION]


def test_double_auth_returns_the_trusted_device():
    assert ed._double_auth(StubSession(), "x", "2fa", choose=lambda q, p: 0) == {"cn": "cn", "cv": "cv"}


def test_flow_starts_by_asking_credentials():
    assert ed.LinkFlow("parent", None).state == {"step": "credentials", "identifiant": "parent", "error": None}


def test_flow_shows_the_security_question(running):
    running.submit_credentials("parent", "right")
    assert wait_for(running, "question")["propositions"] == PROPOSITIONS


def test_flow_finishes_with_the_account_name(running):
    running.submit_credentials("parent", "right")
    wait_for(running, "question")
    running.submit_answer(1)
    assert wait_for(running, "done")["name"] == "Ada Lovelace"


def test_flow_saves_the_login(running, saved):
    running.submit_credentials(" parent ", "right")
    wait_for(running, "question")
    running.submit_answer(1)
    wait_for(running, "done")
    assert saved[0]["identifiant"] == "parent"


def test_wrong_password_asks_credentials_again(running):
    running.submit_credentials("parent", "wrong")
    time.sleep(0.05)
    assert wait_for(running, "credentials")["error"] == "Invalid identifiant or password."


def test_rejected_answer_asks_credentials_again(running):
    running.submit_credentials("parent", "right")
    wait_for(running, "question")
    running.submit_answer(0)
    time.sleep(0.05)
    assert wait_for(running, "credentials")["error"] == "The 2FA answer was rejected."


def test_out_of_range_answer_is_refused(running):
    running.submit_credentials("parent", "right")
    wait_for(running, "question")
    running.submit_answer(7)
    time.sleep(0.05)
    assert wait_for(running, "credentials")["error"] == "That answer is not one of the choices."


def test_flow_times_out_without_credentials():
    with pytest.raises(ed.EDError, match="timed out"):
        ed.LinkFlow("parent", None, timeout=0.05).run(login=asking_login)


def test_not_logged_in_points_to_link(monkeypatch):
    monkeypatch.setattr(ed, "load_config", lambda: {})
    with pytest.raises(ed.EDError, match="call the `link` tool"):
        ed.require_login()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
