#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "click>=8.1",
#     "curl_cffi>=0.7",
#     "rich>=13.0",
# ]
# ///
"""EcoleDirecte CLI — read grades, homework, timetable and messages from the terminal.

Drives EcoleDirecte's private JSON API (``https://api.ecoledirecte.com/v3/``), the
same back-end the web app and mobile apps use. There is no official public API and
no static bearer token: authentication is a small dance and the session token
*rotates* on every response.

Auth model (verified live against a parent account, 2026-07):
  1. ``GET  /login.awp?gtk=1``  → sets a short-lived ``GTK`` cookie (a CSRF token).
  2. ``POST /login.awp`` with header ``X-GTK`` = the GTK cookie value, and a form
     body ``data=<json>`` holding ``{identifiant, motdepasse, isReLogin, uuid, fa}``.
     ``fa`` is the "trusted device" (``cn``/``cv``) that skips two-factor auth.
  3. When ``fa`` is absent the server answers ``code 250`` (double-auth required):
     fetch a security question from ``/connexion/doubleauth.awp``, answer it, and
     it returns the ``cn``/``cv`` pair to fold into a second login call.
  4. Every authenticated call then carries two headers — ``X-Token`` (a UUID that
     changes with each response; you echo back the ``token`` field of the previous
     response) and a constant ``2FA-Token`` — plus a ``data=<json>`` body.

Credentials live in ``~/.config/ecoledirecte-cli/config.json`` (mode 600): the
identifiant, the password (needed to re-login when the rotating token expires),
and the trusted-device tokens so re-login never re-triggers the 2FA question.

Feature availability is not universal: each school enables modules per account.
The login response lists them, so the CLI can say "the NOTES module is disabled
for this student" instead of failing on an empty payload.
"""

from __future__ import annotations

import base64
import datetime as _dt
import html as _html
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import click
from curl_cffi import requests
from rich.console import Console
from rich.table import Table

logger = logging.getLogger("ecoledirecte")
console = Console()
err_console = Console(stderr=True)

# --- Constants ---------------------------------------------------------------

CONFIG_DIR = Path.home() / ".config" / "ecoledirecte-cli"
CONFIG_FILE = CONFIG_DIR / "config.json"

BASE = "https://api.ecoledirecte.com/v3"
# API version string sent as the `v=` query param on every call. The server
# rejects calls whose version it considers too old, so this tracks the web app.
API_VERSION = "4.100.6"

# api.ecoledirecte.com sits behind a WAF that does TLS fingerprinting; presenting
# a real Chrome fingerprint avoids 403s that never reach the JSON layer.
TLS_IMPERSONATE = "chrome131"
DEFAULT_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# EcoleDirecte response codes we special-case. Anything else with code != 200 is
# surfaced verbatim to the user.
CODE_OK = 200
CODE_DOUBLE_AUTH = 250  # login needs the 2FA question answered
CODE_BAD_CREDENTIALS = 505
CODE_EXPIRED_TOKEN = 525  # rotating token no longer valid → re-login

# Module codes (from the login `modules` list) mapped to the feature each
# command needs. Used to give a precise "module disabled" message rather than a
# blank result when a school hasn't turned a feature on.
MODULE_NOTES = "NOTES"
MODULE_HOMEWORK = "CAHIER_DE_TEXTES"
MODULE_TIMETABLE = "EDT"
MODULE_MESSAGING = "MESSAGERIE"


# --- Config ------------------------------------------------------------------


def load_config() -> dict:
    """Return the stored config, or an empty dict when nothing is saved yet."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_config(config: dict) -> None:
    """Persist config at mode 600.

    On macOS the password is kept out of this file (it lives in the Keychain);
    everywhere else it stays here as a mode-600 fallback.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    CONFIG_FILE.chmod(0o600)


# --- Password storage (macOS Keychain, with a mode-600 file fallback) --------

KEYCHAIN_SERVICE = "ecoledirecte-cli"


def keychain_available() -> bool:
    """True on macOS, where the ``security`` tool backs the login Keychain."""
    return sys.platform == "darwin"


def store_password(identifiant: str, password: str) -> bool:
    """Save the password in the macOS Keychain. Return False if unavailable.

    A False return tells the caller to fall back to the mode-600 config file
    (e.g. on Linux). ``-U`` updates the item in place when it already exists.
    """
    if not keychain_available():
        return False
    try:
        subprocess.run(
            ["security", "add-generic-password", "-a", identifiant,
             "-s", KEYCHAIN_SERVICE, "-w", password, "-U"],
            check=True, capture_output=True,
        )
        return True
    except (OSError, subprocess.CalledProcessError) as exc:
        logger.debug("keychain store failed: %s", exc)
        return False


def fetch_password(identifiant: str) -> str | None:
    """Read the password back from the macOS Keychain, or None if absent."""
    if not keychain_available() or not identifiant:
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password", "-a", identifiant,
             "-s", KEYCHAIN_SERVICE, "-w"],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    if r.returncode != 0:
        return None
    return r.stdout.rstrip("\n") or None


def delete_password(identifiant: str) -> None:
    """Remove the Keychain item (best-effort; ignores a missing item)."""
    if not keychain_available() or not identifiant:
        return
    try:
        subprocess.run(
            ["security", "delete-generic-password", "-a", identifiant,
             "-s", KEYCHAIN_SERVICE],
            capture_output=True,
        )
    except OSError:
        pass


def get_password(cfg: dict) -> str | None:
    """Return the usable password: Keychain first, then the config fallback."""
    return fetch_password(cfg.get("identifiant", "")) or cfg.get("password")


# --- HTTP / API client -------------------------------------------------------


def make_session() -> requests.Session:
    """Build a curl_cffi session impersonating Chrome, shared across calls.

    A single session keeps the ``GTK`` cookie between the gtk handshake and the
    login POST, which is exactly the double-submit the CSRF check expects.
    """
    s = requests.Session(impersonate=TLS_IMPERSONATE)
    s.headers.update(
        {
            "User-Agent": DEFAULT_UA,
            "Accept": "application/json, text/plain, */*",
            "Origin": "https://www.ecoledirecte.com",
            "Referer": "https://www.ecoledirecte.com/",
        }
    )
    return s


def encode_body(payload: dict | None) -> dict:
    """Shape a JSON payload into the ``data=<json>`` form body the API expects.

    Returning a dict lets curl_cffi form-urlencode it; the server url-decodes the
    single ``data`` field back into JSON, so passwords with ``+``/``%``/``&`` in
    them survive the round-trip.
    """
    return {"data": json.dumps(payload if payload is not None else {})}


class EDError(click.ClickException):
    """An EcoleDirecte API error carrying the server's numeric code."""

    def __init__(self, message: str, code: int | None = None):
        super().__init__(message)
        self.code = code


class EDClient:
    """Authenticated client that carries the rotating token across calls.

    The token returned in each response body replaces the one we send next, and a
    separate constant ``2FA-Token`` proves the device passed two-factor auth. When
    the token expires mid-session the client re-authenticates once, transparently,
    from the stored credentials.
    """

    def __init__(self, cfg: dict, session: requests.Session | None = None):
        self.cfg = cfg
        self.session = session or make_session()
        self.token: str | None = cfg.get("token")
        self.twofa_token: str | None = cfg.get("twofaToken")

    def _headers(self) -> dict:
        h = {}
        if self.token:
            h["X-Token"] = self.token
        if self.twofa_token:
            h["2FA-Token"] = self.twofa_token
        return h

    def post(
        self,
        path: str,
        payload: dict | None = None,
        verbe: str = "get",
        extra: dict | None = None,
    ) -> dict:
        """POST to an ``.awp`` endpoint and return its ``data`` object.

        ``extra`` adds query parameters beyond ``verbe``/``v`` (e.g. ``mode`` when
        reading a single message). Rotates ``self.token`` from the response, and
        on an expired-token error re-logs-in once before retrying.
        """
        try:
            return self._post_once(path, payload, verbe, extra)
        except EDError as exc:
            if exc.code == CODE_EXPIRED_TOKEN and get_password(self.cfg):
                logger.debug("token expired, re-authenticating")
                self._reauth()
                return self._post_once(path, payload, verbe, extra)
            raise

    def _reauth(self) -> None:
        """Re-login from the stored credentials + trusted device (no 2FA prompt).

        Uses the saved ``cn``/``cv`` so the security question is not re-asked, and
        persists the refreshed tokens so later invocations start authenticated.
        """
        password = get_password(self.cfg)
        if not password:
            raise EDError("Session expired and no stored password. Run `login` again.")
        fresh = authenticate(self.cfg["identifiant"], password, self.cfg.get("fa"))
        self.token = fresh["token"]
        self.twofa_token = fresh["twofaToken"]
        # Merge refreshed session material back into the persisted config.
        self.cfg = {**self.cfg, **{k: v for k, v in fresh.items() if k != "password"}}
        save_config({k: v for k, v in self.cfg.items() if k != "password"})

    def _post_once(
        self, path: str, payload: dict | None, verbe: str, extra: dict | None = None
    ) -> dict:
        url = f"{BASE}/{path}?verbe={verbe}&v={API_VERSION}"
        if extra:
            url += "".join(f"&{k}={v}" for k, v in extra.items())
        logger.debug("POST %s payload=%s", url, payload)
        r = self.session.post(
            url, data=encode_body(payload), headers=self._headers(), timeout=30
        )
        try:
            body = r.json()
        except Exception:
            raise EDError(f"Non-JSON response ({r.status_code}) from {path}")
        code = body.get("code")
        # Every response hands back the next token to use.
        if body.get("token"):
            self.token = body["token"]
        if code != CODE_OK:
            raise EDError(
                body.get("message") or f"API error code {code} on {path}", code=code
            )
        return body.get("data", {})


# --- Authentication ----------------------------------------------------------


def _gtk(session: requests.Session) -> str:
    """Run the gtk handshake and return the ``GTK`` cookie value (the CSRF token)."""
    r = session.get(f"{BASE}/login.awp?gtk=1&v={API_VERSION}", timeout=30)
    gtk = r.cookies.get("GTK") or session.cookies.get("GTK")
    if not gtk:
        raise EDError(
            "Could not obtain a GTK token from EcoleDirecte (login handshake failed)."
        )
    return gtk


def _double_auth(session: requests.Session, x_token: str, twofa_token: str) -> dict:
    """Answer the 2FA security question and return the ``{cn, cv}`` trust tokens.

    The double-auth endpoint authorises the request with the ``X-Token`` **and**
    ``2FA-Token`` the ``code 250`` login issued as response headers — sending only
    ``X-Token`` gets a ``520 Token invalide``. The question and every proposition
    are base64-encoded, and the chosen answer is sent back base64-encoded too.
    """
    headers = {"X-Token": x_token, "2FA-Token": twofa_token}
    logger.debug("doubleauth GET xtoken.len=%d 2fa.len=%d", len(x_token or ""), len(twofa_token or ""))
    r = session.post(
        f"{BASE}/connexion/doubleauth.awp?verbe=get&v={API_VERSION}",
        data=encode_body({}),
        headers=headers,
        timeout=30,
    )
    body = r.json()
    logger.debug("doubleauth GET code=%s message=%r", body.get("code"), body.get("message"))
    # The X-Token rotates with each response; the 2FA-Token stays constant.
    get_hdrs = {k.lower(): v for k, v in r.headers.items()}
    x_token = get_hdrs.get("x-token") or x_token
    if body.get("code") != CODE_OK:
        raise EDError(body.get("message") or "Could not fetch the 2FA question.")
    data = body["data"]
    question = base64.b64decode(data["question"]).decode("utf-8", "replace")
    propositions = [
        base64.b64decode(p).decode("utf-8", "replace") for p in data["propositions"]
    ]

    err_console.print(f"\n[bold]Double authentification[/bold]: {question}")
    for i, prop in enumerate(propositions, 1):
        err_console.print(f"  {i}. {prop}")
    choice = click.prompt("Your answer (number)", type=click.IntRange(1, len(propositions)))
    chosen_b64 = base64.b64encode(propositions[choice - 1].encode("utf-8")).decode()

    r = session.post(
        f"{BASE}/connexion/doubleauth.awp?verbe=post&v={API_VERSION}",
        data=encode_body({"choix": chosen_b64}),
        headers={"X-Token": x_token, "2FA-Token": twofa_token},
        timeout=30,
    )
    body = r.json()
    logger.debug("doubleauth POST code=%s message=%r", body.get("code"), body.get("message"))
    if body.get("code") != CODE_OK:
        raise EDError(body.get("message") or "The 2FA answer was rejected.")
    return {"cn": body["data"]["cn"], "cv": body["data"]["cv"]}


def authenticate(identifiant: str, password: str, fa: list | None) -> dict:
    """Full login flow. Returns a dict ready to persist as config.

    Retries the login with freshly-minted ``cn``/``cv`` when the server asks for
    two-factor auth, so a first login (no trusted device yet) walks the user
    through the security question exactly once. The gtk (CSRF) cookie is single-use
    — a fresh one is fetched before each login POST.
    """
    session = make_session()
    fa = fa or []

    def do_login() -> tuple[dict, dict]:
        # gtk is consumed/cleared by each login POST, so mint a fresh one first.
        gtk = _gtk(session)
        payload = {
            "identifiant": identifiant,
            "motdepasse": password,
            "isReLogin": False,
            "uuid": "",
            "fa": fa,
        }
        r = session.post(
            f"{BASE}/login.awp?v={API_VERSION}",
            data=encode_body(payload),
            headers={"X-GTK": gtk},
            timeout=30,
        )
        logger.debug("login response headers: %s", dict(r.headers))
        # Normalise to lowercase keys: the API returns `x-token` / `2fa-token`.
        return r.json(), {k.lower(): v for k, v in r.headers.items()}

    body, hdrs = do_login()
    logger.debug("login #1 code=%s message=%r", body.get("code"), body.get("message"))
    if body.get("code") == CODE_DOUBLE_AUTH:
        # The 250 response issues the X-Token + 2FA-Token the 2FA exchange needs.
        pair = _double_auth(session, hdrs.get("x-token", ""), hdrs.get("2fa-token", ""))
        fa = [{"cn": pair["cn"], "cv": pair["cv"], "uniq": False}]
        body, hdrs = do_login()
        logger.debug("login #2 code=%s message=%r", body.get("code"), body.get("message"))

    code = body.get("code")
    if code == CODE_BAD_CREDENTIALS:
        raise EDError("Invalid identifiant or password.")
    if code != CODE_OK:
        raise EDError(body.get("message") or f"Login failed (code {code}).")

    accounts = body["data"]["accounts"]
    return {
        "identifiant": identifiant,
        "password": password,
        "fa": fa,
        # Rotating session token, and the constant 2FA-Token from the login headers.
        "token": body.get("token") or hdrs.get("x-token"),
        "twofaToken": hdrs.get("2fa-token") or body.get("token"),
        "accounts": accounts,
    }


def require_login() -> dict:
    """Return the stored config or abort telling the user to run ``login``."""
    cfg = load_config()
    if not cfg.get("token") or not cfg.get("accounts"):
        raise EDError("Not logged in. Run `ecoledirecte login` first.")
    # Migrate a legacy plaintext password into the Keychain, then strip it from
    # the file — so upgrading the tool secures an old session automatically.
    if cfg.get("password") and store_password(cfg.get("identifiant", ""), cfg["password"]):
        cfg.pop("password")
        save_config(cfg)
        logger.debug("migrated plaintext password to Keychain")
    return cfg


# --- Account / module helpers ------------------------------------------------


def primary_account(cfg: dict) -> dict:
    """Return the main account object (the one flagged ``main`` or the first)."""
    accounts = cfg.get("accounts", [])
    for a in accounts:
        if a.get("main"):
            return a
    if not accounts:
        raise EDError("No account in the stored session; re-run `login`.")
    return accounts[0]


def list_students(cfg: dict) -> list[dict]:
    """Return the students reachable from the session.

    A parent account (``typeCompte`` ``"1"``) exposes children under
    ``profile.eleves``; a student account (``"E"``) is itself the one student.
    """
    acc = primary_account(cfg)
    if acc.get("typeCompte") == "E":
        return [acc]
    return acc.get("profile", {}).get("eleves", [])


def resolve_student(cfg: dict, student: str | None) -> dict:
    """Pick a student by id or name substring; default to the only/first one."""
    students = list_students(cfg)
    if not students:
        raise EDError("No student is attached to this account.")
    if student is None:
        if len(students) > 1:
            names = ", ".join(f"{s['id']}={s.get('prenom', '')}" for s in students)
            raise EDError(
                f"Several students found — pass --student <id>. Options: {names}"
            )
        return students[0]
    for s in students:
        if str(s.get("id")) == str(student):
            return s
    needle = student.lower()
    for s in students:
        full = f"{s.get('prenom', '')} {s.get('nom', '')}".lower()
        if needle in full:
            return s
    raise EDError(f"No student matching '{student}'.")


def student_name(s: dict) -> str:
    return f"{s.get('prenom', '')} {s.get('nom', '')}".strip() or str(s.get("id"))


def module_enabled(entity: dict, code: str) -> bool:
    """True when ``code`` is present and enabled in the entity's module list."""
    for m in entity.get("modules", []):
        if m.get("code") == code:
            return bool(m.get("enable"))
    return False


def require_module(entity: dict, code: str, label: str) -> None:
    """Abort with a clear message when a school hasn't enabled a feature."""
    if not module_enabled(entity, code):
        name = entity.get("prenom") or entity.get("nom") or "this account"
        raise EDError(
            f"The '{label}' module ({code}) is disabled for {name}. "
            "The school does not publish this feature through EcoleDirecte."
        )


def html_to_text(s: str) -> str:
    """Flatten EcoleDirecte's rich-text HTML message bodies to readable text.

    Message content comes back as base64-encoded HTML; block tags become line
    breaks and entities are unescaped, so the terminal shows plain prose.
    """
    s = re.sub(r"(?i)<br\s*/?>", "\n", s)
    s = re.sub(r"(?i)</(p|div|tr|li|h[1-6]|table)>", "\n", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = _html.unescape(s)
    s = re.sub(r"[ \t]+\n", "\n", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def decode_b64_text(s: str) -> str:
    """Decode a base64 string to UTF-8, tolerating already-plain values."""
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return s


def output(data, as_json: bool, render) -> None:
    """Either dump raw JSON or call the human renderer."""
    if as_json:
        console.print_json(json.dumps(data, ensure_ascii=False))
    else:
        render(data)


# --- CLI ---------------------------------------------------------------------


@click.group()
@click.option("--debug", is_flag=True, help="Verbose logging of HTTP traffic.")
def cli(debug: bool) -> None:
    """EcoleDirecte CLI — grades, homework, timetable and messages from the shell."""
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


@cli.command()
@click.option("--identifiant", "-u", help="EcoleDirecte username (prompted if omitted).")
@click.option(
    "--no-store-password",
    is_flag=True,
    help="Do not save the password. You'll be prompted again when the token expires.",
)
def login(identifiant: str | None, no_store_password: bool) -> None:
    """Log in to EcoleDirecte and save the session.

    Prompts for the password (never echoed) and, on a first login, walks you
    through the two-factor security question once. The trusted-device tokens are
    then stored so future logins skip 2FA.
    """
    cfg = load_config()
    identifiant = (
        identifiant
        or os.environ.get("ECOLEDIRECTE_IDENTIFIANT")
        or cfg.get("identifiant")
        or click.prompt("Identifiant")
    )
    # Password may come from the environment (agents / non-interactive shells) or
    # be typed at a hidden prompt. It is never taken from a CLI flag, so it can't
    # leak into shell history or a process listing.
    password = os.environ.get("ECOLEDIRECTE_PASSWORD") or click.prompt(
        "Mot de passe", hide_input=True
    )

    result = authenticate(identifiant, password, cfg.get("fa"))

    # Decide where the password lives. Default: macOS Keychain. The config file
    # never keeps the password unless we're on a platform without a Keychain and
    # the user did not opt out.
    result.pop("password", None)
    where = "not stored"
    if no_store_password:
        delete_password(identifiant)
    elif store_password(identifiant, password):
        where = "password in macOS Keychain"
    else:
        result["password"] = password  # mode-600 fallback (non-macOS)
        where = "password in config (mode 600)"
    save_config(result)

    acc = primary_account(result)
    kind = "parent" if acc.get("typeCompte") == "1" else "élève"
    console.print(
        f"[green]✓[/green] Logged in as [cyan]{acc.get('civilite', '')} "
        f"{acc.get('prenom', '')} {acc.get('nom', '')}[/cyan] ({kind}) "
        f"— {acc.get('nomEtablissement', '')}"
    )
    students = list_students(result)
    if students:
        console.print(f"  Students: " + ", ".join(f"{student_name(s)} (id {s['id']})" for s in students))
    console.print(f"  Session saved to {CONFIG_FILE} ({where})")


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def whoami(as_json: bool) -> None:
    """Show the logged-in account and reachable students."""
    cfg = require_login()
    acc = primary_account(cfg)
    students = list_students(cfg)
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "account": {
                        "id": acc.get("id"),
                        "identifiant": acc.get("identifiant"),
                        "typeCompte": acc.get("typeCompte"),
                        "name": f"{acc.get('prenom', '')} {acc.get('nom', '')}".strip(),
                        "etablissement": acc.get("nomEtablissement"),
                    },
                    "students": [
                        {
                            "id": s.get("id"),
                            "name": student_name(s),
                            "classe": (s.get("classe") or {}).get("libelle"),
                            "modules": [
                                m["code"] for m in s.get("modules", []) if m.get("enable")
                            ],
                        }
                        for s in students
                    ],
                },
                ensure_ascii=False,
            )
        )
        return
    kind = "parent" if acc.get("typeCompte") == "1" else "élève"
    console.print(
        f"[cyan]{acc.get('civilite', '')} {acc.get('prenom', '')} {acc.get('nom', '')}[/cyan] "
        f"({kind}) — {acc.get('nomEtablissement', '')}"
    )
    if students:
        table = Table("ID", "Student", "Classe", "Enabled modules")
        for s in students:
            mods = ", ".join(m["code"] for m in s.get("modules", []) if m.get("enable"))
            table.add_row(
                str(s.get("id")),
                student_name(s),
                (s.get("classe") or {}).get("libelle", ""),
                mods,
            )
        console.print(table)


@cli.command()
def logout() -> None:
    """Delete the stored session and credentials (does not touch the server)."""
    cfg = load_config()
    delete_password(cfg.get("identifiant", ""))
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink()
        console.print("[green]✓[/green] Local session and Keychain entry cleared.")
    else:
        console.print("Nothing to clear.")


@cli.command()
@click.option("--student", "-s", help="Student id or name (parent accounts).")
@click.option("--year", help="School year, e.g. 2025-2026. Default: current.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def notes(student: str | None, year: str | None, as_json: bool) -> None:
    """Show grades (notes) and per-subject averages."""
    cfg = require_login()
    s = resolve_student(cfg, student)
    require_module(s, MODULE_NOTES, "Notes")
    client = EDClient(cfg)
    data = client.post(
        f"eleves/{s['id']}/notes.awp", {"anneeScolaire": year or ""}
    )
    save_config({**cfg, "token": client.token})

    def render(d):
        grades = d.get("notes", [])
        if not grades:
            console.print("[yellow]No grades yet.[/yellow]")
            return
        table = Table("Date", "Subject", "Grade", "/", "Coef", "Title")
        for n in grades:
            table.add_row(
                n.get("date", ""),
                n.get("libelleMatiere", ""),
                str(n.get("valeur", "")),
                str(n.get("noteSur", "")),
                str(n.get("coef", "")),
                n.get("devoir", ""),
            )
        console.print(table)

    output(data, as_json, render)


@cli.command()
@click.option("--student", "-s", help="Student id or name (parent accounts).")
@click.option("--date", "date_", help="Homework for a specific day (YYYY-MM-DD).")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def homework(student: str | None, date_: str | None, as_json: bool) -> None:
    """Show the cahier de textes (homework). Omit --date for upcoming days."""
    cfg = require_login()
    s = resolve_student(cfg, student)
    require_module(s, MODULE_HOMEWORK, "Cahier de textes")
    client = EDClient(cfg)
    if date_:
        data = client.post(f"Eleves/{s['id']}/cahierdetexte/{date_}.awp", {})
    else:
        data = client.post(f"Eleves/{s['id']}/cahierdetexte.awp", {})
    save_config({**cfg, "token": client.token})

    def render(d):
        if date_:
            items = d.get("matieres", [])
            if not items:
                console.print(f"[yellow]No homework recorded for {date_}.[/yellow]")
                return
            for m in items:
                console.print(f"[bold]{m.get('matiere', '')}[/bold] — {m.get('nomProf', '')}")
                af = m.get("aFaire") or {}
                if af.get("contenu"):
                    console.print(f"  {af['contenu']}")
        else:
            # Top-level object keyed by date → list of subjects with work due.
            if not d:
                console.print("[yellow]No upcoming homework.[/yellow]")
                return
            table = Table("Date", "Subject", "To do")
            for day, entries in sorted(d.items()):
                for e in entries:
                    table.add_row(day, e.get("matiere", ""), "✓" if e.get("aFaire") else "")
            console.print(table)

    output(data, as_json, render)


@cli.command()
@click.option("--student", "-s", help="Student id or name (parent accounts).")
@click.option("--from", "date_from", help="Start date YYYY-MM-DD. Default: today.")
@click.option("--to", "date_to", help="End date YYYY-MM-DD. Default: +7 days.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def timetable(
    student: str | None, date_from: str | None, date_to: str | None, as_json: bool
) -> None:
    """Show the emploi du temps (timetable) for a date range."""
    cfg = require_login()
    s = resolve_student(cfg, student)
    require_module(s, MODULE_TIMETABLE, "Emploi du temps")
    today = _dt.date.today()
    date_from = date_from or today.isoformat()
    date_to = date_to or (today + _dt.timedelta(days=7)).isoformat()
    client = EDClient(cfg)
    data = client.post(
        f"E/{s['id']}/emploidutemps.awp",
        {"dateDebut": date_from, "dateFin": date_to, "avecTrous": False},
    )
    save_config({**cfg, "token": client.token})

    def render(d):
        lessons = d if isinstance(d, list) else d.get("lessons", [])
        if not lessons:
            console.print("[yellow]No lessons in that range.[/yellow]")
            return
        table = Table("Start", "End", "Subject", "Room", "Teacher")
        for c in sorted(lessons, key=lambda x: x.get("start_date", "")):
            table.add_row(
                c.get("start_date", ""),
                c.get("end_date", ""),
                c.get("matiere") or c.get("text", ""),
                c.get("salle", ""),
                c.get("prof", ""),
            )
        console.print(table)

    output(data, as_json, render)


def mailbox_path(acc: dict) -> str:
    """Return the messages endpoint base for the account.

    A parent reads the family mailbox; a student reads their own.
    """
    if acc.get("typeCompte") == "E":
        return f"eleves/{acc['id']}"
    return f"familles/{acc['id']}"


# EcoleDirecte's folder names, mapped to the response key each populates and the
# `mode` a single-message read needs.
FOLDERS = {
    "received": {"key": "received", "mode": "destinataire"},
    "sent": {"key": "sent", "mode": "expediteur"},
    "archived": {"key": "archived", "mode": "destinataire"},
    "draft": {"key": "draft", "mode": "expediteur"},
}


@cli.command()
@click.option("--folder", type=click.Choice(list(FOLDERS)), default="received",
              help="Mailbox folder. Default: received.")
@click.option("--year", help="School year, e.g. 2025-2026. Default: current.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def messages(folder: str, year: str | None, as_json: bool) -> None:
    """List messages in a mailbox folder (all of them, not just the first page)."""
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    payload = {"anneeMessages": year} if year else {}
    # The default call caps at 20 per folder; a large itemsPerPage on a single
    # folder pulls the whole list in one request (counts are in the low hundreds).
    data = client.post(
        f"{mailbox_path(acc)}/messages.awp",
        payload,
        extra={
            "typeRecuperation": folder,
            "getAll": "1",
            "idClasseur": "0",
            "orderBy": "date",
            "order": "desc",
            "page": "0",
            "itemsPerPage": "5000",
        },
    )
    save_config({**cfg, "token": client.token})

    def render(d):
        items = (d.get("messages") or {}).get(FOLDERS[folder]["key"], [])
        if not items:
            console.print(f"[yellow]No messages in '{folder}'.[/yellow]")
            return
        table = Table("ID", "Date", "From", "Subject", "Read")
        for m in items:
            frm = m.get("from") or {}
            table.add_row(
                str(m.get("id", "")),
                m.get("date", ""),
                f"{frm.get('prenom', '')} {frm.get('nom', '')}".strip(),
                m.get("subject", ""),
                "" if m.get("read") else "●",
            )
        console.print(table)
        console.print(f"[dim]{len(items)} message(s). Read one with: read <ID>[/dim]")

    output(data, as_json, render)


@cli.command()
@click.argument("message_id")
@click.option("--folder", type=click.Choice(list(FOLDERS)), default="received",
              help="Folder the message is in (sets read mode). Default: received.")
@click.option("--year", help="School year the message belongs to, e.g. 2025-2026.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON (content still base64).")
def read(message_id: str, folder: str, year: str | None, as_json: bool) -> None:
    """Read one message by ID (see the IDs from `messages`)."""
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    payload = {"anneeMessages": year} if year else {}
    data = client.post(
        f"{mailbox_path(acc)}/messages/{message_id}.awp",
        payload,
        extra={"mode": FOLDERS[folder]["mode"]},
    )
    save_config({**cfg, "token": client.token})

    def render(d):
        frm = d.get("from") or {}
        console.print(f"[bold]{d.get('subject', '(no subject)')}[/bold]")
        console.print(
            f"[dim]From {frm.get('prenom', '')} {frm.get('nom', '')} · {d.get('date', '')}[/dim]\n"
        )
        console.print(html_to_text(decode_b64_text(d.get("content", ""))))
        files = d.get("files") or []
        if files:
            console.print("\n[bold]Attachments:[/bold]")
            for f in files:
                console.print(f"  • {f.get('libelle', '')} (id {f.get('id', '')})")

    output(data, as_json, render)


if __name__ == "__main__":
    cli()
