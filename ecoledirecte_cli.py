#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "click>=8.1",
#     "curl_cffi>=0.7",
#     "rich>=13.0",
# ]
# ///
"""EcoleDirecte CLI — grades, homework, timetable and messages (read, reply, send) from the terminal.

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

The 1Password broker manages credentials and rotating tokens. A mode-600
working copy preserves login and token refresh while the broker is unavailable.

Feature availability is not universal: each school enables modules per account.
The login response lists them, so the CLI can say "the NOTES module is disabled
for this student" instead of failing on an empty payload.

Writes (verified live, 2026-09): ``mark`` toggles read state; ``reply``/``send`` post
a message through ``messages.awp?verbe=post`` after pushing each attachment through
``televersement.awp`` (multipart ``file`` field). Sending is a dry run unless ``--yes``.

Output conventions:
- default: compact human/agent-readable tables, one line per grade/lesson/message
- --json:  the API's own ``data`` payload, unflattened — for piping to jq/python
"""

from __future__ import annotations

import base64
import datetime as _dt
import html as _html
import json
import logging
import mimetypes
import os
import re
import subprocess
import sys
from pathlib import Path

import click
from curl_cffi import CurlMime, requests
from rich.console import Console
from rich.table import Table

logger = logging.getLogger("ecoledirecte")
console = Console()
err_console = Console(stderr=True)

# --- Constants ---------------------------------------------------------------

CONFIG_DIR = Path.home() / ".config" / "ecoledirecte-cli"
CONFIG_FILE = CONFIG_DIR / "config.json"

__version__ = "1.1.0"

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
# A stale rotating token comes back as either code: 520 "Token invalide !" when the
# server has dropped the session entirely, 525 when it merely expired. Both recover
# the same way, by re-logging-in from the trusted device.
CODE_INVALID_TOKEN = 520
CODE_EXPIRED_TOKEN = 525
STALE_TOKEN_CODES = (CODE_INVALID_TOKEN, CODE_EXPIRED_TOKEN)

# Module codes (from the login `modules` list) mapped to the feature each
# command needs. Used to give a precise "module disabled" message rather than a
# blank result when a school hasn't turned a feature on.
MODULE_NOTES = "NOTES"
MODULE_HOMEWORK = "CAHIER_DE_TEXTES"
MODULE_TIMETABLE = "EDT"
MODULE_MESSAGING = "MESSAGERIE"


# --- Config ------------------------------------------------------------------



def _auth_broker(action, payload=None):
    """Keep credential bodies on pipes and suppress provider errors containing secrets."""
    import subprocess
    import json
    try:
        result = subprocess.run(
            ["claudine-secret", "auth", action, "ecoledirecte"],
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode not in (0, 3):
            return None
        value = json.loads(result.stdout)
        if not isinstance(value, dict):
            return None
        if action == "load" and result.returncode:
            return None
        return value
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def load_config() -> dict:
    """Prefer broker pending or vault credentials over a legacy working copy."""
    if CONFIG_FILE.with_suffix(".signed-out").exists():
        return {}
    if CONFIG_FILE.with_suffix(".auth-pending").exists():
        return _legacy_config()
    return _auth_broker("load") or _legacy_config()


def _legacy_config() -> dict:
    """Return the stored config, or an empty dict when nothing is saved yet."""
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except json.JSONDecodeError:
        return {}


def save_config(config: dict) -> None:
    """Keep a protected working copy and synchronize rotating credentials through the broker."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.touch(mode=0o600, exist_ok=True)
    CONFIG_FILE.chmod(0o600)
    CONFIG_FILE.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    CONFIG_FILE.chmod(0o600)
    pending = CONFIG_FILE.with_suffix(".auth-pending")
    if _auth_broker("save", config) is None:
        pending.touch(mode=0o600)
    else:
        pending.unlink(missing_ok=True)


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
    """Prefer the synchronized password and retain Keychain migration compatibility."""
    return cfg.get("password") or fetch_password(cfg.get("identifiant", ""))


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
        on a stale-token error (520 or 525) re-logs-in once before retrying.
        """
        return self._with_reauth(lambda: self._post_once(path, payload, verbe, extra))

    def _with_reauth(self, call):
        """Run ``call``; on a stale-token error re-login once and run it again."""
        try:
            return call()
        except EDError as exc:
            if exc.code in STALE_TOKEN_CODES and get_password(self.cfg):
                logger.debug("token expired, re-authenticating")
                self._reauth()
                return call()
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

    def download(self, file_id: str | int, file_type: str, payload: dict | None = None) -> bytes:
        """Download a file (message attachment, etc.) and return its raw bytes.

        The download endpoint streams the binary directly — no JSON envelope — so
        the rotating token is refreshed from the ``X-Token`` response header
        instead of a body field.
        """
        url = (
            f"{BASE}/telechargement.awp?verbe=get&fichierId={file_id}"
            f"&leTypeDeFichier={file_type}&v={API_VERSION}"
        )
        logger.debug("DOWNLOAD %s", url)
        r = self.session.post(
            url, data=encode_body(payload), headers=self._headers(), timeout=120
        )
        new_token = {k.lower(): v for k, v in r.headers.items()}.get("x-token")
        if new_token:
            self.token = new_token
        ctype = r.headers.get("content-type", "")
        # An error comes back as JSON instead of the binary stream.
        if "application/json" in ctype:
            try:
                body = r.json()
                raise EDError(body.get("message") or "Download failed.", code=body.get("code"))
            except ValueError:
                pass
        if r.status_code != 200 or not r.content:
            raise EDError(f"Download failed (HTTP {r.status_code}).")
        return r.content

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
        return self._parse(r, path)

    def _parse(self, r, path: str) -> dict:
        """Unwrap a JSON envelope: rotate the token, raise on a non-200 code, return ``data``."""
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

    def upload(self, path: Path) -> dict:
        """Upload a local file as a pending attachment and return its descriptor.

        The web composer's dropzone posts a multipart ``file`` field to
        ``televersement.awp``; the returned descriptor (``unc`` temp path and
        ``libelle``) goes verbatim into the message's ``files`` list, and the
        server turns it into a real PIECE_JOINTE when the message is posted.
        """
        return self._with_reauth(lambda: self._upload_once(path))

    def _upload_once(self, path: Path) -> dict:
        url = f"{BASE}/televersement.awp?verbe=post&v={API_VERSION}"
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        logger.debug("UPLOAD %s (%s)", path, mime)
        form = CurlMime()
        form.addpart("file", content_type=mime, filename=path.name, local_path=path)
        try:
            r = self.session.post(url, multipart=form, headers=self._headers(), timeout=300)
        finally:
            form.close()
        return self._parse(r, "televersement.awp")


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


def is_read(message: dict) -> bool:
    """Whether a message is read. The API sends ``read`` as the string 'True'/'False'."""
    return str(message.get("read")).strip().lower() == "true"


def safe_filename(name: str, fallback: str) -> str:
    """Return a filesystem-safe basename, never empty and never a path.

    Guards against a server-supplied name escaping the output directory (path
    separators, ``..``) by reducing to the basename and stripping leading dots.
    """
    name = os.path.basename((name or "").replace("\\", "/").strip()).lstrip(".")
    return name or fallback


# --- Message composition -----------------------------------------------------

# Profile-type codes the API uses for people: the `type` of a directory contact
# and the `role` of a message participant are the same alphabet.
RECIPIENT_TYPES = {
    "A": "personnel",
    "P": "enseignant",
    "E": "élève",
    "1": "famille",
    "2": "famille",
    "T": "entreprise",
}
# A recipient spec on the command line may name a person directly as TYPE:ID.
RECIPIENT_SPEC = re.compile(r"^([A-Z0-9]{1,2}):(\d+)$")


def text_to_html(text: str) -> str:
    """Turn plain terminal text into the HTML body EcoleDirecte stores.

    Blank lines separate paragraphs, single newlines become ``<br/>``, and
    markup characters are escaped so a literal ``<`` survives as text.
    """
    paragraphs = re.split(r"\n\s*\n", text.replace("\r\n", "\n").strip())
    return "".join(
        f"<p>{_html.escape(p).replace(chr(10), '<br/>')}</p>" for p in paragraphs if p.strip()
    )


def escape_html_entities(markup: str) -> str:
    """Replace every non-ASCII character, plus ``$`` and ``%``, with a numeric entity.

    The web composer entity-encodes accented letters before base64ing a body so
    the server never sees raw UTF-8 or ``$``/``%`` in message content.
    """
    return "".join(f"&#{ord(c)};" if c in "$%" or ord(c) > 126 else c for c in markup)


def encode_message_content(markup: str) -> str:
    """Base64 the entity-escaped HTML body: the wire format of ``message.content``."""
    return base64.b64encode(escape_html_entities(markup).encode("ascii")).decode("ascii")


def participant_name(person: dict) -> str:
    """'Mme A. BERNARD' style display for a message participant or a contact."""
    parts = [person.get("civilite", ""), person.get("prenom", ""), person.get("particule", ""), person.get("nom", "")]
    return " ".join(p for p in parts if p).strip()


def quote_original(msg: dict) -> str:
    """HTML block quoting the message being answered, as the web composer inserts it."""
    frm = msg.get("from") or {}
    who = participant_name(frm)
    if frm.get("fonctionPersonnel"):
        who = f"{who} ({frm['fonctionPersonnel']})"
    original = decode_b64_text(msg.get("content") or "")
    return (
        f"<br/><br/><b>De {_html.escape(who)}</b>"
        f"<br/><i>(le {_html.escape(msg.get('date') or '???')})</i>"
        f"<br/><br/><blockquote>{original}</blockquote>"
    )


def reply_subject(subject: str) -> str:
    """Prefix ``Re:`` once, never stacking it on an existing reply."""
    subject = (subject or "").strip()
    return subject if subject.lower().startswith("re:") else f"Re: {subject}"


def recipient(entry: dict, to_cc_cci: str = "to") -> dict:
    """Shape a directory contact or a message's ``from``/``to`` entry as a recipient.

    A participant carries ``role`` where a contact carries ``type``; the
    composer sends both under ``type``. A participant knows its function or
    class only as the free-text ``fonctionPersonnel`` label.
    """
    kind = entry.get("type") or entry.get("role") or ""
    fonction = dict(entry.get("fonction") or {"id": 0, "libelle": ""})
    classe = dict(entry.get("classe") or {"id": 0, "code": "", "libelle": ""})
    label = entry.get("fonctionPersonnel") or ""
    if label and kind == "A":
        fonction["libelle"] = label
    if label and kind == "E":
        classe["libelle"] = label
    return {
        "id": entry.get("id"),
        "type": kind,
        "isSelected": True,
        "nom": entry.get("nom", ""),
        "prenom": entry.get("prenom", ""),
        "civilite": entry.get("civilite", ""),
        "particule": entry.get("particule", ""),
        "to_cc_cci": to_cc_cci,
        "fonction": fonction,
        "classes": [],
        "classe": classe,
        "isPP": False,
        "responsable": entry.get("responsable") or {},
    }


def recipient_display(r: dict) -> str:
    """'Mme Marie MARTIN [A:301]' — name plus the TYPE:ID usable in --to."""
    return f"{participant_name(r)} [{r.get('type')}:{r.get('id')}]".strip()


def group_recipients(recipients: list[dict]) -> list[dict]:
    """Bucket recipients by profile type into the composer's ``groupesDestinataires``."""
    groups: dict[str, list[dict]] = {}
    for r in recipients:
        groups.setdefault(r["type"], []).append(r)
    return [{"destinataires": rs, "selection": {"type": t}} for t, rs in groups.items()]


def build_message(
    acc: dict,
    subject: str,
    body_html: str,
    recipients: list[dict],
    files: list[dict],
    response_id: int | None = None,
    draft: bool = False,
) -> dict:
    """Assemble the ``message`` object that ``messages.awp?verbe=post`` expects.

    ``brouillon`` saves to the Brouillons folder instead of sending; the sender
    is the logged-in account (its ``typeCompte`` is the ``role``).
    """
    msg = {
        "subject": subject,
        "content": encode_message_content(body_html),
        "groupesDestinataires": group_recipients(recipients),
        "files": files,
        "transfertFiles": [],
        "read": True,
        "from": {"role": acc.get("typeCompte"), "id": acc.get("id"), "read": True},
        "brouillon": draft,
    }
    if response_id is not None:
        msg["responseId"] = int(response_id)
    return msg


def is_self(acc: dict, participant: dict) -> bool:
    """Whether a message participant is the logged-in account itself."""
    return str(participant.get("id")) == str(acc.get("id")) and (
        participant.get("role") or participant.get("type")
    ) == acc.get("typeCompte")


def resolve_recipient(spec: str, directory: list[dict], to_cc_cci: str = "to") -> dict:
    """Turn a ``--to`` value into a recipient: exact ``TYPE:ID`` or a unique name match.

    Name matching is a case-insensitive substring over first/last name and
    function label, so 'martin' or 'directrice' both work when unambiguous.
    """
    m = RECIPIENT_SPEC.match(spec.strip())
    if m:
        kind, ident = m.group(1), int(m.group(2))
        for c in directory:
            if c.get("type") == kind and str(c.get("id")) == str(ident):
                return recipient(c, to_cc_cci)
        return recipient({"id": ident, "type": kind}, to_cc_cci)
    needle = spec.strip().lower()
    hits = [
        c
        for c in directory
        if needle in f"{c.get('prenom', '')} {c.get('nom', '')}".lower()
        or needle in ((c.get("fonction") or {}).get("libelle") or "").lower()
    ]
    if len(hits) == 1:
        return recipient(hits[0], to_cc_cci)
    if not hits:
        raise EDError(f"No contact matching '{spec}'. Run `contacts` to list who you can write to.")
    options = ", ".join(recipient_display(recipient(c)) for c in hits)
    raise EDError(f"'{spec}' is ambiguous ({options}). Use the TYPE:ID form.")


def read_body(body: str | None, body_file: str | None) -> str:
    """The message text from --body, --body-file ('-' = stdin), or piped stdin."""
    if body and body_file:
        raise EDError("Pass either --body or --body-file, not both.")
    if body:
        return body
    if body_file:
        text = sys.stdin.read() if body_file == "-" else Path(body_file).read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        raise EDError("No body: pass --body TEXT, --body-file PATH, or pipe text on stdin.")
    if not text.strip():
        raise EDError("The message body is empty.")
    return text


def mailbox_settings(client: EDClient, acc: dict) -> dict:
    """The school's mailbox ``parametrage`` (who this account may write to).

    It only travels with a folder listing, so a one-item list call fetches it.
    """
    data = client.post(
        f"{mailbox_path(acc)}/messages.awp",
        {},
        extra={
            "typeRecuperation": "received",
            "getAll": "0",
            "idClasseur": "0",
            "orderBy": "date",
            "order": "desc",
            "page": "0",
            "itemsPerPage": "1",
        },
    )
    return data.get("parametrage") or {}


def fetch_contacts(client: EDClient, cfg: dict, acc: dict) -> tuple[list[dict], list[str]]:
    """Every contact the account may write to, plus notes on directories it cannot reach.

    Schools gate each directory: ``destAdmin`` opens the staff list, ``destProf``
    the teachers of each child. A closed directory is reported, not fetched.
    """
    settings = mailbox_settings(client, acc)
    contacts: list[dict] = []
    notes: list[str] = []
    if settings.get("destAdmin"):
        contacts += client.post("messagerie/contacts/personnels.awp", {}).get("contacts") or []
    else:
        notes.append("school staff: the school does not let this account write to them (destAdmin off)")
    if settings.get("destProf"):
        for s in list_students(cfg):
            try:
                data = client.post(
                    "messagerie/contacts/professeurs.awp", {}, extra={"idEleve": s["id"], "nom": ""}
                )
                contacts += data.get("contacts") or []
            except EDError as exc:
                notes.append(f"teachers of {student_name(s)}: {exc}")
    else:
        notes.append("teachers: the school does not let this account write to them (destProf off)")
    return contacts, notes


def output(data, as_json: bool, render) -> None:
    """Either dump raw JSON or call the human renderer."""
    if as_json:
        console.print_json(json.dumps(data, ensure_ascii=False))
    else:
        render(data)


# --- CLI ---------------------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="ecoledirecte")
@click.option("--debug", is_flag=True, help="Verbose logging of HTTP traffic.")
def cli(debug: bool) -> None:
    """EcoleDirecte from the terminal: grades, homework, timetable, messages.

    Acts as the logged-in parent or student over EcoleDirecte's private JSON
    API. Run `login` once interactively (it answers the 2FA question and stores
    a trusted device); every other command then runs unattended. Every read
    supports --json. `reply` and `send` are dry runs unless --yes is passed.
    """
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

    # An explicit opt-out also removes the legacy local password copy.
    result.pop("password", None)
    where = "not stored"
    if no_store_password:
        delete_password(identifiant)
    if not no_store_password:
        result["password"] = password
        where = "password queued for 1Password with protected offline persistence"
    CONFIG_FILE.with_suffix(".signed-out").unlink(missing_ok=True)
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
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.with_suffix(".signed-out").touch(mode=0o600)
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
                "" if is_read(m) else "●",
            )
        console.print(table)
        unread = sum(1 for m in items if not is_read(m))
        console.print(
            f"[dim]{len(items)} message(s), {unread} unread (●). Read one with: read <ID>[/dim]"
        )

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


@cli.command()
@click.argument("message_id")
@click.option("--file", "file_id", help="Only this attachment id (default: all attachments).")
@click.option("--folder", type=click.Choice(list(FOLDERS)), default="received",
              help="Folder the message is in. Default: received.")
@click.option("--year", help="School year the message belongs to, e.g. 2025-2026.")
@click.option("--out", "-o", default=".", type=click.Path(file_okay=False, path_type=Path),
              help="Directory to save into. Default: current directory.")
def download(message_id: str, file_id: str | None, folder: str, year: str | None, out: Path) -> None:
    """Download a message's attachment(s) to disk (see IDs from `messages`/`read`)."""
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    payload = {"anneeMessages": year} if year else {}
    msg = client.post(
        f"{mailbox_path(acc)}/messages/{message_id}.awp",
        payload,
        extra={"mode": FOLDERS[folder]["mode"]},
    )
    files = msg.get("files") or []
    if file_id:
        files = [f for f in files if str(f.get("id")) == str(file_id)]
    if not files:
        raise EDError("No matching attachment on that message.")

    out.mkdir(parents=True, exist_ok=True)
    for f in files:
        content = client.download(f["id"], f.get("type") or "PIECE_JOINTE", payload)
        name = safe_filename(f.get("libelle", ""), f"attachment_{f['id']}")
        path = out / name
        path.write_bytes(content)
        console.print(f"[green]✓[/green] {path} [dim]({len(content):,} bytes)[/dim]")
    save_config({**cfg, "token": client.token})


@cli.command()
@click.argument("message_ids", nargs=-1, required=True)
@click.option("--read/--unread", "as_read", default=True,
              help="Mark as read (default) or --unread.")
@click.option("--year", help="School year the message(s) belong to, e.g. 2025-2026.")
def mark(message_ids: tuple[str, ...], as_read: bool, year: str | None) -> None:
    """Mark one or more messages as read or unread.

    `read` and `download` already mark a message read as a side effect; use
    `mark --unread <ID>` to undo that.
    """
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    action = "marquerCommeLu" if as_read else "marquerCommeNonLu"
    client.post(
        f"{mailbox_path(acc)}/messages.awp",
        {"action": action, "ids": [int(i) for i in message_ids], "anneeMessages": year or ""},
        verbe="put",
    )
    save_config({**cfg, "token": client.token})
    state = "read" if as_read else "unread"
    console.print(f"[green]✓[/green] Marked {len(message_ids)} message(s) as {state}.")


def _attach_option(f):
    return click.option(
        "--attach",
        "attachments",
        multiple=True,
        type=click.Path(exists=True, dir_okay=False, path_type=Path),
        help="File to attach (repeatable).",
    )(f)


def _compose_options(f):
    """Options shared by `reply` and `send`: body source, attachments, delivery mode."""
    for opt in reversed(
        [
            click.option("--body", help="Message text. Blank lines separate paragraphs."),
            click.option("--body-file", help="Read the text from this file ('-' = stdin)."),
            _attach_option,
            click.option("--draft", is_flag=True, help="Save to Brouillons instead of sending."),
            click.option("--yes", is_flag=True, help="Actually send. Without it, only preview."),
            click.option("--json", "as_json", is_flag=True, help="Output the API response as JSON."),
        ]
    ):
        f = opt(f)
    return f


def preview_message(subject: str, recipients: list[dict], body_html: str, attachments: tuple[Path, ...]) -> None:
    """Print what would be sent, in the same words a mail client uses."""
    for slot in ("to", "cc", "cci"):
        people = [recipient_display(r) for r in recipients if r["to_cc_cci"] == slot]
        if people:
            console.print(f"[bold]{slot.upper()}:[/bold] {', '.join(people)}")
    console.print(f"[bold]Subject:[/bold] {subject}")
    if attachments:
        names = ", ".join(f"{p.name} ({p.stat().st_size:,} bytes)" for p in attachments)
        console.print(f"[bold]Attachments:[/bold] {names}")
    console.print()
    console.print(html_to_text(body_html))
    console.print()


def deliver(
    client: EDClient,
    cfg: dict,
    acc: dict,
    message: dict,
    attachments: tuple[Path, ...],
    yes: bool,
    as_json: bool,
) -> None:
    """Upload the attachments, post the message (or draft), report the new id.

    Nothing leaves the account unless ``yes`` or the message is a draft: the
    default path prints the preview and stops before any upload.
    """
    draft = message.get("brouillon", False)
    recipients = [r for g in message["groupesDestinataires"] for r in g["destinataires"]]
    if not yes and not draft:
        preview_message(message["subject"], recipients, decode_b64_text(message["content"]), attachments)
        console.print(
            "[yellow]Dry run — nothing sent. Add --yes to send, or --draft to save a draft.[/yellow]"
        )
        return
    files = []
    for path in attachments:
        descriptor = client.upload(path)
        files.append(descriptor)
        console.print(f"[green]✓[/green] uploaded {descriptor.get('libelle') or path.name}")
    message["files"] = files
    data = client.post(
        f"{mailbox_path(acc)}/messages.awp", {"message": message, "anneeMessages": ""}, verbe="post"
    )
    save_config({**cfg, "token": client.token})

    def render(d):
        verb = "Draft saved" if draft else "Sent"
        names = ", ".join(recipient_display(r) for r in recipients)
        console.print(
            f"[green]✓[/green] {verb} message #{d.get('id')} to {names} "
            f"[dim]({len(files)} attachment(s))[/dim]"
        )

    output(data, as_json, render)


@cli.command()
@click.option("--search", help="Only contacts whose name or function contains this text.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
def contacts(search: str | None, as_json: bool) -> None:
    """List the people this account may write to (use their TYPE:ID with `send --to`)."""
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    directory, notes = fetch_contacts(client, cfg, acc)
    save_config({**cfg, "token": client.token})
    if search:
        needle = search.lower()
        directory = [
            c
            for c in directory
            if needle in participant_name(c).lower()
            or needle in ((c.get("fonction") or {}).get("libelle") or "").lower()
        ]

    def render(d):
        if d:
            table = Table("Type", "ID", "Name", "Function")
            for c in d:
                table.add_row(
                    f"{c.get('type', '')} ({RECIPIENT_TYPES.get(c.get('type', ''), '?')})",
                    str(c.get("id", "")),
                    participant_name(c),
                    (c.get("fonction") or {}).get("libelle") or "",
                )
            console.print(table)
            console.print(f"[dim]{len(d)} contact(s). Write to one with: send --to TYPE:ID[/dim]")
        else:
            console.print("[yellow]No contact available.[/yellow]")
        for n in notes:
            console.print(f"[dim]• {n}[/dim]")

    output(directory, as_json, render)


@cli.command()
@click.argument("message_id")
@click.option("--folder", type=click.Choice(list(FOLDERS)), default="received",
              help="Folder the message is in. Default: received.")
@click.option("--year", help="School year the message belongs to, e.g. 2025-2026.")
@click.option("--all", "reply_all", is_flag=True, help="Reply to the sender and every other recipient.")
@click.option("--no-quote", is_flag=True, help="Do not quote the original message below the reply.")
@_compose_options
def reply(
    message_id: str,
    folder: str,
    year: str | None,
    reply_all: bool,
    no_quote: bool,
    body: str | None,
    body_file: str | None,
    attachments: tuple[Path, ...],
    draft: bool,
    yes: bool,
    as_json: bool,
) -> None:
    """Reply to a message, optionally with attachments. Dry run unless --yes.

    The reply goes to the original sender (plus the other recipients with
    --all), quotes the original like the website does, and is saved as a
    draft with --draft. Opening the message marks it read, like `read`.
    """
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    text = read_body(body, body_file)
    payload = {"anneeMessages": year} if year else {}
    msg = client.post(
        f"{mailbox_path(acc)}/messages/{message_id}.awp",
        payload,
        extra={"mode": FOLDERS[folder]["mode"]},
    )
    if str(msg.get("canAnswer", True)).strip().lower() == "false":
        raise EDError(
            f"Message {message_id} does not accept replies (a circular or no-reply sender)."
        )
    recipients = [recipient(msg.get("from") or {})]
    if reply_all:
        recipients += [
            recipient(p, p.get("to_cc_cci") or "to")
            for p in msg.get("to") or []
            if not is_self(acc, p)
        ]
    body_html = text_to_html(text) + ("" if no_quote else quote_original(msg))
    message = build_message(
        acc,
        reply_subject(msg.get("subject", "")),
        body_html,
        recipients,
        [],
        response_id=msg.get("id") or int(message_id),
        draft=draft,
    )
    deliver(client, cfg, acc, message, attachments, yes, as_json)


@cli.command()
@click.option("--to", "to", multiple=True, required=True,
              help="Recipient: TYPE:ID or a unique name/function substring (repeatable).")
@click.option("--cc", "cc", multiple=True, help="Carbon-copy recipient, same forms as --to.")
@click.option("--subject", required=True, help="Message subject.")
@_compose_options
def send(
    to: tuple[str, ...],
    cc: tuple[str, ...],
    subject: str,
    body: str | None,
    body_file: str | None,
    attachments: tuple[Path, ...],
    draft: bool,
    yes: bool,
    as_json: bool,
) -> None:
    """Send a new message, optionally with attachments. Dry run unless --yes.

    Recipients come from `contacts`: give the TYPE:ID shown there, or a name
    fragment that matches exactly one person. --draft saves to Brouillons.
    """
    cfg = require_login()
    acc = primary_account(cfg)
    client = EDClient(cfg)
    text = read_body(body, body_file)
    directory, _ = fetch_contacts(client, cfg, acc)
    recipients = [resolve_recipient(spec, directory, "to") for spec in to]
    recipients += [resolve_recipient(spec, directory, "cc") for spec in cc]
    message = build_message(acc, subject, text_to_html(text), recipients, [], draft=draft)
    deliver(client, cfg, acc, message, attachments, yes, as_json)



@cli.command("auth-status")
@click.option("--json", "as_json", is_flag=True, help="Emit secret-free metadata.")
def auth_status(as_json):
    """Report credential storage without contacting the provider. Example: auth-status --json."""
    import json
    metadata = _auth_broker("status") or {
        "connector": "ecoledirecte", "account": "default", "source": "unavailable",
        "configured": False, "pending": False, "last_sync": None,
    }
    if not metadata.get("configured") and CONFIG_FILE.exists():
        metadata.update(source="legacy", configured=True)
    metadata.update(session_scope="portable")
    if CONFIG_FILE.with_suffix(".auth-pending").exists():
        metadata.update(source="pending-local", configured=True, pending=True)
    if CONFIG_FILE.with_suffix(".signed-out").exists():
        metadata.update(configured=False, signed_out=True)
    click.echo(json.dumps(metadata))


@cli.command("auth-sync")
def auth_sync():
    """Move stored credentials into 1Password. Example: auth-sync."""
    import json
    if CONFIG_FILE.with_suffix(".signed-out").exists():
        raise click.ClickException("This host is signed out. Connect the account before synchronizing.")
    local_pending = CONFIG_FILE.with_suffix(".auth-pending")
    metadata = _auth_broker("save", _legacy_config()) if local_pending.exists() else _auth_broker("sync")
    if metadata and local_pending.exists():
        local_pending.unlink()
    if not metadata or not metadata.get("configured"):
        config = load_config()
        if config and not config.get("password"):
            password = fetch_password(config.get("identifiant", ""))
            if password:
                config["password"] = password
        metadata = _auth_broker("save", config) if config else metadata
    click.echo(json.dumps(metadata or {"connector": "ecoledirecte", "source": "unavailable", "pending": False}))
    if not metadata or not metadata.get("configured") or metadata.get("pending"): raise click.exceptions.Exit(3)


# Provider commands share the app and MCP execution policy.
from pathlib import Path as _PolicyPath
import sys as _policy_sys
_policy_sys.path.insert(0, str(_PolicyPath(__file__).resolve().parent))
from onebrain_policy import install as _install_onebrain_policy
_install_onebrain_policy(cli, 'ecoledirecte')

if __name__ == "__main__":
    cli()
