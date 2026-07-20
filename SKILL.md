---
name: ecoledirecte-cli
description: >
  Read a French school's EcoleDirecte account from the terminal using
  ecoledirecte_cli.py — grades (notes), homework (cahier de textes), timetable
  (emploi du temps) and the internal mailbox (messagerie). Talks to the private
  EcoleDirecte JSON API (api.ecoledirecte.com/v3), the same back-end the web and
  mobile apps use, authenticating as the user (parent or student) with a rotating
  session token; handles the mandatory two-factor "question secrète" on first
  login. Every read supports --json for piping. Use when the user wants to check
  their child's or their own grades, homework, schedule or EcoleDirecte messages.
  Triggers: "check my kid's grades", "ecoledirecte", "notes ecole directe",
  "cahier de textes", "emploi du temps", "mes messages ecole directe".
---

# ecoledirecte-cli

Single-file client for **EcoleDirecte**, the portal French private schools use
for grades, homework, timetables and parent↔school messaging. There is no
official public API; this drives the private JSON API at
`https://api.ecoledirecte.com/v3/` — the same one the website and apps use.

It authenticates **as the user** (a parent or student login), not via an API
key. The session token **rotates on every response**, and the first login on a
new device triggers a **two-factor security question** ("question secrète")
that the user answers once; the resulting trusted-device tokens are then stored
so future logins skip it.

## Running

```bash
uv run /Users/clementwalter/Documents/ecoledirecte-cli/ecoledirecte_cli.py <command> [options]
```

(Optionally alias it: `alias ecoledirecte='uv run …/ecoledirecte_cli.py'`.)

## When to use

- "Quelles sont les dernières notes de mon fils / ma fille ?"
- "Y a-t-il des devoirs pour demain ?"
- "Montre l'emploi du temps de la semaine."
- "Ai-je des nouveaux messages sur EcoleDirecte ?"

## When NOT to use

- Sending messages, paying invoices, or submitting forms — this is a **read**
  tool for v1. It never writes.
- A feature the school hasn't enabled. Availability is **per account**: each
  school turns modules on or off. If a module is off the CLI says so clearly
  (e.g. *"The 'Notes' module (NOTES) is disabled for Thalie"*) — that is not a
  bug, the API genuinely won't serve it for that account. Check `whoami` to see
  which modules are enabled before promising a feature.

## Authentication

First login is **interactive** (the 2FA question can't be answered
non-interactively), so run it in a real terminal:

```bash
uv run …/ecoledirecte_cli.py login
```

It prompts for the identifiant (username) and password — the password is typed
at a hidden prompt, or read from `$ECOLEDIRECTE_PASSWORD` for automation — then,
on a new device, prints the security question and its numbered choices. The user
picks the number. On success the session is written to
`~/.config/ecoledirecte-cli/config.json` (mode 600): identifiant, the
trusted-device tokens (`cn`/`cv`, so 2FA is not asked again), and the session
token.

**Password storage.** EcoleDirecte has no static bearer token — the session
token rotates and expires, and re-login always needs the password. So the
password is kept, but **on macOS it goes into the login Keychain** (via the
`security` tool), never the config file; a legacy plaintext password from an
older session is migrated to the Keychain automatically on first use. On
non-macOS it falls back to the mode-600 config file. `login --no-store-password`
keeps nothing (re-prompts on expiry); `logout` clears both file and Keychain.

Agents should **not** try to bypass or auto-answer the 2FA question — ask the
user to run `login` once. After that, all read commands work unattended and
auto-re-login when the token expires.

Use `--no-store-password` on `login` to avoid saving the password (the user is
then re-prompted whenever the token expires). `logout` deletes the local file.

## Usage by an agent

### 1. Check login + see what's available

```bash
uv run …/ecoledirecte_cli.py whoami --json
```

Shows the account (parent vs élève), the reachable students with their ids, and
each student's **enabled modules**. Use the module list to know whether `notes`,
`homework`, `timetable` will return data for a given student. If it errors with
"Not logged in", ask the user to run `login`.

### 2. Read

All read commands accept `--json` (raw API `data`) and, where a parent has more
than one child, `--student <id-or-name>` to pick one.

```bash
uv run …/ecoledirecte_cli.py notes [--student NAME] [--year 2025-2026] [--json]
uv run …/ecoledirecte_cli.py homework [--student NAME] [--date YYYY-MM-DD] [--json]
uv run …/ecoledirecte_cli.py timetable [--student NAME] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--json]
uv run …/ecoledirecte_cli.py messages [--folder received|sent|archived|draft] [--year 2025-2026] [--json]
uv run …/ecoledirecte_cli.py read <MESSAGE_ID> [--folder received] [--year 2025-2026] [--json]
```

- `notes` — grades with per-devoir value, scale, coefficient and subject.
- `homework` — the cahier de textes: without `--date`, upcoming days and which
  have work to do; with `--date`, the detail for that day.
- `timetable` — lessons in a date range (defaults today → +7 days).
- `messages` — lists a mailbox folder in full (not just the first page of 20),
  printing each message's **ID**. `--folder` selects `received` (default),
  `sent`, `archived` or `draft`. Defaults to the **current** school year, which
  is often empty early on; pass `--year 2025-2026` (EcoleDirecte's own string
  form) to read a **previous** year — the "Année précédente" dropdown.
- `read <ID>` — opens one message: subject, sender, date, the body (base64 HTML
  decoded to plain text), and any attachments. Use `--folder sent` for a message
  from the sent folder, and the same `--year` you listed it under.

For a parent account, grades/homework/timetable use the **student** id; messages
use the **family** id — the CLI picks the right one automatically.

## Notes / gotchas

- **Rotating token**: handled internally; each response's token is reused on the
  next call and persisted, so sequential commands don't re-login.
- **Module names** (from `whoami`): `NOTES`, `CAHIER_DE_TEXTES`, `EDT`
  (emploi du temps), `MESSAGERIE`, `VIE_SCOLAIRE`, `DOCUMENTS_ELEVE`, …
- The `--year` values follow EcoleDirecte's own strings: school years like
  `2025-2026` for notes, and `2026-2027`-style for messages.
