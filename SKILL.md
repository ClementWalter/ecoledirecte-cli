---
name: ecoledirecte-cli
description: >
  Read a French school's EcoleDirecte account from the terminal using
  ecoledirecte_cli.py — grades (notes), homework (cahier de textes), timetable
  (emploi du temps) and the internal mailbox (messagerie), and reply to or send
  messages with attachments (dry run unless --yes). Talks to the private
  EcoleDirecte JSON API (api.ecoledirecte.com/v3), the same back-end the web and
  mobile apps use, authenticating as the user (parent or student) with a rotating
  session token; handles the mandatory two-factor "question secrète" on first
  login. Every read supports --json for piping. Use when the user wants to check
  their child's or their own grades, homework, schedule or EcoleDirecte messages,
  or answer / write to the school through the messagerie.
  Triggers: "check my kid's grades", "ecoledirecte", "notes ecole directe",
  "cahier de textes", "emploi du temps", "mes messages ecole directe",
  "réponds à ce message ecole directe", "envoie un message à l'école".
allowed-tools:
  - Bash
  - Read
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

## How to invoke

Invoke it as **`ecoledirecte`** — on `$PATH` via a symlink in `~/.local/bin` onto this
repo's `bin/ecoledirecte`, so it always runs the current checkout: a `git pull`, or even
an uncommitted edit, takes effect immediately with nothing to reinstall.

```bash
ecoledirecte notes
```

Examples in this doc are written that way. If `ecoledirecte` is not on `$PATH`, run the
bundled launcher `bin/ecoledirecte` resolved against this skill's own directory (PEP 723
— `uv` resolves deps inline on first run), or link it once:

```bash
ln -sfn <skill-dir>/bin/ecoledirecte ~/.local/bin/ecoledirecte
```

## When to use

- "Quelles sont les dernières notes de mon fils / ma fille ?"
- "Y a-t-il des devoirs pour demain ?"
- "Montre l'emploi du temps de la semaine."
- "Ai-je des nouveaux messages sur EcoleDirecte ?"
- "Réponds à la secrétaire avec le justificatif en pièce jointe."

## When NOT to use

- Paying invoices, submitting forms, deleting or archiving messages — the only
  writes are `mark` (read state) and `reply`/`send` (mailbox), and a message
  never leaves the account without `--yes` (or lands in Brouillons with
  `--draft`). Show the user the dry-run preview before passing `--yes`.
- A feature the school hasn't enabled. Availability is **per account**: each
  school turns modules on or off. If a module is off the CLI says so clearly
  (e.g. *"The 'Notes' module (NOTES) is disabled for Alice"*) — that is not a
  bug, the API genuinely won't serve it for that account. Check `whoami` to see
  which modules are enabled before promising a feature.

## Authentication

First login is **interactive** (the 2FA question can't be answered
non-interactively), so run it in a real terminal:

```bash
ecoledirecte login
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

## Output conventions

- **`--json` everywhere.** Every read command emits the API's own `data`
  payload — use it to chain commands or extract fields; never parse the human
  output.
- **Default output is compact tables**, one line per grade / lesson / message,
  with the id you need for the next call (message IDs, student ids) in view.
- **No silent fallbacks.** A disabled module, an unknown student or an expired
  session is an error with a one-line reason and a non-zero exit, never an
  empty result — surface it rather than reporting "nothing found".

## Commands

### 1. Check login + see what's available

```bash
ecoledirecte whoami --json
```

Shows the account (parent vs élève), the reachable students with their ids, and
each student's **enabled modules**. Use the module list to know whether `notes`,
`homework`, `timetable` will return data for a given student. If it errors with
"Not logged in", ask the user to run `login`.

### 2. Read

All read commands accept `--json` (raw API `data`) and, where a parent has more
than one child, `--student <id-or-name>` to pick one.

```bash
ecoledirecte notes [--student NAME] [--year 2025-2026] [--json]
ecoledirecte homework [--student NAME] [--date YYYY-MM-DD] [--json]
ecoledirecte timetable [--student NAME] [--from YYYY-MM-DD] [--to YYYY-MM-DD] [--json]
ecoledirecte messages [--folder received|sent|archived|draft] [--year 2025-2026] [--json]
ecoledirecte read <MESSAGE_ID> [--folder received] [--year 2025-2026] [--json]
ecoledirecte download <MESSAGE_ID> [--file FID] [--out DIR] [--folder received] [--year 2025-2026]
ecoledirecte mark <MESSAGE_ID>... [--read | --unread] [--year 2025-2026]
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
- `download <ID>` — saves the message's attachment(s) to disk (`--out DIR`,
  `--file FID` for just one) using the server's filename. The CLI only fetches
  the bytes; to *read* a PDF/image, open the saved file with your own tools (an
  agent can read the downloaded file directly). Pass the same `--folder`/`--year`
  used to find the message.
- `mark <ID>...` — marks message(s) `--read` (default) or `--unread`. Note that `read` and `download` already mark a message
  read as a side effect (the API does this on fetch, like the website); use
  `mark --unread` to undo. Pass `--year` if the message is from a past year.

For a parent account, grades/homework/timetable use the **student** id; messages
use the **family** id — the CLI picks the right one automatically.

### 3. Write to the school (reply / send)

```bash
ecoledirecte contacts [--search TEXT] [--json]
ecoledirecte reply <MESSAGE_ID> [--body TEXT | --body-file PATH] [--attach FILE]... [--all] [--no-quote] [--draft] [--yes] [--folder …] [--year …]
ecoledirecte send --to TYPE:ID... [--cc TYPE:ID]... --subject S [--body TEXT | --body-file PATH] [--attach FILE]... [--draft] [--yes]
```

Both are **dry runs by default**: they print TO/CC, subject, attachments and the
body, then stop with *"Dry run — nothing sent"*. Re-run with `--yes` to send, or
`--draft` to save into Brouillons without sending. Nothing is uploaded during a
dry run. Recommended flow for an agent: run without `--yes`, show the preview to
the user, send only once they confirm.

- Body: `--body "text"`, `--body-file PATH` (`-` = stdin), or pipe stdin. Plain
  text — blank lines become paragraphs, single newlines line breaks; markup is
  escaped. Accents are fine (entity-encoded like the website does).
- `--attach FILE` (repeatable) uploads each file through `televersement.awp`
  first, then posts the message carrying the returned descriptors; the server
  turns them into `PIECE_JOINTE` entries you can see with `read`.
- `reply <ID>` answers the original **sender**; `--all` adds every other
  recipient (minus yourself). Subject becomes `Re: …` (not stacked); the original
  is quoted below your text like the web composer (`--no-quote` to skip). A
  message with `canAnswer: false` (a circular) is refused before anything is
  sent. Opening it marks it read, as `read` does.
- `send --to` accepts the **`TYPE:ID`** printed by `contacts` (e.g. `A:301` — a
  staff member) or a name / function fragment matching exactly one contact;
  ambiguity is an error listing the candidates. `--cc` takes the same forms.
- `contacts` lists only the directories the **school** opens to this account
  (`parametrage.destAdmin` → staff, `destProf` → each child's teachers) and
  prints a note for each closed one. Many schools let parents write only to the
  administration. The teachers lookup (`professeurs.awp?idEleve=…`) is not
  verified live because the test school has `destProf` off.
- `--json` prints the API response (`{"id": <new message id>}`); the new message
  appears in `messages --folder sent` (or `draft`).

## Gotchas

- **Rotating token**: handled internally; each response's token is reused on the
  next call and persisted, so sequential commands don't re-login. A token the
  server no longer accepts comes back as `520 Token invalide !` or
  `525`, and both trigger one silent re-login from the stored password plus
  trusted device, so an unattended read recovers on its own. Note that `whoami`
  reads the cached config and makes no API call, so it succeeds even when the
  session is dead: to check a session is alive, run a real read (`messages`).
- **Module names** (from `whoami`): `NOTES`, `CAHIER_DE_TEXTES`, `EDT`
  (emploi du temps), `MESSAGERIE`, `VIE_SCOLAIRE`, `DOCUMENTS_ELEVE`, …
- The `--year` values follow EcoleDirecte's own strings: school years like
  `2025-2026` for notes, and `2026-2027`-style for messages.

## Tests

```bash
uv run --with pytest --with click --with curl_cffi --with rich \
  python -m pytest tests/ -q
```

80 tests over the network-free layers — body encoding, student resolution,
module gating, HTML/base64 decoding, message composition (HTML body, entity
escaping, recipients, payload, dry-run guard), password-storage precedence, and
the CLI help/version surface. The auth dance and the endpoints are verified live
against a real account (sending verified with `--draft`), not mocked.
