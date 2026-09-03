# ecoledirecte-cli

A French school's **EcoleDirecte** account from the terminal — grades, homework,
timetable and the internal mailbox (read, reply and send, with attachments) — in
one self-contained Python script.

EcoleDirecte has no official public API. This CLI drives the private JSON API at
`https://api.ecoledirecte.com/v3/` (the same back-end the website and mobile apps
use), authenticating **as the user** (a parent or student login).

## Install

Nothing to install — [`uv`](https://docs.astral.sh/uv/) runs the script and its
dependencies inline (PEP 723):

```bash
ecoledirecte --help
```

To use it from any directory, put the launcher on `$PATH` — the symlink points at
the checkout, so a `git pull` is all an upgrade takes:

```bash
ln -sfn /path/to/ecoledirecte-cli/bin/ecoledirecte ~/.local/bin/ecoledirecte
```

## Authentication

```bash
ecoledirecte login
```

Prompts for your identifiant and password. **On a new device EcoleDirecte asks a
two-factor security question** ("question secrète") — the CLI prints the choices
and you pick the number, once. The trusted-device tokens are then saved so it
isn't asked again.

Where the password is stored:

- **macOS** → the login **Keychain** (never written to disk in cleartext). An
  older plaintext password is migrated to the Keychain automatically.
- **Other OSes** → `~/.config/ecoledirecte-cli/config.json`, mode 600.
- `login --no-store-password` → nothing stored; you re-enter it when the rotating
  token expires.

For automation, the password can come from `$ECOLEDIRECTE_PASSWORD` (and the
username from `$ECOLEDIRECTE_IDENTIFIANT`). `logout` clears the local session and
the Keychain entry.

## Usage

| Command | What it shows |
|---|---|
| `login` / `logout` | Sign in (handles 2FA) / clear the local session |
| `whoami [--json]` | The account, the students, and each student's **enabled modules** |
| `notes [--student N] [--year 2025-2026] [--json]` | Grades (notes) |
| `homework [--student N] [--date YYYY-MM-DD] [--json]` | Cahier de textes |
| `timetable [--student N] [--from …] [--to …] [--json]` | Emploi du temps |
| `messages [--folder received] [--year 2025-2026] [--json]` | Messagerie — full list of a folder |
| `read <ID> [--folder received] [--year …] [--json]` | One message, body decoded to text + attachments |
| `download <ID> [--file FID] [--folder …] [--year …] [-o DIR]` | Save a message's attachment(s) to disk |
| `mark <ID>... [--read/--unread] [--year …]` | Mark message(s) read or unread |
| `contacts [--search TEXT] [--json]` | Who this account may write to, with their `TYPE:ID` |
| `reply <ID> [--body TEXT] [--attach FILE]... [--all] [--yes]` | Reply to a message, quoting it, with attachments |
| `send --to TYPE:ID... --subject S [--body TEXT] [--attach FILE]... [--yes]` | New message to one or more contacts |

Every read command supports `--json` for piping into `jq`/scripts, and the
grade/homework/timetable commands take `--student <id-or-name>` to pick a child
on a multi-child parent account.

```bash
ecoledirecte whoami
ecoledirecte notes --student Alice
ecoledirecte homework --date 2026-09-15
ecoledirecte timetable --from 2026-09-14 --to 2026-09-20
ecoledirecte messages --year 2025-2026          # previous school year
ecoledirecte messages --folder sent             # sent folder
ecoledirecte read 57 --year 2025-2026           # read message id 57
ecoledirecte download 57 --year 2025-2026 -o ./dl  # save its attachments
ecoledirecte contacts                            # who can I write to?
ecoledirecte reply 57 --body "Merci, c'est noté." --attach justificatif.pdf        # preview
ecoledirecte reply 57 --body "Merci, c'est noté." --attach justificatif.pdf --yes  # send
ecoledirecte send --to A:301 --subject "Absence" --body-file mot.txt --draft      # save a draft
```

`messages` lists the **whole** folder (not just the first page) and prints each
message's ID; pass that ID to `read`. Folders: `received` (default), `sent`,
`archived`, `draft`.

## Feature availability is per account

Each school enables EcoleDirecte modules independently. If a module is off for an
account, the CLI says so plainly instead of returning a blank result:

```
$ ecoledirecte notes
Error: The 'Notes' module (NOTES) is disabled for Alice. The school does not
publish this feature through EcoleDirecte.
```

Run `whoami` to see which modules (`NOTES`, `CAHIER_DE_TEXTES`, `EDT`,
`MESSAGERIE`, …) are enabled for each student.

## How auth works (for the curious)

1. `GET /login.awp?gtk=1` sets a short-lived `GTK` cookie (a CSRF token).
2. `POST /login.awp` with header `X-GTK` = the GTK value and a form body
   `data=<json>` of `{identifiant, motdepasse, fa}`. `fa` is the trusted device.
3. Without `fa`, the server returns `code 250`; the CLI fetches the security
   question from `/connexion/doubleauth.awp`, you answer it, and it returns the
   `cn`/`cv` trust tokens folded into a second login.
4. Every authenticated call then sends `X-Token` (a token that **rotates** each
   response) and a constant `2FA-Token`, both issued by the login response.

## Output conventions

- **`--json` everywhere.** Every read command emits the API's own `data`
  payload — pipe it to `jq`/python rather than parsing the human output.
- **Default output is compact tables**, one line per grade / lesson / message,
  carrying the id the next command needs.
- **No silent fallbacks.** A disabled module, an unknown student or an expired
  session exits non-zero with a one-line reason, never an empty result.

## Tests

```bash
uv run --with pytest --with click --with curl_cffi --with rich \
  python -m pytest tests/ -q
```

80 tests over the network-free layers — body encoding, student resolution,
module gating, HTML/base64 decoding, message composition (HTML body, entity
escaping, recipients, payload, dry-run guard), password-storage precedence, and
the CLI help/version surface. The auth dance and the endpoints are verified live
via `login` and `--draft`, not mocked.

## Writing: reply and send

`reply` and `send` are **dry runs by default**: they print the recipients,
subject, body and attachments and stop. Add `--yes` to actually send, or
`--draft` to save into Brouillons (nothing leaves the account). The body comes
from `--body`, `--body-file` (`-` for stdin) or piped stdin; blank lines separate
paragraphs. Each `--attach FILE` is uploaded first, then the message is posted
with the files attached — the same two-step the website's composer performs.

- `reply <ID>` answers the sender (`--all` adds the other recipients) and quotes
  the original below your text (`--no-quote` to skip). A circular that does not
  accept answers is refused up front.
- `send --to` takes the `TYPE:ID` shown by `contacts` (e.g. `A:301`) or a name /
  function fragment that matches exactly one person; `--cc` takes the same forms.
- `contacts` lists the directories the **school** lets this account write to —
  often only the administrative staff, teachers being closed to parents
  (`destProf` off). The CLI says which directories are closed.

## Reading marks messages as read

Opening a message (`read`) or fetching its attachments (`download`) marks it
**read** on the server — the API's single-message fetch does this, exactly like
opening it on the website. To undo, use `mark --unread <ID>`.

## Scope

Reads everything; writes only to the mailbox — `mark` toggles read/unread, and
`reply`/`send` post messages (never without `--yes`, or as a draft). It never
pays invoices, submits forms, or deletes anything.
