# ecoledirecte-cli

Read a French school's **EcoleDirecte** account from the terminal — grades,
homework, timetable and the internal mailbox — in one self-contained Python
script.

EcoleDirecte has no official public API. This CLI drives the private JSON API at
`https://api.ecoledirecte.com/v3/` (the same back-end the website and mobile apps
use), authenticating **as the user** (a parent or student login).

## Install / run

Nothing to install — [`uv`](https://docs.astral.sh/uv/) runs the script and its
dependencies inline (PEP 723):

```bash
uv run ecoledirecte_cli.py --help
```

Optional alias:

```bash
alias ecoledirecte='uv run /path/to/ecoledirecte_cli.py'
```

## Authentication

```bash
uv run ecoledirecte_cli.py login
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

## Commands

| Command | What it shows |
|---|---|
| `login` / `logout` | Sign in (handles 2FA) / clear the local session |
| `whoami [--json]` | The account, the students, and each student's **enabled modules** |
| `notes [--student N] [--year 2025-2026] [--json]` | Grades (notes) |
| `homework [--student N] [--date YYYY-MM-DD] [--json]` | Cahier de textes |
| `timetable [--student N] [--from …] [--to …] [--json]` | Emploi du temps |
| `messages [--folder received] [--year 2025-2026] [--json]` | Messagerie — full list of a folder |
| `read <ID> [--folder received] [--year …] [--json]` | One message, body decoded to text + attachments |

Every read command supports `--json` for piping into `jq`/scripts, and the
grade/homework/timetable commands take `--student <id-or-name>` to pick a child
on a multi-child parent account.

```bash
uv run ecoledirecte_cli.py whoami
uv run ecoledirecte_cli.py notes --student Thalie
uv run ecoledirecte_cli.py homework --date 2026-09-15
uv run ecoledirecte_cli.py timetable --from 2026-09-14 --to 2026-09-20
uv run ecoledirecte_cli.py messages --year 2025-2026          # previous school year
uv run ecoledirecte_cli.py messages --folder sent             # sent folder
uv run ecoledirecte_cli.py read 57 --year 2025-2026           # read message id 57
```

`messages` lists the **whole** folder (not just the first page) and prints each
message's ID; pass that ID to `read`. Folders: `received` (default), `sent`,
`archived`, `draft`.

## Feature availability is per account

Each school enables EcoleDirecte modules independently. If a module is off for an
account, the CLI says so plainly instead of returning a blank result:

```
$ uv run ecoledirecte_cli.py notes
Error: The 'Notes' module (NOTES) is disabled for Thalie. The school does not
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

## Development

```bash
uv run --with pytest --with click --with curl_cffi --with rich \
  python -m pytest tests/ -q
```

The tests cover the network-free logic (body encoding, student resolution,
module gating, password-storage precedence). The auth flow and endpoints are
verified live via `login`.

## Scope

v1 is **read-only**: it never sends messages, pays invoices, or submits forms.
