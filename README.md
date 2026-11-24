# handvault

**People type the password. Agents only ever see its length.**

`handvault` is a small CLI for the awkward moment when an AI agent needs a
credential you don't want to paste into a chat window.

```console
$ handvault put regrevia-mail yc@regrevia.com --imap imap.qiye.aliyun.com:993
a terminal window is open — type the password there

    (in that window)  Password (no echo):
                      17 characters
                      Again:
                      17 characters

OK service=regrevia-mail account=yc@regrevia.com length=17
IMAP OK (imap.qiye.aliyun.com:993, inbox 214)
```

The secret goes from your keyboard into the OS keychain. The agent's process
gets `length=17` and *that's it* — no plaintext in the transcript, in argv, in
the shell history, in a log file, or in the model's context.

## Install

```sh
npm install -g handvault
```

Requires Python 3.8+ and macOS (`security`) or Linux (`secret-tool` from
`libsecret`). No Python dependencies, no build step, no daemon.

## Why

An agent that can read a secret can leak it: into a log line, into its context
window, into the next prompt, into a screenshot, into a commit. The usual
workarounds are worse than the problem — `export TOKEN=...` in your history,
a `.env` file on disk, or pasting into chat and hoping.

`handvault` splits the job along the one line that matters: **the human supplies
it, the machine stores it, the agent only learns that it happened.**

## Commands

| Command | What the agent sees |
| --- | --- |
| `put SERVICE [ACCOUNT]` | `OK service=… account=… length=N` |
| `get SERVICE [ACCOUNT]` | length only; `--show` prints plaintext **and requires a tty** |
| `probe SERVICE [ACCOUNT] --imap H:P --smtp H:P` | `IMAP OK`, `SMTP FAIL …` — never the password |
| `exec SERVICE [ACCOUNT] --env NAME -- CMD…` | the command's own output; secret arrives via env |
| `exec SERVICE [ACCOUNT] --fd N -- CMD…` | same, but the secret arrives on fd N instead of the env |
| `list` | service, account, length, timestamp, still-there |
| `rm SERVICE [ACCOUNT]` | deleted |
| `doctor` | backend, file modes, leftovers |

Exit codes: `0` ok, `1` failed, `2` the human didn't finish (timeout or cancel).

### The three ways to hand over a secret

**1. Window (default when the caller has no terminal).** `put` spawns a
`.command` file in Terminal and waits. The agent's stdout only carries the
length. If you're slow, the agent times out and the window keeps working —
what you type still lands in the keychain, and `handvault list` shows it later.

**2. In place (when you already have a terminal).** `put` prompts right there,
twice, so a typo can't silently become your new password.

**3. `exec` — the secret never leaves the process tree.** For scripts and test
suites: the value is read from the keychain and handed to one child process, so
nothing is echoed and nothing is exported to your shell.

```sh
handvault exec qq-mail 2429936596@qq.com --env QPASS -- ./run-tests.sh
```

`--env` is the convenient form. An environment variable is readable by the same
user through `/proc/<pid>/environ` on Linux and shows up in crash dumps, so when
that matters use `--fd`, which writes the secret into a pipe the child inherits
at a fixed descriptor — never in `argv`, never in the environment, never on disk:

```sh
handvault exec qq-mail 2429936596@qq.com --fd 7 -- ./run-tests.sh
# inside the script:  read -r QPASS <&7   (or os.read(7, 4096))
```

### Probes

`put --imap/--smtp` and `probe` actually log in and report a verdict, so
"credentials stored" and "credentials work" stop being the same claim:

```console
$ handvault probe regrevia-mail yc@regrevia.com --imap imap.qiye.aliyun.com:993
IMAP OK (imap.qiye.aliyun.com:993, inbox 214)
```

Failures print the exception text, never the password.

## Security notes

What it does:

- Secret reaches the keychain through a **private pty**, not argv. `ps` never
  shows it, and neither does your shell history.
- Read-back verification after every write: a silent `security` failure is
  reported as `FAIL`, not as success.
- `~/.handvault` is `0700`; the ledger and status files are `0600`.
- The ledger records `timestamp`, `service`, `account`, `length`, `label` — no
  secrets, ever. Rotation shows up as a changed length.
- Core dumps are disabled for the process, so a crash can't leave plaintext in
  `/cores`.
- `--from-stdin` is refused unless `HANDVAULT_ALLOW_STDIN=1`; it exists for
  tests, not for real credentials.
- `HANDVAULT_SECURITY` (test hook) refuses a binary that isn't yours or is
  group/world-writable.
- Stale window shims are swept after 24 h; they contain service names only.

What it deliberately does *not* do: it is not a vault, it does not encrypt
anything itself, and it does not defend against a compromised local account.
The security boundary is your OS keychain and your user session — the same
boundary as `ssh-agent`. If an attacker already runs code as you, they can read
what you stored. `handvault` narrows *accidental* exposure (logs, transcripts,
history, screenshots); it is not a defence against a host that is already owned.

**Agents should treat `length=N` as the whole answer.** There is no flag that
produces plaintext without a tty for a reason.

## Library use

The pieces are importable if you want the same behaviour in your own tool:

```python
import handvault
b = handvault.backend()          # macOS keychain or libsecret
b.put('svc', 'acct', secret, 'label')
handvault.probe(secret, 'me@example.com', imap='imap.example.com:993')
```

## Tests

```sh
python3 -m unittest discover -s test -v
```

22 tests, all against a fake backend and a temporary state directory — the real
keychain and `~/.handvault` are never touched.

## License

MIT.
