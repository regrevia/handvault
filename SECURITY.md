# Security

## Model

`handvault` is a **transport** between a human's keyboard and the OS keychain.
It is not a vault and it does not encrypt anything itself.

- macOS: `/usr/bin/security` (login keychain)
- Linux: `secret-tool` (libsecret, Secret Service)

Trust boundary: the OS keychain plus your logged-in user session — the same
boundary as `ssh-agent` or `git credential-osxkeychain`. Code running as you
can read what you stored. What `handvault` prevents is *accidental* exposure:
secrets in chat transcripts, model context, argv, shell history, logs, core
dumps and screenshots.

## Invariants

1. A secret never appears in `argv`.
2. A secret never appears in the agent-visible stdout of `put`; that is
   `length=N` only.
3. `get --show` requires a tty.
4. Nothing is written to disk except the OS keychain, plus a ledger of
   `timestamp / service / account / length / label` at mode `0600`.
5. `exec` hands the secret to one child process, never through a shell string.
   `--fd N` uses an inherited pipe; `--env NAME` uses one environment variable,
   which the same user can read back from `/proc` on Linux — documented, and the
   reason `--fd` exists.
6. Every write is read back and compared; a mismatch is reported as failure.

## Reporting

Open a private security advisory at
<https://github.com/regrevia/handvault/security/advisories/new>, or email
`yc@regrevia.com`. Please don't file a public issue for a live vulnerability.

Expect an acknowledgement within 72 hours. Supported versions: the latest
minor release.
