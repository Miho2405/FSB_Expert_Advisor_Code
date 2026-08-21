# pwman

An offline, end-to-end encrypted password manager for the command line.

The whole vault is a single authenticated-encrypted file. There is no server, no
sync, no telemetry, and no network traffic at all unless you explicitly ask for
the breach check. Secrets never appear in `argv`, never in the shell history, and
never on stdout unless you pass `--show`.

```
$ pwman init
$ pwman add github --username me@example.com --url https://github.com --generate
$ pwman get github                 # password to the clipboard, wiped after 20 s
$ pwman audit                      # weak, reused, stale passwords
$ pwman shell                      # unlock once, auto-locks when idle
```

## How it protects the vault

| Layer | What is used | Why |
| --- | --- | --- |
| Master password → key | **Argon2id** (64 MiB, t=3, p=4 by default, auto-calibrated), scrypt fallback | memory-hard: GPUs and ASICs gain far less than against PBKDF2/bcrypt |
| Vault key | random 256-bit key, wrapped under the master key | the master password can be changed without re-encrypting content |
| Content | **AES-256-GCM** (or ChaCha20-Poly1305) with a per-save sub-key from HKDF-SHA256 | authenticated encryption; a fresh key per save makes nonce reuse impossible |
| Header | passed as AEAD associated data | the cipher, the KDF and its cost cannot be tampered with or downgraded |
| Payload | padded to 4 KiB blocks (~a dozen entries each) | the file size does not reveal how many entries you have |
| On disk | `0600`, written to a temp file, fsynced, atomically renamed, previous version kept as `.bak` | no half-written vault, no world-readable secrets |

Full design and threat model: [SECURITY.md](SECURITY.md).

## Install

```bash
cd password_manager
python3 -m pip install -e .[argon2]      # argon2-cffi is optional but recommended
pwman --help
```

Or run it straight from the source tree without installing:

```bash
python3 -m pip install -r requirements.txt
python3 -m pwman --help
```

Python 3.9+ is required (developed and tested on 3.11).

## Everyday use

```bash
pwman init                                   # create the vault, tune the KDF to ~0.75 s
pwman init --cipher ChaCha20-Poly1305        # for CPUs without AES-NI
pwman init --kdf scrypt                      # if you cannot install argon2-cffi

pwman add github -u me@example.com -g        # -g / --generate makes a 20 char password
pwman add mail --passphrase -w 6             # six words from the bundled 1024 word list
pwman add server --secret-stdin < secret.txt # for scripts; the file is your problem

pwman list                                   # names and usernames only
pwman list --long --tag dev                  # plus tags and password strength
pwman search github

pwman get github                             # copy the password, wipe it after 20 s
pwman get github --show                      # print it instead
pwman get github -f username                 # other fields: url, notes, totp
pwman get github -f totp                     # current 2FA code

pwman edit github --generate                 # rotate; the old password goes to history
pwman edit github --url https://github.com --tags dev work
pwman edit github --totp 'otpauth://totp/...?secret=...'
pwman rm github

pwman gen -n 5 -l 32                         # generate without opening the vault
pwman gen --passphrase -w 7 --readable

pwman audit                                  # weak / reused / stale / recycled
pwman audit --pwned                          # + Have I Been Pwned (k-anonymous)
pwman passwd                                 # change the master password
pwman info                                   # cipher, KDF parameters, file mode
```

`pwman shell` unlocks once and keeps the vault open in that one process, with an
idle auto-lock (default 300 s) and a clipboard wipe on exit:

```
pwman> list
pwman> get github
pwman> passwd github --generate
pwman> lock
```

Exit codes: `0` ok, `1` error, `2` usage, `3` wrong master password, `4` audit
findings (so `pwman audit` is usable in a cron job).

## Where the vault lives

`$PWMAN_VAULT`, else `$XDG_DATA_HOME/pwman/vault.pmv`, else
`~/.local/share/pwman/vault.pmv`. Override per command with `--vault`.

Back it up by copying that file: it is encrypted at rest, so a copy on a USB
stick or in cloud storage is as safe as your master password. Keep the master
password somewhere physical — **there is no recovery, no reset, and no backdoor**.

## Moving in and out

```bash
pwman import chrome-passwords.csv            # name/url/username/password columns
pwman import backup.json --replace
pwman export backup.json --insecure-plaintext   # writes clear text, 0600, on purpose
```

The export flag is deliberately ugly. To move a vault between machines, copy the
`.pmv` file instead — it stays encrypted the whole way.

## Scripting

Secrets are never command line arguments. For unattended use:

```bash
printf '%s\n' "$MASTER" | pwman --password-stdin list --json
printf '%s\n%s\n' "$MASTER" "$ENTRY_PW" | pwman --password-stdin add ci-token --secret-stdin
printf '%s\n%s\n' "$OLD" "$NEW" | pwman --password-stdin passwd
```

## Tests

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest            # 211 tests, ~6 s
```

The suite covers the crypto envelope (round trips, tamper detection on every
field, downgrade and cross-vault swap attempts), atomic writes and file modes,
generator uniformity and entropy accounting, RFC 6238 TOTP vectors, the
k-anonymity breach check (offline, with a stub), and the CLI end to end.

## Limitations worth knowing

pwman protects a file at rest. It cannot protect you from malware, a keylogger,
or someone reading your unlocked screen. Python also cannot reliably wipe
strings from memory. See [SECURITY.md](SECURITY.md) for the full, honest list.
