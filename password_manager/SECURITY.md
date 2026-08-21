# Security design and threat model

This document states exactly what pwman protects, how, and where it stops.
"Secure" without a threat model is marketing, so the limits are listed as
prominently as the guarantees.

## 1. What it defends against

* **Theft of the vault file.** A stolen `.pmv` (laptop, backup drive, cloud
  sync, discarded disk) is useless without the master password. Everything
  except the header is encrypted; the header contains no secret material.
* **Tampering with the vault file.** Every byte an attacker could change is
  covered by an AEAD tag or by the associated data. Modified files fail to
  open — they do not open with altered content.
* **Downgrade attacks.** The KDF choice and its cost parameters are
  authenticated, so an attacker cannot rewrite the header to make key
  derivation cheap and then hand you back "your" vault.
* **Offline brute force.** Key derivation is Argon2id, memory-hard and
  calibrated to about 0.75 s on the machine that created the vault. Guessing
  rates drop from billions per second (a fast hash) to a few thousand per
  second per GPU.
* **Other local users.** The vault, its backup and any export are created with
  mode `0600` inside a `0700` directory, and pwman warns if it finds otherwise.
* **Shoulder-surfing and log leakage.** No secret is ever printed unless you
  ask with `--show`, passed as a command line argument, or written to a log.
* **Clipboard residue.** Copied passwords are wiped after a timeout, and only
  if the clipboard still holds the value pwman put there.
* **Silent overwrite by a second session.** Saving verifies that the file on
  disk is still the one that was unlocked.

## 2. What it does **not** defend against

* **A compromised machine.** Malware, a keylogger, a malicious shell alias, a
  hostile root user, or a debugger attached to the process can read your master
  password as you type it and the entries after unlocking. No password manager
  solves this; pwman does not pretend to.
* **Memory disclosure.** Key material lives in `bytearray`s that are zeroed
  after use, but decrypted entries are Python `str` objects: immutable,
  possibly interned, and freely copied by the interpreter and garbage
  collector. A core dump, a swap file or hibernation image can contain them.
  Use an encrypted swap partition and disable core dumps if this matters.
* **Rubber-hose and coercion.** There is no hidden second vault, no plausible
  deniability, and no duress password.
* **Forgetting the master password.** There is no recovery, no reset, and no
  escrow. That is the point.
* **A copy an attacker already made.** Changing the master password re-wraps
  *your* file; it does nothing to a copy the attacker took earlier. If you
  suspect the vault leaked, rotate the passwords **inside** it, at the sites
  they belong to.
* **Weak master passwords.** Argon2id multiplies the attacker's cost; it does
  not create entropy. `pwman gen --passphrase` exists for exactly this.
* **Metadata.** The header reveals that the file is a pwman vault, the cipher,
  the KDF parameters, and the salts. The payload is padded to 4 KiB blocks — about a
  dozen entries each — so the file size only reveals which bucket you are in,
  never the exact count. File timestamps are visible to the filesystem; all per-entry
  timestamps live inside the ciphertext.

## 3. Cryptography

```
master password
      |  Argon2id (default m=64 MiB, t=3, p=4, 16 byte salt)   [scrypt N=2^17, r=8, p=1 fallback]
      v
   KEK  ──HKDF-SHA256(salt = random 32 B per save, info="pwman/v1/wrap")──> wrap key
                                                                                 |
                                             AEAD(wrap key, nonce, vault key, AAD = header)
                                                                                 v
                                                                        random 256-bit vault key
      ──HKDF-SHA256(salt = random 32 B per save, info="pwman/v1/body")──> body key
                                                                                 |
                                            AEAD(body key, nonce, padded entries, AAD = header ‖ wrap)
```

* **AEAD:** AES-256-GCM by default (hardware accelerated nearly everywhere),
  ChaCha20-Poly1305 selectable at `init` for CPUs without AES-NI. Both provide
  confidentiality *and* integrity; neither is used in a mode where a truncated
  or reordered file could pass.
* **Nonces:** 96-bit, random per encryption. Because a fresh HKDF salt is drawn
  on every save, the AEAD key is different every time — so even a hypothetical
  nonce collision would not be a key/nonce reuse, the one failure mode that
  breaks GCM and Poly1305 catastrophically.
* **Two-key envelope:** the content is encrypted under a random vault key that
  is itself wrapped by the password-derived key. Changing the master password
  re-wraps that key instead of re-encrypting the content, and the design leaves
  room for additional wrappings (a key file, a second password) later.
* **Associated data:** the body's AAD covers the header *and* the wrap block, so
  a wrap and a body from different files cannot be combined.
* **Parameter floors:** parameters below the OWASP minimums (Argon2id 19 MiB /
  t=2 / p=1, scrypt N=2^15 / r=8) are rejected when creating a vault and
  reported as warnings when opening one.
* **Randomness:** `os.urandom` / `secrets` only — the OS CSPRNG. No seeding, no
  PRNG of our own, and `secrets.choice` for every generated character (uniform,
  no modulo bias).
* **No home-grown primitives.** Argon2id comes from `argon2-cffi` (or
  `cryptography` ≥ 44), scrypt from `hashlib`/OpenSSL, AEAD and HKDF from
  `cryptography`. This project only wires them together.

### File format (`format: 1`)

```json
{
  "magic":  "PWMANVLT",
  "format": 1,
  "cipher": "AES-256-GCM",
  "kdf":    {"algo": "argon2id", "salt": "<b64>", "memory_kib": 65536, "time_cost": 3, "parallelism": 4},
  "wrap":   {"salt": "<b64 32>", "nonce": "<b64 12>", "ct": "<b64>"},
  "body":   {"salt": "<b64 32>", "nonce": "<b64 12>", "ct": "<b64>"}
}
```

The plaintext body is `uint32 length ‖ JSON ‖ zero padding` to a 4 KiB multiple.
JSON was chosen so a vault survives copying between systems, can be inspected
without special tools, and gains a version number that refuses to guess at
future formats.

## 4. Operational choices

* **No secrets in `argv`.** `/proc/<pid>/cmdline` is world-readable on Linux and
  arguments land in shell history. Secrets are prompted for via `/dev/tty` with
  echo off, or read from stdin when explicitly requested. There is no
  `--password VALUE` option anywhere, and a test enforces that.
* **No agent, no daemon, no key on disk.** `pwman shell` keeps the keys in one
  foreground process with an idle auto-lock; when it exits, keys are wiped and
  the clipboard is cleared.
* **Clipboard by default, printing on request.** The clipboard is a shared,
  unauthenticated channel, so the copy is temporary and self-cleaning; the
  helper receives the secret on stdin, never as an argument.
* **Atomic writes.** Write to a `0600` temp file in the same directory, `fsync`,
  `os.replace`, then `fsync` the directory. A crash leaves either the old or the
  new vault, never a truncated one. The previous version stays as `.pmv.bak` —
  note that after `pwman passwd` that backup still opens with the **old** master
  password, so delete it once you are sure.
* **Failures are indistinguishable.** A wrong password and a modified file
  produce the same error. An attacker who can corrupt your file learns nothing
  about which passwords were tried.
* **No lock files.** Instead of a lock that can be left behind by a crash,
  saving checks that the file's identity (inode, size, mtime) is unchanged since
  unlocking, and refuses rather than clobber a parallel session's work.

## 5. TOTP: a deliberate compromise

Storing TOTP seeds next to passwords means one stolen, unlocked vault yields
both factors — that weakens the "something you have" property. It is offered
anyway because the realistic alternative is people not using 2FA at all. If a
site protects something critical, keep its seed on a separate device.

## 6. The strength estimator is a heuristic

`pwman audit` prices a password by the cheapest of several attacker strategies
(character search, dictionary segmentation over ~2300 words, a list of the most
common passwords, repeated blocks). It is guidance, not a proof: a real attacker
has a far larger dictionary and knows more patterns. Entropy of *generated*
secrets, by contrast, is exact — it comes from the generator's own distribution,
including the small cost of the "must contain each class" rule.

## 7. Verifying the claims

```bash
python3 -m pytest                     # tamper, downgrade, swap, permission and wipe tests
python3 -m json.tool ~/.local/share/pwman/vault.pmv   # inspect the header; find no plaintext
pwman info                            # cipher and real KDF parameters of your vault
```

## 8. Reporting a problem

Open an issue describing the impact and how to reproduce it. Please do not
include vault files, master passwords, or real credentials in a bug report.
