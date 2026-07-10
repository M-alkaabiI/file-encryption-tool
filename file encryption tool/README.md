# filecrypt

A local file-encryption tool with a built-in password-manager add-on.
Comes as three files:

- `filecrypt_core.py` — the vault + envelope-encryption logic (shared).
- `filecrypt.py` — command-line interface.
- `filecrypt_gui.py` — desktop GUI (Tkinter), built on the same core.

All three must sit in the same folder (the CLI and GUI both `import filecrypt_core`).

## Setup

```bash
pip install cryptography
```

Tkinter ships with most Python installs on Windows/macOS. On Linux, if
`filecrypt_gui.py` complains it's missing, install it via your package
manager, e.g. `sudo apt install python3-tk`.

First run (either interface) will offer to create the vault at
`~/.filecrypt/vault.json` (permissions locked to your user, `chmod 600`).
It does **not** store your password — it stores a salt, KDF parameters, and
a verifier hash. Every future run re-derives the key from what you type and
checks it against that hash.

## GUI

```bash
python3 filecrypt_gui.py
```

- **First run:** "Create Vault" screen — set your master password.
- **Every run after:** "Unlock" screen — type the password; it's hashed and
  checked against the stored verifier, exactly like the CLI. Three wrong
  guesses closes the app.
- **Main window:** buttons to encrypt/decrypt files (native file picker),
  a "Delete original after operation" checkbox, a change-password dialog
  (with optional re-keying of existing `.enc` files), and a "Lock" button.
- The unlocked key is held **only in memory** for as long as the window is
  open — clicking Lock or closing the app discards it immediately. It is
  never written to disk, so you're not retyping your password for every
  single file in one session, but nothing persists between sessions.

## CLI

```bash
python3 filecrypt.py init                            # first-time setup
python3 filecrypt.py encrypt report.pdf notes.txt     # -> report.pdf.enc, notes.txt.enc
python3 filecrypt.py decrypt report.pdf.enc           # -> report.pdf
python3 filecrypt.py status                           # vault info, no secrets
python3 filecrypt.py change-password --rewrap report.pdf.enc notes.txt.enc
```

Add `--delete-original` to `encrypt`/`decrypt` if you want the source file
removed once the operation succeeds.

## How the "password manager add-on" part works

1. `init` asks for a master password once.
2. We derive a **vault key** from it with `scrypt` (memory-hard, cost-tunable
   KDF) using a random 16-byte salt.
3. We compute `HMAC-SHA256(vault_key, "filecrypt-verify")` and store *that*
   as the verifier — the password and the vault key itself are never written
   to disk.
4. On every later `encrypt`/`decrypt`/`change-password` call, you type the
   password, we re-derive the vault key with the stored salt/params, and
   compare the resulting hash to the stored verifier with a
   constant-time comparison. Match → proceed. No match → reject, with a
   short delay and a 3-attempt cap to blunt casual brute-forcing.
5. Everything lives in `~/.filecrypt/` on this machine only — nothing is
   sent anywhere, and there's no recovery path if you forget the password
   and lose the vault file (by design — no backdoor means no backdoor for
   anyone else either).

## How the file encryption works (envelope encryption)

Each file gets its own random 256-bit **file key**, and the file's bytes are
encrypted with **AES-256-GCM** under that key (authenticated encryption —
tampering causes decryption to fail loudly instead of returning corrupted
plaintext).

The file key is then **wrapped** (encrypted) with the vault key, also via
AES-256-GCM, and stored in a small header at the top of the `.enc` file:

```
FLC1 | wrap_nonce (12B) | wrapped_file_key (48B) | file_nonce (12B) | ciphertext
```

Why not just derive one key straight from the password and use it everywhere?
Because then rotating your password would mean decrypting and re-encrypting
every file's full contents. With envelope encryption, `change-password
--rewrap` only has to re-wrap the small 32-byte file keys — the bulk
ciphertext never moves.

## Threat model / limitations (read before relying on this)

- This protects data at rest against someone who gets your files but not
  your master password. It does **not** protect against malware running as
  you while you have a session open, physical keyloggers, or someone editing
  `vault.json` directly (local root/admin access defeats any local tool).
- `scrypt` cost is set high enough to meaningfully slow offline guessing
  (~0.2–0.5s per attempt on typical hardware) but a weak/short password is
  still a weak password. Use a real passphrase.
- There's no password recovery. That's a deliberate tradeoff, not a bug.
