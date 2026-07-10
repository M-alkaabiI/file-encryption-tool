#!/usr/bin/env python3
"""
filecrypt.py - command-line interface. See README.md for design details.
Shares its vault + encryption logic with filecrypt_gui.py via filecrypt_core.py.
"""

import argparse
import getpass
import sys
import time
from pathlib import Path

import filecrypt_core as core


def _authenticate(prompt="Master password: ") -> bytes:
    if not core.vault_exists():
        print("No vault found. Run `filecrypt.py init` first.")
        sys.exit(1)

    attempts = 3
    while attempts:
        pw = getpass.getpass(prompt)
        try:
            return core.authenticate(pw)
        except core.WrongPassword:
            attempts -= 1
            print(f"Incorrect password.{f' {attempts} attempt(s) left.' if attempts else ''}")
            time.sleep(1.0)

    print("Too many failed attempts.")
    sys.exit(1)


def cmd_init(args):
    if core.vault_exists() and not args.force:
        print(f"Vault already exists at {core.VAULT_FILE}. Use --force to overwrite "
              f"(this makes existing .enc files unreadable unless you know the old password).")
        return 1
    pw1 = getpass.getpass("Set master password: ")
    pw2 = getpass.getpass("Confirm master password: ")
    if pw1 != pw2:
        print("Passwords did not match.")
        return 1
    if len(pw1) < 8:
        print("Choose at least 8 characters.")
        return 1
    core.create_vault(pw1)
    print(f"Vault created at {core.VAULT_FILE} (permissions locked to your user only).")
    return 0


def cmd_status(args):
    if not core.vault_exists():
        print("No vault initialized. Run `filecrypt.py init`.")
        return 1
    vault = core.load_vault()
    print(f"Vault file : {core.VAULT_FILE}")
    print(f"KDF        : scrypt n={vault['kdf']['n']} r={vault['kdf']['r']} p={vault['kdf']['p']}")
    print("Password   : not stored (only a verifier hash is kept)")
    return 0


def cmd_change_password(args):
    old_pw = getpass.getpass("Current master password: ")
    try:
        core.authenticate(old_pw)
    except core.WrongPassword:
        print("Incorrect password.")
        return 1
    except core.NoVault:
        print("No vault found. Run `filecrypt.py init` first.")
        return 1

    pw1 = getpass.getpass("New master password: ")
    pw2 = getpass.getpass("Confirm new master password: ")
    if pw1 != pw2:
        print("Passwords did not match.")
        return 1

    core.rotate_password(old_pw, pw1, rewrap_files=args.rewrap or [])
    print("Master password changed.")
    if not args.rewrap:
        print("Note: pass --rewrap file1.enc file2.enc ... to re-key existing "
              "encrypted files under the new password.")
    return 0


def cmd_encrypt(args):
    vault_key = _authenticate()
    for src in args.files:
        src = Path(src)
        if not src.is_file():
            print(f"Skipping {src}: not a file.")
            continue
        dest = core.encrypt_file(vault_key, src, delete_original=args.delete_original)
        print(f"Encrypted -> {dest}")
    return 0


def cmd_decrypt(args):
    vault_key = _authenticate()
    for src in args.files:
        src = Path(src)
        if not src.is_file():
            print(f"Skipping {src}: not a file.")
            continue
        try:
            dest = core.decrypt_file(vault_key, src, dest=args.output, delete_original=args.delete_original)
        except core.FilecryptError as e:
            print(f"Failed to decrypt {src}: {e}")
            continue
        print(f"Decrypted -> {dest}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="filecrypt.py",
        description="Local file encryption with a built-in password-manager add-on.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create the local password vault (first-time setup).")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_status = sub.add_parser("status", help="Show vault info (no secrets).")
    p_status.set_defaults(func=cmd_status)

    p_change = sub.add_parser("change-password", help="Rotate the master password.")
    p_change.add_argument("--rewrap", nargs="*", default=[])
    p_change.set_defaults(func=cmd_change_password)

    p_enc = sub.add_parser("encrypt", help="Encrypt one or more files.")
    p_enc.add_argument("files", nargs="+")
    p_enc.add_argument("--delete-original", action="store_true")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt one or more .enc files.")
    p_dec.add_argument("files", nargs="+")
    p_dec.add_argument("--output")
    p_dec.add_argument("--delete-original", action="store_true")
    p_dec.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
