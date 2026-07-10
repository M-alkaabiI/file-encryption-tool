"""
filecrypt_core.py - shared vault + envelope-encryption logic for filecrypt.

Used by both the CLI (filecrypt.py) and the GUI (filecrypt_gui.py).
See README.md for the full design rationale. Short version:

- Vault: scrypt-derived key from your master password, verified locally via
  an HMAC "verifier" hash (never the password or key itself) stored in
  ~/.filecrypt/vault.json.
- Files: envelope encryption. Each file gets its own random AES-256 key;
  that key is wrapped with the vault key; the file bytes are encrypted
  with AES-256-GCM under the file key.
"""

import hashlib
import hmac
import json
import os
import stat
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_DIR = Path.home() / ".filecrypt"
VAULT_FILE = VAULT_DIR / "vault.json"

MAGIC = b"FLC1"
KEY_LEN = 32
NONCE_LEN = 12
WRAPPED_KEY_LEN = KEY_LEN + 16

DEFAULT_KDF = {"n": 2 ** 15, "r": 8, "p": 1}


class FilecryptError(Exception):
    """Base error for all user-facing filecrypt failures."""


class WrongPassword(FilecryptError):
    pass


class NoVault(FilecryptError):
    pass


class CorruptFile(FilecryptError):
    pass


# --------------------------------------------------------------------------
# Vault
# --------------------------------------------------------------------------

def vault_exists() -> bool:
    return VAULT_FILE.exists()


def load_vault() -> dict:
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault(data: dict) -> None:
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(VAULT_DIR, stat.S_IRWXU)
    tmp = VAULT_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(VAULT_FILE)


def derive_vault_key(password: str, salt: bytes, kdf: dict) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=kdf["n"], r=kdf["r"], p=kdf["p"],
        dklen=KEY_LEN,
        maxmem=256 * 1024 * 1024,
    )


def verifier_for(vault_key: bytes) -> str:
    return hmac.new(vault_key, b"filecrypt-verify", hashlib.sha256).hexdigest()


def create_vault(password: str) -> None:
    salt = os.urandom(16)
    kdf = DEFAULT_KDF
    vault_key = derive_vault_key(password, salt, kdf)
    save_vault({
        "salt": salt.hex(),
        "kdf": kdf,
        "verifier": verifier_for(vault_key),
    })


def authenticate(password: str) -> bytes:
    """Return the vault key if password is correct, else raise WrongPassword."""
    if not vault_exists():
        raise NoVault("No vault found. Create one first.")
    vault = load_vault()
    salt = bytes.fromhex(vault["salt"])
    vault_key = derive_vault_key(password, salt, vault["kdf"])
    if not hmac.compare_digest(verifier_for(vault_key), vault["verifier"]):
        raise WrongPassword("Incorrect master password.")
    return vault_key


def rotate_password(old_password: str, new_password: str, rewrap_files=()) -> None:
    old_vault_key = authenticate(old_password)

    new_salt = os.urandom(16)
    kdf = DEFAULT_KDF
    new_vault_key = derive_vault_key(new_password, new_salt, kdf)

    for path in rewrap_files:
        rewrap_file_key(Path(path), old_vault_key, new_vault_key)

    save_vault({
        "salt": new_salt.hex(),
        "kdf": kdf,
        "verifier": verifier_for(new_vault_key),
    })


# --------------------------------------------------------------------------
# File envelope encryption
# --------------------------------------------------------------------------

def _read_header(f):
    magic = f.read(4)
    if magic != MAGIC:
        raise CorruptFile("Not a filecrypt (.enc) file, or it's corrupted.")
    wrap_nonce = f.read(NONCE_LEN)
    wrapped_key = f.read(WRAPPED_KEY_LEN)
    file_nonce = f.read(NONCE_LEN)
    if len(wrap_nonce) != NONCE_LEN or len(wrapped_key) != WRAPPED_KEY_LEN or len(file_nonce) != NONCE_LEN:
        raise CorruptFile("Truncated or corrupted filecrypt header.")
    return wrap_nonce, wrapped_key, file_nonce


def unwrap_file_key(vault_key: bytes, wrap_nonce: bytes, wrapped_key: bytes) -> bytes:
    try:
        return AESGCM(vault_key).decrypt(wrap_nonce, wrapped_key, None)
    except Exception as e:
        raise WrongPassword("Could not unwrap file key (wrong password or tampered file).") from e


def rewrap_file_key(enc_path: Path, old_vault_key: bytes, new_vault_key: bytes) -> None:
    with open(enc_path, "rb") as f:
        wrap_nonce, wrapped_key, file_nonce = _read_header(f)
        rest = f.read()

    file_key = unwrap_file_key(old_vault_key, wrap_nonce, wrapped_key)
    new_wrap_nonce = os.urandom(NONCE_LEN)
    new_wrapped_key = AESGCM(new_vault_key).encrypt(new_wrap_nonce, file_key, None)

    with open(enc_path, "wb") as f:
        f.write(MAGIC)
        f.write(new_wrap_nonce)
        f.write(new_wrapped_key)
        f.write(file_nonce)
        f.write(rest)


def encrypt_file(vault_key: bytes, src: Path, dest: Path = None, delete_original: bool = False) -> Path:
    src = Path(src)
    dest = Path(dest) if dest else src.with_suffix(src.suffix + ".enc")

    file_key = os.urandom(KEY_LEN)
    file_nonce = os.urandom(NONCE_LEN)
    wrap_nonce = os.urandom(NONCE_LEN)

    plaintext = src.read_bytes()
    ciphertext = AESGCM(file_key).encrypt(file_nonce, plaintext, None)
    wrapped_key = AESGCM(vault_key).encrypt(wrap_nonce, file_key, None)

    with open(dest, "wb") as f:
        f.write(MAGIC)
        f.write(wrap_nonce)
        f.write(wrapped_key)
        f.write(file_nonce)
        f.write(ciphertext)

    if delete_original:
        src.unlink()

    return dest


def decrypt_file(vault_key: bytes, src: Path, dest: Path = None, delete_original: bool = False) -> Path:
    src = Path(src)
    with open(src, "rb") as f:
        wrap_nonce, wrapped_key, file_nonce = _read_header(f)
        ciphertext = f.read()

    file_key = unwrap_file_key(vault_key, wrap_nonce, wrapped_key)
    try:
        plaintext = AESGCM(file_key).decrypt(file_nonce, ciphertext, None)
    except Exception as e:
        raise CorruptFile("Authentication failed: file is corrupted or was tampered with.") from e

    if dest is None:
        dest = src.with_suffix("") if src.suffix == ".enc" else src.with_suffix(src.suffix + ".dec")
    dest = Path(dest)
    dest.write_bytes(plaintext)

    if delete_original:
        src.unlink()

    return dest
