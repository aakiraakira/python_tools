#!/usr/bin/env python3
"""
password_encryptor.py

A super-advanced Python password encryptor with layered, memory-hard key derivation,
multiple symmetric ciphers, HMAC authentication, and seamless CLI for encryption/decryption.

Usage:
  # Encrypt a password
  python password_encryptor.py encrypt \
    --password "My$ecretP@ssw0rd!" \
    --output encrypted.json

  # Decrypt
  python password_encryptor.py decrypt \
    --input encrypted.json \
    --output decrypted.txt

Dependencies:
  pip install cryptography argon2_cffi
"""
import os, sys, json, base64, secrets, argparse
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# ----------------------------
# Core Crypto Parameters
# ----------------------------
ARGON2_TIME_COST    = 6       # iterations
ARGON2_MEMORY_COST  = 1 << 20 # 1 GiB
ARGON2_PARALLELISM  = 4       # parallel lanes
MASTER_KEY_LEN      = 32
HKDF_INFO           = b"password_encryptor_v1"
BACKEND             = default_backend()

# ----------------------------
# KDF: Argon2id -> HKDF
# ----------------------------
def derive_subkeys(passphrase: bytes, salt: bytes):
    # Raw Argon2id master key
    master_key = hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=MASTER_KEY_LEN,
        type=Type.ID
    )
    # Expand into three 32-byte subkeys: AES, ChaCha, HMAC
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=MASTER_KEY_LEN * 3,
        salt=None,
        info=HKDF_INFO,
        backend=BACKEND
    )
    key_material = hkdf.derive(master_key)
    return key_material[:32], key_material[32:64], key_material[64:]

# ----------------------------
# Encryption / Decryption
# ----------------------------
def encrypt_password(password: str) -> str:
    pwd_bytes = password.encode('utf-8')
    salt    = secrets.token_bytes(16)
    aes_key, chacha_key, hmac_key = derive_subkeys(pwd_bytes, salt)

    # First layer: AES-256-GCM
    aes_nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    ct1 = aesgcm.encrypt(aes_nonce, pwd_bytes, None)

    # Second layer: ChaCha20-Poly1305
    cha_nonce = secrets.token_bytes(12)
    chacha = ChaCha20Poly1305(chacha_key)
    ct2 = chacha.encrypt(cha_nonce, ct1, None)

    # HMAC-SHA512 over header+ct
    hdr = salt + aes_nonce + cha_nonce
    h = hmac.HMAC(hmac_key, hashes.SHA512(), backend=BACKEND)
    h.update(hdr + ct2)
    tag = h.finalize()

    envelope = {
        'salt'       : base64.b64encode(salt).decode(),
        'aes_nonce'  : base64.b64encode(aes_nonce).decode(),
        'cha_nonce'  : base64.b64encode(cha_nonce).decode(),
        'hmac_tag'   : base64.b64encode(tag).decode(),
        'ciphertext' : base64.b64encode(ct2).decode()
    }
    return json.dumps(envelope, indent=2)


def decrypt_password(envelope_json: str) -> str:
    env = json.loads(envelope_json)
    salt      = base64.b64decode(env['salt'])
    aes_nonce = base64.b64decode(env['aes_nonce'])
    cha_nonce = base64.b64decode(env['cha_nonce'])
    tag       = base64.b64decode(env['hmac_tag'])
    ct2       = base64.b64decode(env['ciphertext'])

    # Derive subkeys (passphrase is unknown here; we re-derive with password?)
    # Instead, we require the user-supplied passphrase as same password to decrypt
    print("Enter passphrase to derive keys:", file=sys.stderr)
    passphrase = sys.stdin.readline().rstrip('\n').encode('utf-8')
    aes_key, chacha_key, hmac_key = derive_subkeys(passphrase, salt)

    # Verify HMAC
    hdr = salt + aes_nonce + cha_nonce
    h = hmac.HMAC(hmac_key, hashes.SHA512(), backend=BACKEND)
    h.update(hdr + ct2)
    h.verify(tag)

    # Decrypt second layer
    chacha = ChaCha20Poly1305(chacha_key)
    ct1 = chacha.decrypt(cha_nonce, ct2, None)

    # Decrypt first layer
    aesgcm = AESGCM(aes_key)
    pwd_bytes = aesgcm.decrypt(aes_nonce, ct1, None)

    return pwd_bytes.decode('utf-8')

# ----------------------------
# CLI Interface
# ----------------------------
def main():
    p = argparse.ArgumentParser(description="Super-Advanced Password Encryptor")
    sub = p.add_subparsers(dest='cmd', required=True)
    enc = sub.add_parser('encrypt')
    enc.add_argument('--password', '-p', required=True, help='Password to encrypt')
    enc.add_argument('--output', '-o', help='Output file (JSON)')

    dec = sub.add_parser('decrypt')
    dec.add_argument('--input', '-i', required=True, help='Input encrypted JSON file')
    dec.add_argument('--output', '-o', help='Output file for decrypted password')

    args = p.parse_args()

    if args.cmd == 'encrypt':
        env_json = encrypt_password(args.password)
        if args.output:
            open(args.output,'w').write(env_json)
            print(f"Encrypted data written to {args.output}")
        else:
            print(env_json)

    elif args.cmd == 'decrypt':
        env_json = open(args.input,'r').read()
        try:
            pwd = decrypt_password(env_json)
            if args.output:
                open(args.output,'w').write(pwd)
                print(f"Decrypted password written to {args.output}")
            else:
                print(pwd)
        except Exception as e:
            print(f"Decryption failed: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == '__main__':
    main()
