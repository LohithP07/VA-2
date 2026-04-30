"""
Future-Ready Key Generator
--------------------------
Generates modern cryptographic key pairs for all issuers that don't yet
have key files on disk.

Features:
- Safe re-run (never overwrites existing keys)
- Supports RSA-3072 (future stronger than RSA-2048)
- Supports Ed25519 (modern fast signatures)
- Password-encrypted private keys (optional)
- Key rotation ready (versioned keys)
- Legacy compatibility files
- Metadata manifest for tracking keys

Usage:
    python -m backend.identity.keygen
"""

import os
import json
import datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519


# ====================================================== 
# CONFIG 
# ====================================================== 

KEY_DIR = Path(__file__).resolve().parent
KEY_VERSION = "v1"

# Choose: RSA or ED25519
DEFAULT_ALGO = "RSA"

# Optional password for private keys
PRIVATE_KEY_PASSWORD = None
# Example:
# PRIVATE_KEY_PASSWORD = b"MyStrongPassword123"

ISSUERS = {
    "mlritm": {},
    "external": {},
    "govt": {},
}


# ====================================================== 
# HELPERS 
# ====================================================== 

def now():
    return datetime.datetime.utcnow().isoformat() + "Z"

def private_encryption():
    if PRIVATE_KEY_PASSWORD:
        return serialization.BestAvailableEncryption(PRIVATE_KEY_PASSWORD)
    return serialization.NoEncryption()

def file_names(issuer, algo):
    base = f"{issuer}_{algo.lower()}_{KEY_VERSION}"
    return (
        KEY_DIR / f"{base}_private.pem",
        KEY_DIR / f"{base}_public.pem"
    )


# ====================================================== 
# KEY GENERATORS 
# ====================================================== 

def generate_rsa():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

def generate_ed25519():
    return ed25519.Ed25519PrivateKey.generate()

def generate_keypair(algo):
    if algo.upper() == "RSA":
        return generate_rsa()
    elif algo.upper() == "ED25519":
        return generate_ed25519()
    else:
        raise ValueError("Unsupported algorithm")


# ====================================================== 
# SAVE KEYS 
# ====================================================== 

def save_keys(private_key, private_path, public_path):
    if private_path.exists() and public_path.exists():
        print(f"[SKIP] {private_path.name} already exists")
        return False

    # Save private key
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=private_encryption()
        ))

    # Save public key
    with open(public_path, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"[OK] Generated {private_path.name}")
    print(f"[OK] Generated {public_path.name}")
    return True


# ====================================================== 
# METADATA 
# ====================================================== 
def update_manifest(issuer, algo, private_path, public_path):
    manifest = KEY_DIR / "key_manifest.json"

    data = {}
    if manifest.exists():
        with open(manifest, "r") as f:
            data = json.load(f)

    data[issuer] = {
        "algorithm": algo,
        "version": KEY_VERSION,
        "private_key": private_path.name,
        "public_key": public_path.name,
        "created_at": now()
    }

    with open(manifest, "w") as f:
        json.dump(data, f, indent=4)


# ====================================================== 
# LEGACY SUPPORT 
# ====================================================== 
def ensure_legacy_files():
    legacy_priv = KEY_DIR / "private_key.pem"
    legacy_pub = KEY_DIR / "public_key.pem"

    source_priv = KEY_DIR / f"mlritm_{DEFAULT_ALGO.lower()}_{KEY_VERSION}_private.pem"
    source_pub = KEY_DIR / f"mlritm_{DEFAULT_ALGO.lower()}_{KEY_VERSION}_public.pem"

    if source_priv.exists() and not legacy_priv.exists():
        legacy_priv.write_bytes(source_priv.read_bytes())

    if source_pub.exists() and not legacy_pub.exists():
        legacy_pub.write_bytes(source_pub.read_bytes())

    print("[OK] Legacy compatibility files ensured")


# ====================================================== 
# MAIN 
# ====================================================== 
def run():
    print("=" * 60)
    print("VERACITY AGENT – FUTURE READY KEY GENERATOR")
    print("=" * 60)

    for issuer in ISSUERS:
        print(f"\nIssuer: {issuer}")

        algo = DEFAULT_ALGO
        private_path, public_path = file_names(issuer, algo)

        private_key = generate_keypair(algo)

        created = save_keys(private_key, private_path, public_path)

        if created:
            update_manifest(issuer, algo, private_path, public_path)

    ensure_legacy_files()

    print("\n✓ All operations complete.\n")

if __name__ == "__main__":
    run()
