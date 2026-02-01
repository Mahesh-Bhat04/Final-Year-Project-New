"""
Phase 1: DID and Verifiable Credentials (VC) for decentralized device identity.
- Device: keypair (pk_i, sk_i), did_i = HASH(pk_i)
- Validator: signs VC_i = {did_i, attributes}, vc_hash = HASH(VC_i)
Uses ECDSA (ecdsa library) for signing; SHA-256 for hashes and DID.
"""

import hashlib
import json
import time
import base64

try:
    import ecdsa
    from ecdsa import SigningKey, VerifyingKey, BadSignatureError
    ECDSA_AVAILABLE = True
except ImportError:
    ECDSA_AVAILABLE = False

# DID prefix for STarEdgeChain
DID_PREFIX = "did:staredge:"


def generate_device_keypair():
    """Generate ECDSA keypair for an IoT device. Returns (private_key, public_key) as bytes."""
    if not ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa package required. Install with: pip install ecdsa")
    sk = SigningKey.generate(curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return sk.to_string(), vk.to_string()


def did_from_public_key(public_key_bytes):
    """
    Compute DID from device public key: did_i = HASH(pk_i).
    Returns DID string: did:staredge:<hex(sha256(pk))>.
    """
    h = hashlib.sha256(public_key_bytes).hexdigest()
    return DID_PREFIX + h


def public_key_from_private(sk_bytes):
    """Recover public key bytes from private key bytes."""
    if not ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa package required")
    sk = SigningKey.from_string(sk_bytes, curve=ecdsa.SECP256k1)
    return sk.get_verifying_key().to_string()


def generate_validator_keypair():
    """Generate ECDSA keypair for the Validator. Returns (private_key, public_key) as bytes."""
    return generate_device_keypair()


def save_keypair_to_files(sk_bytes, pk_bytes, sk_path="device_sk.txt", pk_path="device_pk.txt"):
    """Save keypair as base64-encoded strings to files."""
    sk_b64 = base64.b64encode(sk_bytes).decode("ascii")
    pk_b64 = base64.b64encode(pk_bytes).decode("ascii")
    with open(sk_path, "w") as f:
        f.write(sk_b64)
    with open(pk_path, "w") as f:
        f.write(pk_b64)


def load_keypair_from_files(sk_path="device_sk.txt", pk_path="device_pk.txt"):
    """Load keypair from base64 files. Returns (sk_bytes, pk_bytes)."""
    with open(sk_path, "r") as f:
        sk_bytes = base64.b64decode(f.read().strip())
    with open(pk_path, "r") as f:
        pk_bytes = base64.b64decode(f.read().strip())
    return sk_bytes, pk_bytes


def load_validator_keys(validator_sk_path="validator_sk.txt", validator_pk_path="validator_pk.txt"):
    """Load Validator keypair from files. Returns (sk_bytes, pk_bytes)."""
    return load_keypair_from_files(validator_sk_path, validator_pk_path)


def save_validator_keys(sk_bytes, pk_bytes, sk_path="validator_sk.txt", pk_path="validator_pk.txt"):
    """Save Validator keypair to files."""
    save_keypair_to_files(sk_bytes, pk_bytes, sk_path, pk_path)


# --- VC: create, sign, verify, hash ---


def vc_create(did_i, attributes=None):
    """Build VC payload (unsigned): {did_i, attributes, timestamp}."""
    if attributes is None:
        attributes = []
    return {
        "did": did_i,
        "attributes": list(attributes),
        "timestamp": time.time(),
    }


def vc_sign(validator_sk_bytes, vc_payload):
    """
    Sign VC payload with Validator's private key.
    Returns signed VC dict: {..., "signature": base64_signature}.
    """
    if not ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa package required")
    # Canonical JSON for deterministic signature
    payload_str = json.dumps(vc_payload, sort_keys=True)
    sk = SigningKey.from_string(validator_sk_bytes, curve=ecdsa.SECP256k1)
    sig = sk.sign(payload_str.encode("utf-8"))
    vc_signed = dict(vc_payload)
    vc_signed["signature"] = base64.b64encode(sig).decode("ascii")
    return vc_signed


def vc_verify(validator_pk_bytes, vc_signed):
    """
    Verify VC signature. vc_signed must include "signature" key.
    Returns True if valid.
    """
    if not ECDSA_AVAILABLE:
        raise RuntimeError("ecdsa package required")
    sig_b64 = vc_signed.get("signature")
    if not sig_b64:
        return False
    sig = base64.b64decode(sig_b64)
    vc_copy = {k: v for k, v in vc_signed.items() if k != "signature"}
    payload_str = json.dumps(vc_copy, sort_keys=True)
    vk = VerifyingKey.from_string(validator_pk_bytes, curve=ecdsa.SECP256k1)
    try:
        vk.verify(sig, payload_str.encode("utf-8"))
        return True
    except BadSignatureError:
        return False


def vc_hash(vc_signed):
    """Compute vc_hash = HASH(VC_i) for anchoring. Uses canonical JSON."""
    payload_str = json.dumps(vc_signed, sort_keys=True)
    return hashlib.sha256(payload_str.encode("utf-8")).hexdigest()


def vc_serialize(vc_signed):
    """Serialize signed VC to JSON string (for storage/transport)."""
    return json.dumps(vc_signed, sort_keys=True)


def vc_deserialize(vc_str):
    """Deserialize VC from JSON string."""
    return json.loads(vc_str)
