#!/usr/bin/env python3
"""
Phase 1 verification: DID & VC (device registration + on-chain anchor).

Run:
  1. Unit tests only (no servers):  python test_phase1.py
  2. With PC node running (port 5000):  python test_phase1.py --integration
  3. With PC + RPi (port 5001):  python test_phase1.py --integration --rpi

Success criteria:
  - Unit: DID generation, VC create/sign/verify, vc_hash consistent
  - Integration: POST /validator/register returns vc_i and vc_hash; chain contains device_registration anchor with same vc_hash
  - RPi: POST /device/register succeeds; GET /device/identity shows registered=True
"""

import os
import sys
import argparse
import requests

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from did_vc import (
    generate_device_keypair,
    did_from_public_key,
    generate_validator_keypair,
    vc_create,
    vc_sign,
    vc_verify,
    vc_hash,
    vc_serialize,
    vc_deserialize,
    load_validator_keys,
    save_validator_keys,
)


def test_did_generation():
    """Device keypair and DID derivation."""
    sk_b, pk_b = generate_device_keypair()
    did_i = did_from_public_key(pk_b)
    assert did_i.startswith("did:staredge:"), "DID should have prefix did:staredge:"
    assert len(did_i) == len("did:staredge:") + 64, "DID should be prefix + 64 hex (SHA-256)"
    return did_i, pk_b


def test_vc_lifecycle():
    """VC create, sign, verify, hash."""
    validator_sk, validator_pk = generate_validator_keypair()
    vc_payload = vc_create("did:staredge:abc123", ["ONE", "TWO"])
    vc_signed = vc_sign(validator_sk, vc_payload)
    assert vc_verify(validator_pk, vc_signed), "VC signature should verify"
    h = vc_hash(vc_signed)
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h), "vc_hash should be 64-char hex"
    return vc_signed, h, validator_pk


def test_vc_hash_deterministic():
    """Same signed VC produces same vc_hash when hashed twice (deterministic hashing)."""
    vc_signed, h1, _ = test_vc_lifecycle()
    h2 = vc_hash(vc_signed)
    assert h1 == h2, "Hashing same VC twice should give same vc_hash"


def test_vc_serialize_deserialize():
    """VC round-trip serialize/deserialize."""
    vc_signed, h, _ = test_vc_lifecycle()
    s = vc_serialize(vc_signed)
    vc_restored = vc_deserialize(s)
    assert vc_hash(vc_restored) == h, "Deserialized VC should have same vc_hash"


def run_unit_tests():
    """Run all unit tests; return True if all pass."""
    tests = [
        ("DID generation", test_did_generation),
        ("VC lifecycle (create/sign/verify/hash)", lambda: test_vc_lifecycle()),
        ("vc_hash deterministic", test_vc_hash_deterministic),
        ("VC serialize/deserialize", test_vc_serialize_deserialize),
    ]
    ok = True
    for name, fn in tests:
        try:
            fn()
            print("[PASS] " + name)
        except Exception as e:
            print("[FAIL] " + name + ": " + str(e))
            ok = False
    return ok


def run_integration_validator(base_url="http://127.0.0.1:5000"):
    """Test Validator: register a DID, then verify anchor on chain."""
    try:
        did_i, _ = test_did_generation()
        r = requests.post(
            base_url.rstrip("/") + "/validator/register",
            json={"did_i": did_i, "attributes": ["ONE", "TWO"]},
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if r.status_code != 201:
            print("[FAIL] Validator register: status " + str(r.status_code) + " " + r.text[:200])
            return False
        data = r.json()
        vc_hash_returned = data.get("vc_hash")
        if not vc_hash_returned:
            print("[FAIL] Validator register: no vc_hash in response")
            return False
        chain_r = requests.get(base_url.rstrip("/") + "/chain", timeout=5)
        if chain_r.status_code != 200:
            print("[FAIL] GET /chain: status " + str(chain_r.status_code))
            return False
        chain = chain_r.json().get("chain", [])
        found = False
        for block in reversed(chain):
            for tx in block.get("transactions", []):
                if tx.get("type") == "device_registration" and tx.get("vc_hash") == vc_hash_returned:
                    found = True
                    break
            if found:
                break
        if not found:
            print("[FAIL] Chain has no device_registration anchor with vc_hash " + vc_hash_returned[:16] + "...")
            return False
        print("[PASS] Validator register + anchor on chain (vc_hash " + vc_hash_returned[:16] + "...)")
        return True
    except requests.exceptions.ConnectionError:
        print("[SKIP] Validator integration: could not connect to " + base_url + " (is blockchain-PC running?)")
        return None
    except Exception as e:
        print("[FAIL] Validator integration: " + str(e))
        return False


def run_integration_rpi(base_url="http://127.0.0.1:5001"):
    """Test RPi: trigger registration, then check identity."""
    try:
        r = requests.post(
            base_url.rstrip("/") + "/device/register",
            json={"validator_url": "http://127.0.0.1:5000"},
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        if r.status_code not in (200, 201):
            print("[FAIL] RPi register: status " + str(r.status_code) + " " + (r.text or "")[:200])
            return False
        id_r = requests.get(base_url.rstrip("/") + "/device/identity", timeout=5)
        if id_r.status_code != 200:
            print("[FAIL] GET /device/identity: status " + str(id_r.status_code))
            return False
        data = id_r.json()
        if not data.get("registered"):
            print("[FAIL] RPi identity: registered=False after register")
            return False
        print("[PASS] RPi register + identity (did_i " + (data.get("did_i", "")[:24] or "") + "...)")
        return True
    except requests.exceptions.ConnectionError:
        print("[SKIP] RPi integration: could not connect to " + base_url + " (is RPi-server running?)")
        return None
    except Exception as e:
        print("[FAIL] RPi integration: " + str(e))
        return False


def main():
    parser = argparse.ArgumentParser(description="Phase 1: DID & VC verification")
    parser.add_argument("--integration", action="store_true", help="Run integration tests (PC on 5000)")
    parser.add_argument("--rpi", action="store_true", help="Run RPi integration (RPi on 5001)")
    parser.add_argument("--validator-url", default="http://127.0.0.1:5000", help="Validator base URL")
    parser.add_argument("--rpi-url", default="http://127.0.0.1:5001", help="RPi base URL")
    args = parser.parse_args()

    print("=== Phase 1: DID & VC (device registration) ===\n")
    unit_ok = run_unit_tests()
    print()
    if not unit_ok:
        print("Unit tests failed. Fix before running integration.")
        sys.exit(1)

    integration_ok = None
    rpi_ok = None
    if args.integration:
        integration_ok = run_integration_validator(args.validator_url)
        print()
        if args.rpi:
            rpi_ok = run_integration_rpi(args.rpi_url)
            print()

    print("--- Summary ---")
    print("Unit tests: PASSED" if unit_ok else "Unit tests: FAILED")
    if args.integration:
        if integration_ok is True:
            print("Validator + chain anchor: PASSED")
        elif integration_ok is False:
            print("Validator + chain anchor: FAILED")
        else:
            print("Validator + chain anchor: SKIPPED (server not reachable)")
        if args.rpi:
            if rpi_ok is True:
                print("RPi registration: PASSED")
            elif rpi_ok is False:
                print("RPi registration: FAILED")
            else:
                print("RPi registration: SKIPPED (RPi not reachable)")

    if unit_ok and (not args.integration or integration_ok is not False):
        print("\nPhase 1 implementation verification: SUCCESS")
        sys.exit(0)
    sys.exit(1)


if __name__ == "__main__":
    main()
