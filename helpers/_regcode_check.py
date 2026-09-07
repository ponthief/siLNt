#!/usr/bin/env python3
"""
Standalone check for the 6-digit registration code. No pytest, no DB, no LNbits.

A short code guarding account creation is only safe because of things that are
easy to get wrong and invisible in review: the attempt cap actually consuming
the row, the code being bound to its email, the comparison being constant-time,
and expiry being checked before the code is. Each is reproduced here against a
dict standing in for the table, mirroring crud.take_pending_registration.

Run: python3 helpers/_regcode_check.py
"""

import hashlib
import hmac
import secrets
import sys
import time

failures = 0


def check(name, cond, detail=""):
    global failures
    if cond:
        print(f"  ok   {name}")
    else:
        failures += 1
        print(f"  FAIL {name}{': ' + detail if detail else ''}")


# ── mirrors of the real thing ────────────────────────────────────────────────
SECRET = b"test-auth-secret-key"
TTL = 60 * 60
MAX_ATTEMPTS = 5
DIGITS = 6


def hash_registration_code(email: str, code: str) -> str:
    msg = f"register:{email.strip().lower()}:{code}".encode()
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()


def generate_code() -> str:
    return str(secrets.randbelow(10**DIGITS)).zfill(DIGITS)


def put(table, email, username, password_hash, code, now=None):
    email = email.strip().lower()
    table[email] = {
        "email": email,
        "username": username,
        "password_hash": password_hash,
        "code_hmac": hash_registration_code(email, code),
        "attempts": 0,
        "created_at": int(now if now is not None else time.time()),
    }


def take(table, email, code, now=None):
    now = int(now if now is not None else time.time())
    email = email.strip().lower()
    row = table.get(email)
    if not row:
        return None, "unknown"
    if now - int(row["created_at"]) > TTL:
        del table[email]
        return None, "expired"
    if not hmac.compare_digest(row["code_hmac"], hash_registration_code(email, code)):
        row["attempts"] += 1
        if row["attempts"] >= MAX_ATTEMPTS:
            del table[email]
        return None, "mismatch"
    del table[email]
    return (
        {
            "email": row["email"],
            "username": row["username"],
            "password_hash": row["password_hash"],
        },
        "",
    )


PH = "$2b$12$" + "x" * 53

print("the happy path")
t = {}
put(t, "Alice@Example.com ", "alice", PH, "123456")
# Stored under the normalised address, so a differently-cased retype finds it.
check("the row is keyed by the normalised email", list(t) == ["alice@example.com"])
row, reason = take(t, "  ALICE@example.COM ", "123456")
check("a differently-cased, padded retype still matches", row is not None and reason == "")
check("it returns the username", row and row["username"] == "alice")
check("it returns the password hash untouched", row and row["password_hash"] == PH)
check("the row is consumed", not t)

print("\nthe code is spent, so it cannot be replayed")
put(t, "a@x.y", "a", PH, "111111")
take(t, "a@x.y", "111111")
row, reason = take(t, "a@x.y", "111111")
check("a second use of a correct code fails", row is None and reason == "unknown")

print("\nthe attempt cap consumes the row")
put(t, "b@x.y", "b", PH, "222222")
reasons = [take(t, "b@x.y", "000000")[1] for _ in range(MAX_ATTEMPTS)]
check(f"{MAX_ATTEMPTS} wrong guesses all rejected", reasons.count("mismatch") == MAX_ATTEMPTS)
check("the row is gone after the cap", "b@x.y" not in t)
# The property that matters: the CORRECT code no longer works either, so
# grinding cannot be resumed by guessing right on attempt six.
row, reason = take(t, "b@x.y", "222222")
check("the correct code no longer works after the cap", row is None)

print("\nguessing is bounded, not merely slowed")
# 5 attempts against 10^6 codes. Stated as the actual number so a change to
# either constant shows up here as a number nobody would accept.
odds = MAX_ATTEMPTS / 10**DIGITS
check(f"chance of guessing within the cap is {odds:.7f}", odds < 1e-5, f"{odds}")

print("\nexpiry is checked before the code")
put(t, "c@x.y", "c", PH, "333333", now=time.time() - TTL - 1)
row, reason = take(t, "c@x.y", "333333")
check("an expired row is rejected even with the right code", row is None and reason == "expired")
check("and swept", "c@x.y" not in t)
# Ordering matters: were the code checked first, an expired row would burn
# attempts and report "mismatch", hiding why it failed.
put(t, "d@x.y", "d", PH, "444444", now=time.time() - TTL - 1)
_, reason = take(t, "d@x.y", "000000")
check("an expired row reports expiry, not mismatch", reason == "expired")

print("\nthe code is bound to its email")
put(t, "e@x.y", "e", PH, "555555")
put(t, "f@x.y", "f", PH, "555555")  # same digits, different address
row, _ = take(t, "e@x.y", "555555")
check("the same digits issued for two addresses are different secrets",
      hash_registration_code("e@x.y", "555555")
      != hash_registration_code("f@x.y", "555555"))
check("each still works for its own address", row is not None and take(t, "f@x.y", "555555")[0] is not None)

print("\nthe stored form is not the code")
put(t, "g@x.y", "g", PH, "654321")
stored = t["g@x.y"]["code_hmac"]
check("the digits do not appear in what is stored", "654321" not in stored)
check("what is stored is a sha256 hex digest", len(stored) == 64 and all(c in "0123456789abcdef" for c in stored))

print("\ngenerated codes")
codes = [generate_code() for _ in range(2000)]
check("every code is exactly 6 digits", all(len(c) == DIGITS and c.isdigit() for c in codes))
check("leading zeros are preserved", any(c[0] == "0" for c in codes))
check("the range is used, not a narrow slice", len(set(codes)) > 1800, f"{len(set(codes))} distinct")

print(f"\n{failures} check(s) failed" if failures else "\nall checks passed")
sys.exit(1 if failures else 0)
