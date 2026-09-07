#!/usr/bin/env python3
"""
Standalone check for the registration-token change. No pytest, no DB, no LNbits.

The claim this rests on is narrow and testable: a bcrypt hash computed when
registration STARTS still authenticates the user when the account is created an
hour later, because LNbits binds the hash to nothing but its own random salt.
If that were false — if the hash were salted with the account id, say — moving
the hashing earlier would lock every new user out of their account, and it would
not be obvious from reading the diff.

Also checks that a token no longer carries anything password-shaped.

Run: python3 helpers/_verification_check.py
"""

import base64
import json
import time
import sys

import bcrypt

failures = 0


def check(name, cond, detail=""):
    global failures
    if cond:
        print(f"  ok   {name}")
    else:
        failures += 1
        print(f"  FAIL {name}{': ' + detail if detail else ''}")


# ── Stand-ins for the LNbits methods, copied from lnbits/core/models/users.py ─
# Account.hash_password / Account.verify_password verbatim in substance. If
# LNbits ever salts with the id, these stop matching the real thing and the
# assumption below needs re-checking against upstream.
def lnbits_hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_pw = bcrypt.hashpw(password.encode(), salt)
    if not hashed_pw:
        raise ValueError("Password hashing failed.")
    return hashed_pw.decode()


def lnbits_verify_password(password_hash: str, password: str) -> bool:
    if not password_hash:
        return False
    return bcrypt.checkpw(password.encode(), password_hash.encode())


print("the assumption: a hash made early still verifies later")
PW = "correct horse battery staple"

# Hashed at registration start, by a request that knows no account id...
hash_at_start = lnbits_hash_password(PW)
# ...and checked after the account was created with a different id entirely.
check("the right password verifies against the early hash",
      lnbits_verify_password(hash_at_start, PW))
check("a wrong password does not",
      not lnbits_verify_password(hash_at_start, PW + "!"))
check("an empty password does not",
      not lnbits_verify_password(hash_at_start, ""))

# The property that makes this safe, stated directly: two hashes of the same
# password differ (random salt) and each verifies. Nothing is derived from an
# account id, so no id needs to be known in advance.
h1 = lnbits_hash_password(PW)
h2 = lnbits_hash_password(PW)
check("two hashes of one password differ (random salt)", h1 != h2)
check("both verify", lnbits_verify_password(h1, PW) and lnbits_verify_password(h2, PW))

# A hash is self-contained: the salt travels inside it, which is why carrying it
# in a token and assigning it to a fresh Account works.
check("the bcrypt hash carries its own salt",
      hash_at_start.startswith("$2b$") and len(hash_at_start) == 60,
      hash_at_start)

print("\nthe 72-byte limit, now enforced before the email is sent")
try:
    lnbits_hash_password("x" * 73)
    check("bcrypt rejects >72 bytes", False, "it accepted 73")
except ValueError:
    check("bcrypt rejects >72 bytes", True)
check("72 bytes is fine", bool(lnbits_hash_password("x" * 72)))
# A multi-byte password can exceed 72 BYTES at far fewer characters, which is
# why start_registration measures the encoded length rather than len().
long_utf8 = "é" * 40  # 80 bytes
check("a 40-char multi-byte password is over the byte limit",
      len(long_utf8.encode("utf-8")) > 72 and len(long_utf8) <= 72)


print("\nthe token no longer carries a password")


# Mirrors _generate_verification_token's payload, minus the LNbits encryption
# (encrypt_internal_message needs a running LNbits). The point being checked is
# the payload's SHAPE, which is where the raw password used to sit.
def payload_for(username, email, password_hash):
    return {
        "kind": "register",
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "ts": int(time.time()),
    }


tok = payload_for("alice", "a@example.com", hash_at_start)
blob = json.dumps(tok, separators=(",", ":"))

check("the payload has no 'password' key", "password" not in tok)
check("the payload has a 'password_hash' key", "password_hash" in tok)
check("the raw password does not appear anywhere in the token", PW not in blob)
# The stronger form: no substring of the password survives, so it cannot be
# recovered even partially by someone who decrypts the token.
check("no 8+ character run of the password survives",
      not any(PW[i:i + 8] in blob for i in range(len(PW) - 7)))
# And what IS in there is only useful for offline cracking, not for signing in
# as the user — a hash is not a credential LNbits accepts.
check("what remains is a bcrypt hash", blob.count("$2b$") == 1)

print(f"\n{failures} check(s) failed" if failures else "\nall checks passed")
sys.exit(1 if failures else 0)
