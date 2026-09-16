"""Checks for plan_repoint — the decision behind repairing a BitMail display
address after the instance's BitMail domain moves.

    python3 helpers/_bitmail_repoint_check.py

Stdlib only, no DB, no network: the same shape as the other _*_check.py scripts
in this folder.
"""

import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

from bitmail import plan_repoint  # noqa: E402

FAILED = []


def check(name, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'} {name}")
    if not ok:
        print(f"       got  {got}")
        print(f"       want {want}")
        FAILED.append(name)


print("A wallet's BASE address (address_id NULL) after the domain moved")
r = plan_repoint(
    {"address_id": None, "label_hr": None, "wallet_hr": "alice@thrilla.me"},
    "alice@whispawallet.com",
)
check("needs repoint", r.needed, True)
check("targets wallets.hr_address", r.address_id, None)
check("reports the stale value", r.stored, "alice@thrilla.me")
check("new value", r.derived, "alice@whispawallet.com")

print("\nA LABELED address — must rewrite wallet_addresses, not the wallet")
r = plan_repoint(
    {"address_id": "addr-7", "label_hr": "shop@thrilla.me", "wallet_hr": "alice@thrilla.me"},
    "shop@whispawallet.com",
)
check("needs repoint", r.needed, True)
check("targets the labeled row", r.address_id, "addr-7")
check("reads the label's own stored value", r.stored, "shop@thrilla.me")

print("\nA labeled row whose own hr_address is NULL must NOT inherit the wallet's")
r = plan_repoint(
    {"address_id": "addr-9", "label_hr": None, "wallet_hr": "alice@thrilla.me"},
    "bob@whispawallet.com",
)
check("no repoint (nothing displayed for it)", r.needed, False)
check("did not read the wallet's value", r.stored, "")

print("\nAlready correct — idempotent, so a repeated sweep does nothing")
r = plan_repoint(
    {"address_id": None, "label_hr": None, "wallet_hr": "alice@whispawallet.com"},
    "alice@whispawallet.com",
)
check("no repoint", r.needed, False)

print("\nCase differs only — a domain is case-insensitive, so no rewrite")
r = plan_repoint(
    {"address_id": None, "label_hr": None, "wallet_hr": "Alice@WhiSPaWallet.com"},
    "alice@whispawallet.com",
)
check("no repoint", r.needed, False)

print("\nNo stored value at all — nothing on screen to repair")
for stored in (None, "", "   "):
    r = plan_repoint({"address_id": None, "label_hr": None, "wallet_hr": stored}, "a@b.com")
    check(f"no repoint for {stored!r}", r.needed, False)

print("\nA malformed derived address must never overwrite a good stored one")
for bad in ("", "   ", "alice", "@whispawallet.com", "alice@", None):
    r = plan_repoint(
        {"address_id": None, "label_hr": None, "wallet_hr": "alice@thrilla.me"}, bad
    )
    check(f"refuses {bad!r}", r.needed, False)

print("\nWhitespace around the stored value is ignored, not treated as a change")
r = plan_repoint(
    {"address_id": None, "label_hr": None, "wallet_hr": "  alice@whispawallet.com  "},
    "alice@whispawallet.com",
)
check("no repoint", r.needed, False)

print()
if FAILED:
    print(f"{len(FAILED)} FAILED: {', '.join(FAILED)}")
    sys.exit(1)
print("all checks passed")
