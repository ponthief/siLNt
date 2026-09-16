"""BitMail display-address helpers.

Pure functions, stdlib only — no FastAPI, no LNbits, no DB — so they can be
tested directly (see _bitmail_repoint_check.py).

Background: a BitMail has two representations and only one of them follows a
domain move.

* DERIVED. The tamper sweep composes `final_username@<current configured
  domain>` on every run, so it starts checking the new domain the moment
  SILNT_BITMAIL_DOMAIN changes.
* STORED. What the apps display is a snapshot written once, when the BitMail was
  issued: `hr_address = f"{username}@{domain}"` in bip353_cloudflare.py, saved
  to wallets.hr_address for a wallet's base address or
  wallet_addresses.hr_address for a labeled one. Nothing rewrites it.

So after moving the DNS record to a new domain, the sweep is happy and the user
still sees the old address. `plan_repoint` decides whether a stored value is
stale, and which column holds it.
"""

from typing import NamedTuple, Optional


class Repoint(NamedTuple):
    """What to do about one issued BitMail's stored display address."""

    needed: bool
    address_id: Optional[str]  # None => wallets.hr_address; else wallet_addresses
    stored: str                # the stale value, for the log line
    derived: str               # what it should become


def plan_repoint(row: dict, derived: str) -> Repoint:
    """Decide whether `row`'s stored display address should become `derived`.

    `row` is a list_approved_bitmails() row: address_id, label_hr, wallet_hr.
    `derived` is final_username@<current configured domain>.

    The caller must only ask once it has PROVEN the derived address resolves via
    DNS to the SP address siLNt issued this BitMail for. This function does not
    and cannot check that; it only compares strings and picks the column.

    Returns needed=False when:
      * there is no stored value at all (nothing is being displayed to repair),
      * the stored value already equals the derived one (idempotent no-op),
      * `derived` is empty or has no domain part (never write a broken address).

    The comparison is case-insensitive because a domain is, but the value
    written is `derived` exactly as composed, so the stored form stays
    consistent with what a fresh issue would produce.
    """
    derived = (derived or "").strip()
    # Guard: never overwrite a real address with something malformed. A domain
    # move gone wrong should leave the old value visible, not blank it.
    if "@" not in derived or derived.startswith("@") or derived.endswith("@"):
        return Repoint(False, None, "", derived)

    address_id = (row.get("address_id") or "").strip() or None
    # Read the column that actually holds this BitMail's value. A labeled row
    # must not fall back to the wallet's: they are different addresses, and
    # treating the wallet's as the label's would rewrite the wrong record.
    stored = ((row.get("label_hr") if address_id else row.get("wallet_hr")) or "").strip()

    if not stored or stored.lower() == derived.lower():
        return Repoint(False, address_id, stored, derived)
    return Repoint(True, address_id, stored, derived)
