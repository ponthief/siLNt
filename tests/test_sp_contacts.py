"""The address book, and the one thing it could not tell you.

A saved SP address is frozen at the moment it was saved. The person it belongs
to can delete that wallet and make another, and nothing on either side says
so: the name in the sender's address book still looks right, the address is
still valid bech32, and a payment to it is simply gone — no bounce, no error,
no way back.

A BitMail contact does not have this problem. The name is resolved through DNS
at send time, so the recipient's own record decides where it goes.
"""

from __future__ import annotations

import ast
import re
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _fn(path: str, name: str) -> str:
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    ends = [i for i in (nxt, other) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


def test_the_list_says_whether_an_address_is_still_a_whispa_wallet():
    body = _fn("views_api.py", "api_sp_contacts_list")
    assert "sp_addresses_in_use(" in body
    assert '"whispa"' in body


def test_a_bitmail_contact_is_not_marked_either_way():
    """It is resolved at send time, so "verified" and "unverified" are both
    the wrong thing to say about it."""
    body = _fn("views_api.py", "api_sp_contacts_list")
    assert 'None if c.kind != "sp"' in body


def test_the_check_only_ever_sees_the_callers_own_contacts():
    """Answering "which WhiSPa account owns this address?" for arbitrary input
    would be an enumeration oracle. It is called with the values already in
    this user's address book, so it answers a question about their own data."""
    body = _fn("views_api.py", "api_sp_contacts_list")
    assert "{c.value for c in rows if c.kind == \"sp\"}" in body
    # And it is scoped to the network the listing was for.
    assert "sp_addresses_in_use(\n        {c.value for c in rows if c.kind == \"sp\"}, network\n    )" in body


def test_verification_is_against_wallets_that_exist_now():
    body = _fn("crud.py", "sp_addresses_in_use")
    assert "FROM silnt.wallets" in body
    assert "network = :net" in body
    # Case-insensitive both ways: bech32 is usually lowercase but nothing
    # guarantees what a user pasted.
    assert body.count(".lower()") >= 2


def test_a_labelled_sub_address_counts_as_a_whispa_wallet():
    """A BIP-352 label (m≥2) derives a DIFFERENT sp1… from the same seed, and
    it is the address a person hands out when they want the payment tagged —
    so a contact saved from one is the ordinary case, not an edge case.

    Checking only silnt.wallets, which holds the base m=0 address, reported
    every labelled sub-address as not belonging to a WhiSPa wallet: the exact
    false warning the feature exists to avoid.
    """
    body = _fn("crud.py", "sp_addresses_in_use")
    assert "silnt.wallet_addresses" in body
    # Scoped per network through the join, because wallet_addresses has no
    # network column of its own.
    assert "JOIN silnt.wallets w ON w.id = a.wallet_id" in body
    assert "WHERE w.network = :net" in body
    # Unioned, not replacing the base-address lookup.
    assert "have |=" in body


def test_the_sub_address_table_really_has_no_network_column():
    """The join above is load-bearing. If wallet_addresses ever gains a network
    column, the query should filter on it directly — and if this test starts
    failing, that is what happened."""
    src = (ROOT / "migrations.py").read_text()
    at = src.index("CREATE TABLE IF NOT EXISTS silnt.wallet_addresses")
    create = src[at:src.index(")", at)]
    assert "network" not in create, create
    alters = re.findall(
        r"ALTER TABLE silnt\.wallet_addresses[^\"']*", src
    )
    assert not any("network" in a for a in alters), alters


def test_a_contact_can_be_repointed_without_losing_its_name():
    body = _fn("crud.py", "update_sp_contact_value")
    assert "UPDATE silnt.sp_contacts SET kind = :k, value = :v" in body
    assert "value_sha256" in body, "the dedup tag has to move with the value"
    assert "id = :id AND user_id = :uid" in body, "a contact of someone else's"


def test_repointing_re_classifies_the_kind():
    """An SP contact edited into a BitMail name is a BitMail contact, and the
    verification above keys off `kind`."""
    assert "_classify_recipient(value)" in _fn("crud.py", "update_sp_contact_value")


def test_repointing_cannot_duplicate_another_contact():
    assert "Another contact already points at that recipient." in _fn(
        "crud.py", "update_sp_contact_value"
    )


def test_the_patch_endpoint_validates_the_new_value():
    """Create refuses anything that is not a BitMail name or an SP address;
    an edit that did not would be the way round it."""
    body = _fn("views_api.py", "api_sp_contacts_update")
    assert 'startswith("sp1")' in body and 'startswith("tsp1")' in body
    assert "Invalid BitMail name." in body


def test_the_update_model_takes_either_field():
    tree = ast.parse((ROOT / "models.py").read_text())
    cls = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "UpdateSpContactData"
    )
    fields = {n.target.id for n in cls.body if isinstance(n, ast.AnnAssign)}
    assert fields == {"label", "value"}, fields
    # Both default to None, so a rename need not resend the address and an
    # address change need not resend the name.
    assert all(
        n.value is not None and isinstance(n.value, ast.Constant) and n.value.value is None
        for n in cls.body if isinstance(n, ast.AnnAssign)
    )
