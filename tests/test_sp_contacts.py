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


# ── a contact that cannot be read says so, instead of handing out ciphertext ──
#
# Reported 2026-11-12 from the phone's Send screen: saved addresses shown as
# `U2FsdGVk…`. `_decrypt_sp_contact_row` swallowed every decrypt failure and
# returned the stored ciphertext as the address.

def _row_fn(pj_decrypt):
    """The real function, compiled out of crud.py, with a stand-in cipher."""
    src = (ROOT / "crud.py").read_text()
    at = src.index("_CIPHERTEXT_PREFIX = ")
    end = src.index("\nasync def create_sp_contact(")
    ns = {"_pj_decrypt": pj_decrypt, "_key_fingerprint": lambda k: "fp",
          "_payjoin_enc_key": lambda: "key"}
    exec(src[at:end], ns)
    return ns["_decrypt_sp_contact_row"]


def _fake_cipher(key="k"):
    import base64

    def enc(plain):
        return "U2FsdGVk" + base64.b64encode((key + "|" + plain).encode()).decode()

    def dec(cipher):
        raw = base64.b64decode(cipher[len("U2FsdGVk"):]).decode()
        k, _, plain = raw.partition("|")
        if k != key:
            raise ValueError("Padding is incorrect.")
        return plain

    return enc, dec


def test_a_readable_contact_comes_back_as_its_address():
    enc, dec = _fake_cipher()
    out = _row_fn(dec)({"id": "c", "value": enc("tsp1qexample")})
    assert out["value"] == "tsp1qexample"
    assert not out.get("unreadable")


def test_a_legacy_plaintext_value_is_left_alone():
    enc, dec = _fake_cipher()
    for v in ("tsp1qexample", "sp1qexample", "alice@example.com"):
        out = _row_fn(dec)({"id": "c", "value": v})
        assert out["value"] == v and not out.get("unreadable")


def test_a_value_encrypted_twice_is_peeled():
    """The ciphertext re-submitted as an address — which a client that was
    shown ciphertext could do — decrypts to more ciphertext."""
    enc, dec = _fake_cipher()
    out = _row_fn(dec)({"id": "c", "value": enc(enc("tsp1qexample"))})
    assert out["value"] == "tsp1qexample"


def test_an_unopenable_value_is_empty_and_flagged_never_ciphertext():
    enc, dec = _fake_cipher("another-instance")
    stored = enc("tsp1qexample")
    out = _row_fn(_fake_cipher("this-instance")[1])({"id": "c", "value": stored})
    assert out["unreadable"] is True
    assert out["value"] == ""
    assert "U2FsdGVk" not in out["value"]


def test_the_swallowing_except_is_gone():
    body = _fn("crud.py", "_decrypt_sp_contact_row")
    code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "pass  # legacy" not in code
    assert "unreadable" in code


def test_the_list_does_not_ask_whether_an_unreadable_one_is_a_wallet():
    body = _fn("views_api.py", "api_sp_contacts_list")
    assert "c.unreadable" in body


# ── a row written under the instance's OTHER key is still read ────────────────
#
# LNbits takes auth_secret_key from AUTH_SECRET_KEY, else from
# <data folder>/.lnbits_auth_key_v1. Setting the variable later, removing it,
# or recreating the folder changes which one answers, and every row written
# under the other stops decrypting. Reported 2026-11-12 as
# "could not decrypt contact … ValueError".

def _crypto_ns(tmp_path, *, auth_secret_key, env=None, key_file=None):
    """The real key + decrypt block from crud.py, with LNbits stubbed."""
    import base64
    import hashlib
    import sys
    import types

    if key_file is not None:
        (tmp_path / ".lnbits_auth_key_v1").write_text(key_file)

    class FakeCipher:
        """Keyed, authenticated, text-only: wrong key raises ValueError, as the
        real one does on a padding failure."""
        def __init__(self, key):
            self.key = key

        def _tag(self):
            return hashlib.sha256(("tag|" + self.key).encode()).hexdigest()[:8]

        def encrypt(self, data):
            return "U2FsdGVk" + base64.b64encode(
                (self._tag() + data.decode()).encode()).decode()

        def decrypt(self, cipher):
            raw = base64.b64decode(cipher[len("U2FsdGVk"):]).decode()
            if raw[:8] != self._tag():
                raise ValueError("Padding is incorrect.")
            return raw[8:]

    settings = types.SimpleNamespace(
        auth_secret_key=auth_secret_key, lnbits_data_folder=str(tmp_path))
    mods = {
        "lnbits": types.ModuleType("lnbits"),
        "lnbits.settings": types.ModuleType("lnbits.settings"),
        "lnbits.utils": types.ModuleType("lnbits.utils"),
        "lnbits.utils.crypto": types.ModuleType("lnbits.utils.crypto"),
    }
    mods["lnbits.settings"].settings = settings
    mods["lnbits.utils.crypto"].AESCipher = FakeCipher
    saved = {k: sys.modules.get(k) for k in mods}
    sys.modules.update(mods)

    src = (ROOT / "crud.py").read_text()
    block = src[src.index("def _payjoin_enc_key()"):src.index("def _xpub_fingerprint_hash")]
    ns: dict = {}
    import os
    old_env = {k: os.environ.get(k) for k in (env or {})}
    os.environ.update(env or {})
    try:
        exec(block, ns)
        ns["_restore"] = lambda: (
            [sys.modules.pop(k, None) if v is None else sys.modules.__setitem__(k, v)
             for k, v in saved.items()],
            [os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
             for k, v in old_env.items()],
        )
        ns["FakeCipher"] = FakeCipher
    except Exception:
        ns["_restore"] = lambda: None
        raise
    return ns


def _legacy(ns, plain):
    """A row as the OLD scheme wrote it: under LNbits' secret, no prefix."""
    return ns["FakeCipher"](ns["_payjoin_enc_key"]()).encrypt(plain.encode())



def test_a_row_written_under_the_key_file_is_read_after_the_env_var_took_over(tmp_path):
    # Written when the file key was current…
    writer = _crypto_ns(tmp_path, auth_secret_key="file-key", key_file="file-key")
    stored = _legacy(writer, "tsp1qexample")
    writer["_restore"]()
    # …then AUTH_SECRET_KEY was set, so settings now answers with another key.
    reader = _crypto_ns(tmp_path, auth_secret_key="env-key", key_file="file-key")
    try:
        assert reader["_pj_decrypt"](stored) == "tsp1qexample"
    finally:
        reader["_restore"]()


def test_a_row_written_under_the_env_key_is_read_after_it_was_removed(tmp_path):
    writer = _crypto_ns(tmp_path, auth_secret_key="env-key", key_file="file-key")
    stored = _legacy(writer, "tsp1qexample")
    writer["_restore"]()
    reader = _crypto_ns(tmp_path, auth_secret_key="file-key", key_file="file-key",
                        env={"AUTH_SECRET_KEY": "env-key"})
    try:
        assert reader["_pj_decrypt"](stored) == "tsp1qexample"
    finally:
        reader["_restore"]()


def test_a_key_nobody_has_still_raises(tmp_path):
    writer = _crypto_ns(tmp_path, auth_secret_key="gone-for-good")
    stored = _legacy(writer, "tsp1qexample")
    writer["_restore"]()
    reader = _crypto_ns(tmp_path, auth_secret_key="current", key_file="other")
    try:
        import pytest
        with pytest.raises(Exception):
            reader["_pj_decrypt"](stored)
    finally:
        reader["_restore"]()


def test_the_current_key_is_tried_first_and_candidates_have_no_duplicates(tmp_path):
    ns = _crypto_ns(tmp_path, auth_secret_key="k", key_file="k")
    try:
        cands = ns["_payjoin_enc_key_candidates"]()
        assert cands[0] == ("current", "k")
        assert len({k for _, k in cands}) == len(cands)
    finally:
        ns["_restore"]()


def test_a_fingerprint_names_a_key_without_being_it():
    src = (ROOT / "crud.py").read_text()
    body = _fn("crud.py", "_key_fingerprint")
    assert "[:8]" in body
    assert "silnt-key-fp|" in body
    # And the log lines carry the fingerprint, never the key.
    log_lines = [l for l in src.splitlines() if "[crypto]" in l or "[contacts]" in l]
    assert log_lines and not any("{primary}" in l or "{key}" in l for l in log_lines)


def test_a_recovered_old_key_named_in_the_environment_opens_old_rows(tmp_path):
    writer = _crypto_ns(tmp_path, auth_secret_key="the-key-before-rotation")
    stored = _legacy(writer, "tsp1qexample")
    writer["_restore"]()
    reader = _crypto_ns(tmp_path, auth_secret_key="rotated-key",
                        env={"SILNT_LEGACY_AUTH_KEYS": "something-else, the-key-before-rotation"})
    try:
        assert reader["_pj_decrypt"](stored) == "tsp1qexample"
    finally:
        reader["_restore"]()


# ── the extension's OWN key, which LNbits cannot rotate ───────────────────────

def test_new_rows_are_v2_and_survive_the_lnbits_secret_being_rotated(tmp_path):
    before = _crypto_ns(tmp_path, auth_secret_key="lnbits-secret-1")
    try:
        stored = before["_pj_encrypt"]("tsp1qexample")
        assert stored.startswith("v2:")
        key_file = tmp_path / ".silnt_enc_key_v1"
        assert key_file.is_file()
        assert len(key_file.read_text().strip()) == 64
        assert oct(key_file.stat().st_mode & 0o777) == oct(0o600)
    finally:
        before["_restore"]()
    # LNbits' secret is rotated — and the data folder keeps the extension's key.
    after = _crypto_ns(tmp_path, auth_secret_key="lnbits-secret-2-after-incident")
    try:
        assert after["_pj_decrypt"](stored) == "tsp1qexample"
    finally:
        after["_restore"]()


def test_the_env_key_wins_over_the_file_and_must_be_long_enough(tmp_path):
    long_key = "k" * 40
    ns = _crypto_ns(tmp_path, auth_secret_key="x", env={"SILNT_ENC_KEY": long_key})
    try:
        assert ns["_silnt_enc_key"]() == long_key
        assert not (tmp_path / ".silnt_enc_key_v1").exists()
    finally:
        ns["_restore"]()
    short = _crypto_ns(tmp_path, auth_secret_key="x", env={"SILNT_ENC_KEY": "short"})
    try:
        import pytest
        with pytest.raises(RuntimeError):
            short["_silnt_enc_key"]()
        # …and saving still works, under the legacy scheme, rather than failing.
        assert not short["_pj_encrypt"]("tsp1qexample").startswith("v2:")
    finally:
        short["_restore"]()


def test_a_v2_row_is_not_tried_against_lnbits_keys(tmp_path):
    a = _crypto_ns(tmp_path / "a" if (tmp_path / "a").mkdir() is None else tmp_path,
                   auth_secret_key="s")
    stored = a["_pj_encrypt"]("tsp1qexample")
    a["_restore"]()
    other = tmp_path / "b"
    other.mkdir()
    b = _crypto_ns(other, auth_secret_key="s")  # a DIFFERENT extension key
    try:
        import pytest
        with pytest.raises(Exception):
            b["_pj_decrypt"](stored)
    finally:
        b["_restore"]()


def test_a_v2_value_is_recognised_as_ciphertext_by_the_contact_reader():
    enc, dec = _fake_cipher()
    row = _row_fn(lambda v: dec(v[len("v2:"):]) if v.startswith("v2:") else dec(v))
    out = row({"id": "c", "value": "v2:" + enc("tsp1qexample")})
    assert out["value"] == "tsp1qexample"
    unreadable = _row_fn(lambda v: (_ for _ in ()).throw(ValueError("x")))(
        {"id": "c", "value": "v2:whatever"})
    assert unreadable["unreadable"] is True and unreadable["value"] == ""


class _FakeDb:
    def __init__(self, rows):
        self.rows = rows            # (table, col) -> list of dict rows
        self.updates = []

    async def fetchall(self, sql, params):
        for (table, col), rows in self.rows.items():
            if f"FROM {table} " in sql and f"{col} AS _v" in sql:
                return [dict(r) for r in rows if not r["_v"].startswith("v2:")]
        return []

    async def execute(self, sql, params):
        self.updates.append((sql, params))


def test_the_migration_rewrites_readable_rows_and_leaves_the_rest(tmp_path):
    import asyncio
    import sys

    ns = _crypto_ns(tmp_path, auth_secret_key="current")
    try:
        legacy = ns["FakeCipher"]("current").encrypt(b"tsp1qreadable")
        lost = ns["FakeCipher"]("gone").encrypt(b"tsp1qlost")
        twice = ns["FakeCipher"]("current").encrypt(legacy.encode())
        db = _FakeDb({
            ("silnt.sp_contacts", "value"): [
                {"id": "a", "_v": legacy},
                {"id": "b", "_v": lost},
                {"id": "c", "_v": "alice@example.com"},     # legacy plaintext
                {"id": "d", "_v": twice},                    # encrypted twice
                {"id": "e", "_v": "v2:already"},             # already migrated
            ],
        })
        src = (ROOT / "crud.py").read_text()
        block = src[src.index("_REENCRYPT_TARGETS = ("):src.index(
            "# ── SP send contacts (per-user private address book)")]
        ns2 = dict(ns)
        ns2.update({"db": db, "_CIPHERTEXT_PREFIX": "U2FsdGVk"})
        exec(block, ns2)
        result = asyncio.run(ns2["reencrypt_legacy_rows"]())

        assert result["done"] == 1, result
        assert result["unreadable"] == 1, result
        assert len(db.updates) == 1
        sql, params = db.updates[0]
        assert "silnt.sp_contacts" in sql and "AND value = :old" in sql
        assert params["p0"] == "a" and params["old"] == legacy
        assert params["new"].startswith("v2:")
        # What was written reads back to the same address.
        assert ns2["_pj_decrypt"](params["new"]) == "tsp1qreadable"
    finally:
        ns["_restore"]()


def test_the_migration_never_writes_without_a_round_trip_and_names_its_tables():
    body = (ROOT / "crud.py").read_text()
    at = body.index("async def reencrypt_legacy_rows")
    fn = body[at:body.index("# ── SP send contacts (per-user private address book)")]
    assert "_pj_decrypt(new) != plain" in fn          # verified before writing
    assert "AND {col} = :old" in fn                    # conditional on what was read
    for col in ("scan_secret", "ln_address", '"address"', "descriptor", "xpub"):
        assert col in body[body.index("_REENCRYPT_TARGETS = ("):at]
