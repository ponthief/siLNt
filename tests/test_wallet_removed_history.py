"""Removing a wallet, and what the two sides are left holding.

Reported 2026-10-05, after a mainnet wallet was removed and the same seed added
back: the balance was right and the transaction list was not. Round
7e180d9e…2aa399 read "Sent -384". And the PARTNER's history had lost the round
too, from the other side of the same deletion.

Two independent causes, both here.

 1. `DELETE FROM silnt.tango_rounds WHERE a_wallet_id = :id OR b_wallet_id = :id`.
    A round row is ONE RECORD SHARED BY TWO WALLETS. Deleting it to clear the
    leaving side's history deleted the staying side's as well. The old code
    said so in a comment and called it the cost of the wallet's side not
    lingering — but the cost was being paid by the party that had not asked
    for anything.

 2. The row is found by WALLET ID, and a wallet id does not survive a
    reinstall: `wallet_id = urlsafe_short_hash()` at create time, so the same
    seed added back is a new id. Even with the row kept, the transaction list
    would not have found it. The Tango screen did, all along, because
    `list_tango_rounds_for_user` is keyed on the user — which is why the round
    was visible in one place and a plain send in the other.

-384 is the shape of the second bug rather than a coincidence: both sides of a
mix put in and take back the same amount, so the net is this side's fee share.
A mix nothing names reads as a tiny payment to nobody.

The functions are exec'd out of the live crud.py rather than imported — crud.py
pulls in lnbits, pydantic models and embit at module scope — so these run the
real statements with a fake database under them.
"""

from __future__ import annotations

import asyncio
import pathlib
import re
import types

CRUD = (pathlib.Path(__file__).resolve().parent.parent / "crud.py").read_text()


def _block(src: str, start: str, end: str) -> str:
    at = src.index(start)
    return src[at : src.index(end, at) + len(end)]


def _fn(src: str, name: str) -> str:
    at = src.rindex(f"async def {name}(")
    ends = [
        i
        for i in (
            src.find("\nasync def ", at + 10),
            src.find("\ndef ", at + 10),
            src.find("\nclass ", at + 10),
        )
        if i != -1
    ]
    return src[at : min(ends)] if ends else src[at:]


class FakeDB:
    """Records every statement, replays one canned row set."""

    def __init__(self, rows=()):
        self.rows = [dict(r) for r in rows]
        self.fetched: list[tuple[str, dict]] = []
        self.ran: list[tuple[str, dict]] = []

    async def fetchall(self, query, values=None):
        self.fetched.append((" ".join(query.split()), values or {}))
        return [dict(r) for r in self.rows]

    async def execute(self, query, values=None):
        self.ran.append((" ".join(query.split()), values or {}))
        return None


def _ns(db: FakeDB, wallet=None) -> dict:
    """crud.py's module globals, as much of them as these two need."""
    tango = types.ModuleType("tango")
    tango.dust_to_fee = lambda *_a, **_k: 0

    async def get_silnt_wallet(_wid):
        return wallet

    ns = {"db": db, "tango": tango, "get_silnt_wallet": get_silnt_wallet}
    exec(_block(CRUD, "_TANGO_DROP_SIDE = {", 'TANGO_FORGOTTEN_NAME = "removed"'), ns)
    exec(_fn(CRUD, "purge_tango_side"), ns)
    exec(_fn(CRUD, "get_tango_txids_for_wallet"), ns)
    return ns


def _wallet(user="u-mine", network="mainnet"):
    return types.SimpleNamespace(user=user, network=network)


ROUND = {
    "id": "r1",
    "status": "BROADCAST",
    "txid": "7e180d9e",
    "network": "mainnet",
    "a_wallet_id": "w-old-mine",
    "b_wallet_id": "w-theirs",
    "a_user_id": "u-mine",
    "b_user_id": "u-theirs",
    "a_username": "mine",
    "b_username": "theirs",
    "denom_sats": 14_000,
    "pieces": 1,
    "a_fee_sats": 384,
    "b_fee_sats": 384,
    "a_change_sats": 0,
    "b_change_sats": 716,
    "vsize": 500,
    "fee_rate": 1.5,
}


# ── 1. the shared row ────────────────────────────────────────────────────────


def test_a_broadcast_round_is_not_deleted_out_from_under_the_partner():
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine"))
    assert not [q for q, _ in db.ran if q.startswith("DELETE")], db.ran
    assert len(db.ran) == 1, db.ran


def test_the_leaving_side_loses_its_outpoints():
    """Which of the transaction's inputs were this wallet's coins. The
    transaction is public — tx_hex on this very row lists every input — but
    that mapping is nowhere else."""
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine"))
    sql, params = db.ran[0]
    assert "a_inputs = NULL" in sql, sql
    # The staying side keeps everything.
    assert "b_inputs" not in sql, sql
    assert params["id"] == "r1"


def test_the_leaving_side_stops_being_labelled():
    """_label_tango_coins skips a side with no wallet id. Left pointing at a
    wallet that no longer exists, it would never find the coins to label,
    never set change_labelled, and come back to the round every five minutes
    for as long as the row survives."""
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine"))
    sql, _ = db.ran[0]
    assert "a_wallet_id = ''" in sql, sql


def test_the_change_script_is_never_cleared():
    """THE TRAP. enqueue_tango_payouts finds the change output's vout BY this
    script and skips any side whose script is missing. A wallet removed
    between broadcast and confirmation would strand a payout already owed —
    the change has paid the instance and the value is owed whatever the user
    has since done with their wallet.

    Asserted on both sides' fragments, since the bug would be a one-letter
    copy between them."""
    for frag in ns_fragments():
        assert "change_spk" not in frag, frag
        assert "payout_tweak" not in frag, frag


def ns_fragments() -> list[str]:
    block = _block(CRUD, "_TANGO_DROP_SIDE = {", "}")
    return re.findall(r'"([^"]*=[^"]*)"', block)


def test_the_other_side_of_the_same_row_redacts_the_other_columns():
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-theirs"))
    sql, _ = db.ran[0]
    assert "b_inputs = NULL" in sql and "a_inputs" not in sql, sql
    assert "b_wallet_id = ''" in sql and "a_wallet_id" not in sql, sql


def test_both_sides_redact_the_same_columns():
    frags = ns_fragments()
    assert len(frags) == 2, frags
    a, b = sorted(frags)
    assert a.replace("a_", "") == b.replace("b_", ""), frags


def test_a_removed_wallet_keeps_its_own_history():
    """The account is still there and the user may well be adding the same seed
    back. list_tango_rounds_for_user is keyed on the user id, so leaving it is
    what makes the round still theirs."""
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine"))
    sql, _ = db.ran[0]
    assert "a_user_id" not in sql and "a_username" not in sql, sql


def test_a_round_that_never_reached_the_chain_goes():
    """Nobody's money moved, so it is not history — and leaving it would keep
    the partner's coins reserved against a wallet that no longer exists."""
    for status in ("PROPOSED", "ACCEPTED", "A_SIGNED", "CANCELLED", "EXPIRED"):
        db = FakeDB([dict(ROUND, status=status)])
        ns = _ns(db)
        asyncio.run(ns["purge_tango_side"]("w-old-mine"))
        assert db.ran[0][0].startswith("DELETE FROM silnt.tango_rounds"), (status, db.ran)


def test_an_account_deletion_forgets_who_it_was():
    db = FakeDB([ROUND])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine", forget_identity=True))
    sql, params = db.ran[0]
    assert "a_user_id = :ruid" in sql and "a_username = :rname" in sql, sql
    assert params["ruid"] == "" and params["rname"] == "removed"
    # Still an UPDATE: the row is the partner's record too.
    assert sql.startswith("UPDATE"), sql
    assert len(db.ran) == 1, db.ran


def test_the_row_goes_once_neither_account_is_left():
    """Nobody is left for it to be history for."""
    db = FakeDB([dict(ROUND, b_user_id="")])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine", forget_identity=True))
    assert db.ran[-1][0].startswith("DELETE FROM silnt.tango_rounds"), db.ran


def test_a_wallet_removal_never_deletes_a_broadcast_row_even_last():
    """Only an ACCOUNT deletion collects the row. A per-wallet removal leaves
    both user ids in place, so the row outlives both wallets — correctly: both
    people still have accounts, and the round is still their history."""
    db = FakeDB([dict(ROUND, b_user_id="")])
    ns = _ns(db)
    asyncio.run(ns["purge_tango_side"]("w-old-mine"))
    assert not [q for q, _ in db.ran if q.startswith("DELETE")], db.ran


# ── 2. finding the round again after a reinstall ─────────────────────────────


def test_the_round_is_found_under_a_new_wallet_id():
    """THE REPORTED BUG. The wallet was removed and the same seed added back,
    so the id is new and `a_wallet_id = :wid` matches nothing."""
    db = FakeDB([ROUND])
    ns = _ns(db, _wallet())
    out = asyncio.run(ns["get_tango_txids_for_wallet"]("w-NEW-mine"))
    assert "7e180d9e" in out, out
    assert out["7e180d9e"]["denom_sats"] == 14_000
    # Side resolved by the user id, so the fee and change are THIS side's.
    assert out["7e180d9e"]["partner"] == "theirs"
    assert out["7e180d9e"]["change_sats"] == 0
    assert out["7e180d9e"]["their_change_sats"] == 716


def test_the_query_asks_by_user_and_network_as_well():
    db = FakeDB([ROUND])
    ns = _ns(db, _wallet())
    asyncio.run(ns["get_tango_txids_for_wallet"]("w-NEW-mine"))
    sql, params = db.fetched[0]
    assert "a_wallet_id = :wid OR b_wallet_id = :wid" in sql, sql
    assert "network = :net AND (a_user_id = :uid OR b_user_id = :uid)" in sql, sql
    assert params["uid"] == "u-mine" and params["net"] == "mainnet"


def test_a_signet_round_is_not_picked_up_by_a_mainnet_wallet():
    """The user-id match has to carry the network, or an unscoped read is
    exactly the drift list_tango_rounds_for_user was fixed for."""
    db = FakeDB([ROUND])
    ns = _ns(db, _wallet())
    asyncio.run(ns["get_tango_txids_for_wallet"]("w-NEW-mine"))
    sql, _ = db.fetched[0]
    at = sql.index("a_user_id = :uid")
    assert "network = :net" in sql[:at], sql


def test_the_wallet_id_still_wins_when_it_matches():
    """It is exact, and it is the only thing that can tell two wallets of the
    same account apart."""
    db = FakeDB([ROUND])
    ns = _ns(db, _wallet(user="u-mine"))
    out = asyncio.run(ns["get_tango_txids_for_wallet"]("w-theirs"))
    assert out["7e180d9e"]["partner"] == "mine"
    assert out["7e180d9e"]["change_sats"] == 716


def test_a_round_whose_side_cannot_be_told_gets_no_summary():
    """Both user ids the same and neither wallet id matching: reading either
    side would report the partner's fee and change as this wallet's. The row
    keeps its plain arithmetic rather than gaining a wrong label."""
    db = FakeDB([dict(ROUND, a_user_id="u-mine", b_user_id="u-mine")])
    ns = _ns(db, _wallet(user="u-mine"))
    assert asyncio.run(ns["get_tango_txids_for_wallet"]("w-NEW-mine")) == {}


def test_a_missing_wallet_falls_back_to_the_wallet_id_alone():
    """get_silnt_wallet returning None must not put None into the query as a
    user id — `a_user_id = NULL` matches nothing in SQL, but an empty string
    would match a row an account deletion had redacted."""
    db = FakeDB([ROUND])
    ns = _ns(db, None)
    asyncio.run(ns["get_tango_txids_for_wallet"]("w-old-mine"))
    sql, params = db.fetched[0]
    assert ":uid" not in sql, sql
    assert "uid" not in params and "net" not in params, params


def test_the_statement_selects_everything_the_side_logic_reads():
    """A column read off a row the query never selected is a KeyError on the
    transaction list of every wallet that has ever mixed."""
    body = _fn(CRUD, "get_tango_txids_for_wallet")
    select = body[body.index("SELECT") : body.index("FROM silnt.tango_rounds")]
    for col in ("a_wallet_id", "b_wallet_id", "a_user_id", "b_user_id",
                "a_username", "b_username"):
        assert col in select, f"{col} is read but not selected"


def test_both_delete_paths_go_through_the_one_helper():
    """The two of them had the same DELETE copied into each, which is how one
    fix would have missed the other."""
    for name in ("delete_silnt_wallet", "delete_all_silnt_data_for_user"):
        body = _fn(CRUD, name)
        assert "purge_tango_side(" in body, name
        assert "silnt.tango_rounds" not in body, name
    assert len(re.findall(r"^async def purge_tango_side\(", CRUD, re.M)) == 1
