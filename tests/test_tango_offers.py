"""The Tango board: adverts that hold no coins.

Three kinds of test, because the failures are of three kinds. The pure rules
(helpers/tangooffers.py) are run. The board's SQL is run against a real SQLite,
because "an offer that ended is gone" and "only what is open is listed" are
round trips. And the endpoint wiring is read from source, because the importing
module needs LNbits: what it pins is each place a refusal or a cleanup could be
quietly dropped while the app kept working.
"""

from __future__ import annotations

import asyncio
import importlib.util
import pathlib
import re
import sqlite3
import sys
import time
import types
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load(module: str):
    name = f"{PKG}.helpers._{module}_for_offer_tests"
    if name in sys.modules:
        return sys.modules[name]
    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(m, types.ModuleType(m))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / f"{module}.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# tangooffers imports `.tango` lazily for outpoint_key; give it the same name
# the package gives it so that import resolves.
wallet = _load("wallet")
sys.modules[f"{PKG}.helpers.wallet"] = wallet
pjsp = _load("payjoin_sp")
sys.modules[f"{PKG}.helpers.payjoin_sp"] = pjsp
tango = _load("tango")
sys.modules[f"{PKG}.helpers.tango"] = tango
board = _load("tangooffers")

VIEWS = (ROOT / "views_api.py").read_text()
CRUD = (ROOT / "crud.py").read_text()
MIG = (ROOT / "migrations.py").read_text()
MODELS = (ROOT / "models.py").read_text()


def _fn(src: str, name: str) -> str:
    at = src.index(f"def {name}(")
    ends = [i for i in (src.find("\nasync def ", at + 10), src.find("\ndef ", at + 10),
                        src.find("\n@silnt_api_router", at + 10)) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


# ── the pure rules ───────────────────────────────────────────────────────────


def test_an_offer_lives_twenty_one_hours():
    """The user's number. A proposal made in the last minute still has most of a
    day: the round's own clock is 24 hours."""
    assert board.OFFER_TTL_SECONDS == 21 * 3600
    assert board.expires_at_for(1_000) == 1_000 + 21 * 3600
    assert board.OFFER_TTL_SECONDS < 86400


def test_denominations_are_a_fixed_ascending_list_of_positive_sats():
    d = list(board.DENOMINATIONS)
    assert d == sorted(set(d)) and d and all(x > 0 for x in d)


def test_the_coin_split_is_one_to_three_and_inside_what_the_protocol_allows():
    assert board.PIECES == (1, 2, 3)
    # ProposeTangoData allows 1-4; an offer must never name a split a proposal
    # for it would be refused.
    assert max(board.PIECES) <= 4


def test_every_denomination_can_be_planned_at_every_split():
    """An offer the protocol cannot build is a dead advert. Priced the way
    propose does: each side's own coins standing in for the other's."""
    def coin(seed, amount):
        txid = f"{seed:02x}" + "11" * 30 + f"{(seed ^ 0xFF):02x}"
        import coincurve
        pub = coincurve.PrivateKey(bytes([seed]) * 32).public_key.format()[1:]
        return pjsp.PayjoinInput(txid=txid, vout=0, amount=amount, pub_key=pub)

    for denom in board.DENOMINATIONS:
        for pieces in board.PIECES:
            mine = [coin(0xA1, denom + board.FUNDING_MARGIN_SATS)]
            other = [coin(0xB2, denom + board.FUNDING_MARGIN_SATS)]
            tango.plan(mine, other, denom, 5.0, pieces)


def test_every_denomination_divides_by_every_split():
    """Why the list is multiples of 6: an output of a Tango is the same size on
    both sides and in every piece, so an amount that does not divide by the
    split cannot be offered at that split."""
    from math import lcm
    step = lcm(*board.PIECES)
    assert all(d % step == 0 for d in board.DENOMINATIONS)


def test_validate_offer_accepts_listed_values_and_refuses_the_rest():
    board.validate_offer(120_000, 2, "connections")
    for bad in [
        (123_456, 1, "connections"),
        (120_000, 4, "connections"),
        (120_000, 0, "connections"),
        (120_000, 1, "public"),
        (120_000, 1, ""),
    ]:
        try:
            board.validate_offer(*bad)
        except ValueError as e:
            assert str(e)
        else:
            raise AssertionError(f"{bad} was accepted")


def test_connections_only_is_the_default_and_anyone_is_a_choice():
    assert board.DEFAULT_VISIBILITY == board.VISIBILITY_CONNECTIONS
    assert board.visible_to("connections", True) is True
    assert board.visible_to("connections", False) is False
    assert board.visible_to("anyone", False) is True
    # Nothing unknown is visible by accident.
    assert board.visible_to("whatever", False) is False


def test_open_means_strictly_before_expiry_and_a_missing_expiry_is_not_open():
    assert board.is_open(101, 100) is True
    assert board.is_open(100, 100) is False
    assert board.is_open(None, 100) is False
    assert board.is_open(0, 100) is False


def test_fee_cap_is_twice_the_fastest_tier_with_a_floor():
    assert board.fee_cap({"fastestFee": 20}) == 40
    assert board.fee_cap({"fastestFee": 1}) == board.FEE_CAP_FLOOR
    # A lookup that failed or sent nonsense must not lift the cap.
    assert board.fee_cap(None) == board.FEE_CAP_FLOOR
    assert board.fee_cap({"fastestFee": "x"}) == board.FEE_CAP_FLOOR


def test_spendable_leaves_out_reserved_coins_and_funding_has_a_margin():
    rows = [
        {"txid": "AA" * 32, "vout": 0, "amount": 60_000},
        {"txid": "bb" * 32, "vout": 1, "amount": 70_000},
    ]
    reserved = {tango.outpoint_key("aa" * 32, 0)}  # case differs on purpose
    assert board.sats_spendable(rows, reserved) == 70_000
    assert board.sats_spendable(rows, set()) == 130_000
    assert board.can_fund(120_000 + board.FUNDING_MARGIN_SATS, 120_000)
    assert not board.can_fund(120_000, 120_000)


def test_the_rate_limiter_blocks_after_the_limit_and_frees_after_the_window():
    now = [1000.0]
    lim = board.RateLimiter(2, 60, clock=lambda: now[0])
    assert lim.allow("u") and lim.allow("u") and not lim.allow("u")
    assert lim.allow("other")          # keyed per user
    now[0] += 61
    assert lim.allow("u")


# ── the board's SQL, against a real SQLite ───────────────────────────────────


class _Db:
    def __init__(self):
        self.c = sqlite3.connect(":memory:")
        self.c.row_factory = sqlite3.Row
        self.c.execute("ATTACH DATABASE ':memory:' AS silnt")
        self.c.execute(
            """CREATE TABLE silnt.tango_offers (
                 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, username TEXT NOT NULL,
                 network TEXT NOT NULL, denom_sats BIGINT NOT NULL,
                 pieces INTEGER NOT NULL DEFAULT 1,
                 visibility TEXT NOT NULL DEFAULT 'connections',
                 posted_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
                 sp_address TEXT)"""
        )
        self.c.execute(
            """CREATE TABLE silnt.tango_board_strikes (
                 user_id TEXT NOT NULL, network TEXT NOT NULL,
                 struck_at BIGINT NOT NULL)"""
        )
        self.c.execute(
            """CREATE TABLE silnt.tango_board_bans (
                 user_id TEXT PRIMARY KEY, username TEXT NOT NULL,
                 banned_at BIGINT NOT NULL)"""
        )
        self.c.execute(
            """CREATE TABLE silnt.tango_rounds (
                 id TEXT PRIMARY KEY, status TEXT, a_user_id TEXT, offer_id TEXT)"""
        )
        self.c.execute(
            """CREATE TABLE silnt.utxos (
                 wallet_id TEXT, txid TEXT, vout INTEGER, amount BIGINT,
                 utxo_state TEXT, frozen BOOLEAN)"""
        )

    async def execute(self, sql, params=None):
        return self.c.execute(sql, params or {})

    async def fetchone(self, sql, params=None):
        r = self.c.execute(sql, params or {}).fetchone()
        return dict(r) if r else None

    async def fetchall(self, sql, params=None, model=None):
        return [dict(r) for r in self.c.execute(sql, params or {}).fetchall()]


class _Round:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _crud():
    start = CRUD.index("# ── the Tango board")
    end = CRUD.index("async def get_reserved_tango_outpoints(")
    db = _Db()
    counter = iter(range(1, 10_000))

    async def get_silnt_wallets(user, network=None):
        return [_Round(id=f"w-{user}-{network}")]

    ns = {
        "db": db, "Optional": Optional, "time": time,
        "urlsafe_short_hash": lambda: f"id{next(counter)}",
        "TangoRound": lambda **kw: _Round(**kw),
        "get_silnt_wallets": get_silnt_wallets,
    }
    exec(CRUD[start:end], ns)
    return ns, db


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _post(ns, uid="u1", denom=120_000, pieces=1, vis="connections",
          posted=1_000, expires=1_000 + 21 * 3600, net="mainnet", sp=None):
    return run(ns["create_tango_offer"](
        user_id=uid, username=f"name-{uid}", network=net, denom_sats=denom,
        pieces=pieces, visibility=vis, posted_at=posted, expires_at=expires,
        sp_address=sp,
    ))


def test_a_posted_offer_reads_back_and_lists_newest_first():
    ns, _ = _crud()
    a = _post(ns, "u1", posted=1_000)
    b = _post(ns, "u2", posted=2_000)
    assert a["denom_sats"] == 120_000 and a["visibility"] == "connections"
    got = run(ns["list_open_tango_offers"]("mainnet", 1_500))
    assert [o["id"] for o in got] == [b["id"], a["id"]]


def test_an_expired_offer_is_not_listed_even_before_the_sweeper_runs():
    ns, _ = _crud()
    _post(ns, "u1", expires=1_500)
    assert run(ns["list_open_tango_offers"]("mainnet", 1_499))
    assert run(ns["list_open_tango_offers"]("mainnet", 1_500)) == []
    assert run(ns["list_user_tango_offers"]("u1", "mainnet", 1_500)) == []


def test_the_board_is_per_network():
    ns, _ = _crud()
    _post(ns, "u1", net="signet")
    assert run(ns["list_open_tango_offers"]("mainnet", 1_000)) == []
    assert len(run(ns["list_open_tango_offers"]("signet", 1_000))) == 1


def test_the_sweeper_deletes_only_what_has_expired_and_says_how_many():
    ns, db = _crud()
    _post(ns, "u1", expires=1_500)
    _post(ns, "u2", expires=1_600)
    keep = _post(ns, "u3", expires=9_999)
    assert run(ns["delete_expired_tango_offers"](1_600)) == 2
    left = db.c.execute("SELECT id FROM silnt.tango_offers").fetchall()
    assert [r["id"] for r in left] == [keep["id"]]


def test_withdrawing_and_leaving_both_delete_rather_than_mark():
    ns, db = _crud()
    a = _post(ns, "u1")
    _post(ns, "u2")
    run(ns["delete_tango_offer"](a["id"]))
    assert run(ns["get_tango_offer"](a["id"])) is None
    run(ns["delete_tango_offers_for_user_network"]("u2", "mainnet"))
    assert db.c.execute("SELECT COUNT(*) FROM silnt.tango_offers").fetchone()[0] == 0


def test_account_deletion_takes_every_offer_of_that_user_only():
    ns, db = _crud()
    _post(ns, "u1", net="mainnet")
    _post(ns, "u1", net="signet", denom=60_000)
    _post(ns, "u2")
    run(ns["delete_tango_offers_for_user"]("u1"))
    rows = db.c.execute("SELECT user_id FROM silnt.tango_offers").fetchall()
    assert [r["user_id"] for r in rows] == ["u2"]


def test_only_waiting_proposals_against_an_offer_are_listed():
    ns, db = _crud()
    for rid, status, offer, taker in [
        ("r1", "PROPOSED", "o1", "t1"),
        ("r2", "ACCEPTED", "o1", "t2"),
        ("r3", "PROPOSED", "o2", "t1"),
        ("r4", "PROPOSED", None, "t1"),
        ("r5", "CANCELLED", "o1", "t3"),
    ]:
        db.c.execute(
            "INSERT INTO silnt.tango_rounds VALUES (?,?,?,?)",
            (rid, status, taker, offer),
        )
    got = run(ns["list_proposed_rounds_for_offer"]("o1"))
    assert [r.id for r in got] == ["r1"]
    # The taker's count is their PROPOSED board rounds only: an ordinary round
    # (no offer) and an answered one do not count against the board's cap.
    assert run(ns["count_board_proposals_by_taker"]("t1")) == 2


def test_the_makers_spendable_coins_exclude_spent_and_frozen():
    ns, db = _crud()
    for txid, state, frozen in [
        ("a", "unspent", 0), ("b", "unspent", 1), ("c", "spent", 0),
        ("d", "unconfirmed_spent", 0),
    ]:
        db.c.execute(
            "INSERT INTO silnt.utxos VALUES (?,?,?,?,?,?)",
            ("w-u1-mainnet", txid, 0, 10_000, state, frozen),
        )
    rows = run(ns["get_spendable_coin_rows"]("u1", "mainnet"))
    assert [r["txid"] for r in rows] == ["a"]


# ── the wiring, read from source ─────────────────────────────────────────────


def test_the_migration_creates_the_table_and_the_round_link_without_a_created_at():
    body = MIG[MIG.index("async def m047_tango_offers"):]
    assert "CREATE TABLE IF NOT EXISTS silnt.tango_offers" in body
    assert "ADD COLUMN IF NOT EXISTS offer_id TEXT" in body
    # `created_at` means a TIMESTAMP in this schema; the epoch columns are named
    # for what they are.
    assert "posted_at" in body and "created_at" not in body.split('"""')[2]


def test_a_round_and_a_proposal_can_carry_an_offer_id():
    assert re.search(r"class TangoRound\(.*?offer_id: Optional\[str\] = None", MODELS, re.S)
    assert re.search(r"class ProposeTangoData\(.*?offer_id: Optional\[str\] = None", MODELS, re.S)
    assert "class PostTangoOfferData" in MODELS


def test_propose_keeps_the_connection_rule_for_every_round_without_an_offer():
    body = _fn(VIEWS, "api_tango_propose")
    # The connection refusal still exists, and is reached only when there is no
    # offer: the board opens one hole, not the whole rule.
    assert "elif not connected:" in body
    assert "You can only Tango with someone you are connected to" in body
    assert "if data.offer_id:" in body
    assert "_tango_check_board_proposal(" in body
    assert "offer_id=offer[\"id\"] if offer else None" in body


def test_a_board_proposal_is_checked_against_the_offer_in_every_way_that_matters():
    body = _fn(VIEWS, "_tango_check_board_proposal")
    for needle in (
        "is_open(offer[\"expires_at\"], now)",           # not expired
        "offer[\"network\"] != wallet.network",           # same network
        "offer[\"user_id\"] != maker_id",                  # the maker named
        "maker_id == uid",                                 # not your own
        "visible_to(offer[\"visibility\"], connected)",    # connections vs anyone
        "MAX_PROPOSALS_PER_OFFER",                         # inbox bounded
        "MAX_BOARD_PROPOSALS_PER_TAKER",                   # taker bounded
        "fee_cap(",                                        # fee bounded
        "_tango_maker_can_fund(",                          # offer honourable
    ):
        assert needle in body, needle
    # Every refusal that could tell a stranger about the maker is the same
    # "gone": an offer that is not for you reads as no offer.
    assert body.count("raise gone") >= 2


def test_accepting_closes_the_offer_and_cancels_the_other_proposals():
    body = _fn(VIEWS, "api_tango_accept")
    assert "if rnd.offer_id:" in body
    assert "_close_tango_offer(rnd.offer_id, keep_round=rid, reason=OFFER_TAKEN)" in body
    close = _fn(VIEWS, "_close_tango_offer")
    assert "if other.id == keep_round:" in close
    assert "status=\"CANCELLED\"" in close and "delete_tango_offer(offer_id)" in close


def test_withdrawing_is_the_owners_alone_and_frees_the_proposers():
    body = _fn(VIEWS, "api_tango_offer_withdraw")
    assert "offer[\"user_id\"] != uid" in body
    assert "reason=OFFER_WITHDRAWN" in body


def test_posting_is_bounded_and_checked():
    body = _fn(VIEWS, "api_tango_offer_post")
    for needle in (
        "_pj_own_wallet(data.wallet_id, uid)",
        "_board_post_limit.allow(uid)",
        "board.validate_offer(",
        "board.MAX_OPEN_OFFERS",
        "_tango_maker_can_fund(",
        "expires_at=board.expires_at_for(now)",
    ):
        assert needle in body, needle


def test_the_listing_hides_what_the_caller_may_not_take_and_never_the_makers_id():
    body = _fn(VIEWS, "api_tango_offers")
    assert "board.visible_to(" in body
    assert "if o[\"user_id\"] == uid:" in body
    view = _fn(VIEWS, "_offer_view")
    assert "user_id" not in view
    # The lists a client renders come from here, not from a copy in the app.
    for key in ("denominations", "pieces", "ttl_seconds", "default_visibility", "now"):
        assert f'"{key}"' in body


def test_expiry_is_swept_and_a_wallet_or_account_going_takes_its_offers():
    assert "delete_expired_tango_offers(now)" in _fn(VIEWS, "run_tango_sweep")
    assert "delete_tango_offers_for_user_network" in VIEWS
    assert "DELETE FROM silnt.tango_offers WHERE user_id = :uid" in CRUD


# ── abuse: the answer window, strikes, one wallet, the operator ──────────────


def test_the_floor_is_not_small():
    """12k and 30k were judged too small to be worth a mix (2026-11-25). The
    floor is one tuple entry; this pins that it did not come back."""
    assert min(board.DENOMINATIONS) >= 60_000


def test_a_board_proposal_gets_two_hours_and_an_answered_one_gets_its_day_back():
    assert board.ANSWER_WINDOW_SECONDS == 2 * 3600
    assert board.ANSWER_WINDOW_SECONDS < 86400
    prop = _fn(VIEWS, "api_tango_propose")
    assert "ANSWER_WINDOW_SECONDS if offer else TANGO_EXPIRY_SECONDS" in prop
    acc = _fn(VIEWS, "api_tango_accept")
    assert '"expires_at": int(time.time()) + TANGO_EXPIRY_SECONDS' in acc
    assert "if rnd.offer_id" in acc


def test_suspension_arithmetic():
    now = 1_000_000
    day = board.STRIKE_WINDOW_SECONDS
    # Under the limit: free.
    assert board.suspended_for([], now) == 0
    assert board.suspended_for([now - 10, now - 20], now) == 0
    # At the limit: wait until the OLDEST of the three has aged out.
    three = [now - 3600, now - 1800, now - 60]
    assert board.suspended_for(three, now) == (now - 3600) + day - now
    # Strikes outside the window do not count at all.
    old = [now - day - 5, now - day - 50, now - 60]
    assert board.suspended_for(old, now) == 0
    # More than the limit: enough must age out to leave LIMIT - 1, so with four
    # strikes it is the second-oldest that sets the wait.
    four = [now - 7000, now - 3600, now - 1800, now - 60]
    assert board.suspended_for(four, now) == (now - 3600) + day - now
    # And never negative.
    assert board.suspended_for(three, now + 10 * day) == 0


def test_strikes_are_counted_per_user_and_network_and_age_out():
    ns, db = _crud()
    for t in (100, 200, 300):
        run(ns["record_board_strike"]("u1", "mainnet", t))
    run(ns["record_board_strike"]("u1", "signet", 250))
    run(ns["record_board_strike"]("u2", "mainnet", 260))
    assert run(ns["list_board_strikes"]("u1", "mainnet", 0)) == [100, 200, 300]
    assert run(ns["list_board_strikes"]("u1", "mainnet", 150)) == [200, 300]
    assert run(ns["list_board_strikes"]("u1", "signet", 0)) == [250]
    assert run(ns["delete_old_board_strikes"](200)) == 2
    assert run(ns["list_board_strikes"]("u1", "mainnet", 0)) == [300]


def test_a_wallets_address_is_counted_across_accounts_and_only_while_open():
    ns, _ = _crud()
    _post(ns, "u1", denom=60_000, sp="tsp1same", expires=5_000)
    _post(ns, "u2", denom=120_000, sp="tsp1same", expires=5_000)
    _post(ns, "u3", denom=60_000, sp="tsp1other", expires=5_000)
    _post(ns, "u4", denom=60_000, sp=None, expires=5_000)   # posted before m048
    count = lambda sp, now=1_000, net="mainnet": run(  # noqa: E731
        ns["count_open_tango_offers_for_address"](net, sp, now))
    assert count("tsp1same") == 2          # two ACCOUNTS, one address
    assert count("tsp1other") == 1
    assert count("tsp1same", now=5_000) == 0   # expired offers do not count
    assert count("tsp1same", net="signet") == 0
    assert count("") == 0 and count(None) == 0  # an unknown address never matches


def test_bans_are_per_user_and_reversible():
    ns, _ = _crud()
    assert run(ns["is_banned_from_board"]("u1")) is False
    run(ns["ban_from_board"]("u1", "alice", 10))
    run(ns["ban_from_board"]("u1", "alice", 20))     # twice is one row
    assert run(ns["is_banned_from_board"]("u1")) is True
    assert run(ns["is_banned_from_board"]("u2")) is False
    assert [b["username"] for b in run(ns["list_board_bans"]())] == ["alice"]
    run(ns["unban_from_board"]("u1"))
    assert run(ns["is_banned_from_board"]("u1")) is False


def test_the_operator_sees_every_open_offer_on_every_network():
    ns, _ = _crud()
    _post(ns, "u1", net="mainnet", expires=5_000)
    _post(ns, "u2", net="signet", denom=60_000, expires=5_000)
    _post(ns, "u3", net="signet", denom=300_000, expires=500)
    got = run(ns["list_all_open_tango_offers"](1_000))
    assert sorted(o["user_id"] for o in got) == ["u1", "u2"]


def test_the_sweep_strikes_only_a_proposal_that_ran_out_unanswered():
    body = _fn(VIEWS, "run_tango_sweep")
    assert 'unanswered = bool(rnd.offer_id) and rnd.status == "PROPOSED"' in body
    # Read BEFORE the status is changed, or every expired round would read
    # CANCELLED and none would ever be struck.
    assert body.index("unanswered =") < body.index('status="CANCELLED"')
    assert "_strike_board_maker(rnd.b_user_id, rnd.network, now)" in body
    assert "delete_old_board_strikes" in VIEWS


def test_enough_strikes_take_the_makers_offers_down():
    body = _fn(VIEWS, "_strike_board_maker")
    assert "record_board_strike" in body and "STRIKE_LIMIT" in body
    assert "delete_tango_offers_for_user_network(user_id, network)" in body


def test_posting_refuses_a_switched_off_board_a_ban_a_suspension_and_a_crowded_address():
    post = _fn(VIEWS, "api_tango_offer_post")
    for needle in (
        "_board_refusal(uid, wallet.network, now)",
        "count_open_tango_offers_for_address(",
        "board.MAX_OPEN_PER_ADDRESS",
        "sp_address=wallet.sp_address",
    ):
        assert needle in post, needle
    refusal = _fn(VIEWS, "_board_refusal")
    for needle in ("tango_board_enabled", "is_banned_from_board(user_id)", "suspended_for("):
        assert needle in refusal, needle


def test_the_listing_says_whether_you_may_post_and_how_long_to_wait():
    body = _fn(VIEWS, "api_tango_offers")
    for key in ("enabled", "suspended_for", "can_post", "answer_seconds"):
        assert f'"{key}"' in body, key
    # A switched-off board lists nothing to take, and still lists your own so
    # you can withdraw them.
    assert '"offers": others if enabled else []' in body


def test_a_switched_off_board_cannot_be_answered():
    body = _fn(VIEWS, "_tango_check_board_proposal")
    assert "tango_board_enabled" in body
    assert "raise gone" in body[body.index("tango_board_enabled"):][:200]


def test_the_operator_endpoints_are_admin_only_and_remove_what_waits():
    for fn in ("api_admin_tango_offers", "api_admin_tango_offer_remove",
               "api_admin_tango_board_ban"):
        assert "require_admin(key_info)" in _fn(VIEWS, fn), fn
    assert "reason=OFFER_WITHDRAWN" in _fn(VIEWS, "api_admin_tango_offer_remove")
    ban = _fn(VIEWS, "api_admin_tango_board_ban")
    assert "ban_from_board(" in ban and "unban_from_board(" in ban
    # Banning takes down what they have up, on every network.
    assert "_close_tango_offer(o[\"id\"]" in ban


def test_the_board_switch_is_a_per_network_setting_that_defaults_on():
    assert re.search(r"tango_board_enabled: bool = True", MODELS)
    assert "class BoardBanData" in MODELS


def test_the_second_migration_adds_the_address_the_strikes_and_the_bans():
    body = MIG[MIG.index("async def m048_tango_board_abuse"):]
    for needle in ("ADD COLUMN IF NOT EXISTS sp_address TEXT",
                   "silnt.tango_board_strikes", "silnt.tango_board_bans"):
        assert needle in body, needle
    assert "created_at" not in body.split('"""')[2]


def test_account_deletion_takes_the_strikes_and_the_ban_too():
    assert "DELETE FROM silnt.tango_board_strikes WHERE user_id = :uid" in CRUD
    assert "DELETE FROM silnt.tango_board_bans WHERE user_id = :uid" in CRUD


# ── an offer is not just "there" or "gone": its state is shown ───────────────


def test_the_board_lists_which_proposals_are_still_waiting():
    ns, db = _crud()
    for rid, status, offer, taker in [
        ("r1", "PROPOSED", "o1", "t1"),
        ("r2", "PROPOSED", "o1", "t2"),
        ("r3", "ACCEPTED", "o1", "t3"),      # answered: not waiting
        ("r4", "CANCELLED", "o2", "t1"),     # over: not waiting
        ("r5", "PROPOSED", None, "t1"),      # an ordinary round, not the board
    ]:
        db.c.execute("INSERT INTO silnt.tango_rounds VALUES (?,?,?,?)",
                     (rid, status, taker, offer))
    got = run(ns["list_waiting_board_proposals"]())
    assert sorted((g["offer_id"], g["a_user_id"]) for g in got) == [("o1", "t1"), ("o1", "t2")]


def test_the_makers_view_counts_waiting_and_everyone_elses_only_says_busy():
    view = _fn(VIEWS, "_offer_view")
    # The maker is told how many; a proposer is told it is theirs; strangers get
    # a yes/no and never a count of who is asking.
    assert '{"waiting": int(waiting)}' in view
    assert '"busy": int(waiting) >= MAX_PROPOSALS_PER_OFFER' in view
    assert '"proposed_by_me": bool(proposed_by_me)' in view
    # `waiting` is only ever emitted on the maker's own view.
    assert view.count('"waiting"') == 1


def test_the_listing_fills_in_that_state_from_one_query():
    body = _fn(VIEWS, "api_tango_offers")
    assert "list_waiting_board_proposals()" in body
    assert "proposed_by_me" in body and "waiting=waiting.get(o[\"id\"], 0)" in body


def test_one_person_cannot_hold_two_of_an_offers_places():
    body = _fn(VIEWS, "_tango_check_board_proposal")
    assert "any(r.a_user_id == uid for r in waiting_here)" in body
    assert "You already proposed to this offer" in body
    # Checked BEFORE the cap, or a full offer would tell you it was full when the
    # truth is that one of the places is yours.
    assert body.index("any(r.a_user_id == uid") < body.index("MAX_PROPOSALS_PER_OFFER:")
