"""The guards /tx/prepare and /tx/build now share.

Extracting them was the point: a check that exists twice eventually differs in
one place, and the one that would drift here decides whether a payment reaches
the recipient or whoever altered a DNS record. These tests hold the extracted
versions to the behaviour the inline copies had.

The DNS and database layers are injected rather than reached, so this says
nothing about whether DNS works — test_bitmail_errors.py covers that — and
everything about which conditions block a send.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PKG = ROOT.name


def _load_guards():
    """Load helpers/send_guards.py with its crud and DNS dependencies stubbed.

    It imports from ..crud, which reaches LNbits, so the package and that module
    are stood up here the way conftest does it for scan.py.
    """
    name = f"{PKG}.helpers.send_guards"
    if name in sys.modules:
        return sys.modules[name]

    for m in ("lnbits", "lnbits.utils", "lnbits.utils.crypto"):
        sys.modules.setdefault(m, types.ModuleType(m))
    if not hasattr(sys.modules["lnbits.utils.crypto"], "AESCipher"):
        sys.modules["lnbits.utils.crypto"].AESCipher = object

    crud = sys.modules.get(f"{PKG}.crud") or types.ModuleType(f"{PKG}.crud")
    crud.get_eligible_utxos = None          # each test injects its own
    crud.get_cloudflare_config = None
    crud.get_issued_bitmail_sp_address = None
    crud.create_admin_alert = None
    crud.send_ntfy_notification = None
    sys.modules[f"{PKG}.crud"] = crud

    spec = importlib.util.spec_from_file_location(
        name, ROOT / "helpers" / "send_guards.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


g = _load_guards()
HTTPException = g.HTTPException


def _rows(*pairs):
    return [
        {"txid": t, "vout": v, "amount": 10_000,
         "priv_key_tweak": "aa" * 32, "pub_key": "bb" * 32}
        for t, v in pairs
    ]


# ── which coins may be spent ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_eligible_coins_come_back_with_their_keys():
    """/tx/prepare hands the client the database's view of each coin, so the
    query has to return the fields the client needs to sign."""
    async def fake(wallet_id, txid_vout_pairs):
        return _rows(("11" * 32, 0), ("22" * 32, 1))

    g.get_eligible_utxos = fake
    out = await g.validate_spendable_utxos(
        "w", [{"txid": "11" * 32, "vout": 0}, {"txid": "22" * 32, "vout": 1}], False
    )
    assert len(out) == 2
    for r in out:
        assert {"txid", "vout", "amount", "priv_key_tweak", "pub_key"} <= set(r)


@pytest.mark.asyncio
async def test_a_frozen_or_spent_coin_is_refused():
    """Anything the query does not return was frozen, spent or another
    wallet's. The message names the outpoint rather than failing vaguely."""
    async def fake(wallet_id, txid_vout_pairs):
        return _rows(("11" * 32, 0))        # the second one is not eligible

    g.get_eligible_utxos = fake
    with pytest.raises(HTTPException) as e:
        await g.validate_spendable_utxos(
            "w", [{"txid": "11" * 32, "vout": 0}, {"txid": "33" * 32, "vout": 2}], False
        )
    assert "33333333333" in e.value.detail
    assert "frozen" in e.value.detail


@pytest.mark.asyncio
async def test_a_scan_in_progress_says_so_instead():
    """Same refusal, different cause: mid-scan the state genuinely just moved,
    and telling someone their coin is frozen would send them to unfreeze a coin
    that is not frozen."""
    async def fake(wallet_id, txid_vout_pairs):
        return []

    g.get_eligible_utxos = fake
    with pytest.raises(HTTPException) as e:
        await g.validate_spendable_utxos("w", [{"txid": "11" * 32, "vout": 0}], True)
    assert "scan is in progress" in e.value.detail
    assert "frozen" not in e.value.detail


@pytest.mark.asyncio
async def test_an_empty_selection_is_refused():
    with pytest.raises(HTTPException, match="No UTXOs"):
        await g.validate_spendable_utxos("w", [], False)


# ── the BitMail tampering guard ──────────────────────────────────────────────

def _dns(result: str):
    def fake(address):
        return {"result": result}
    return fake


@pytest.mark.asyncio
async def test_a_plain_address_passes_through_untouched():
    """No @ means no lookup — and no chance for a DNS failure to block a send
    that never needed DNS."""
    g.bip353_resolve = _dns("should not be called")
    for addr in ("sp1qqtest", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"):
        assert await g.resolve_recipient(addr) == addr


@pytest.mark.asyncio
async def test_a_bitmail_resolves_to_its_sp_address():
    g.bip353_resolve = _dns("bitcoin:?sp=sp1qqresolved")

    async def no_cf():
        raise RuntimeError("no cloudflare configured")

    g.get_cloudflare_config = no_cf
    assert await g.resolve_recipient("alice@example.com") == "sp1qqresolved"


@pytest.mark.asyncio
async def test_a_record_that_is_not_a_silent_payment_is_refused():
    g.bip353_resolve = _dns("bitcoin:?lno=lno1zzz")

    async def no_cf():
        raise RuntimeError("no cloudflare configured")

    g.get_cloudflare_config = no_cf
    with pytest.raises(HTTPException, match="Silent Payment"):
        await g.resolve_recipient("alice@example.com")


@pytest.mark.asyncio
async def test_a_tampered_bitmail_on_our_own_domain_blocks_the_send():
    """The case the guard exists for: a name WE issued now resolves somewhere
    else, which means the TXT record was altered to redirect funds."""
    g.bip353_resolve = _dns("bitcoin:?sp=sp1qqATTACKER")
    alerts, pushes = [], []

    class CF:
        domain = "whispawallet.com"

    async def cf():
        return CF()

    async def issued(user):
        return "sp1qqREAL"

    async def alert(**kw):
        alerts.append(kw)

    async def ntfy(**kw):
        pushes.append(kw)

    g.get_cloudflare_config = cf
    g.get_issued_bitmail_sp_address = issued
    g.create_admin_alert = alert
    g.send_ntfy_notification = ntfy

    with pytest.raises(HTTPException) as e:
        await g.resolve_recipient("bob@whispawallet.com")

    assert "does not match what was registered" in e.value.detail
    assert "Do not retry" in e.value.detail
    # The attacker's address must not be echoed to the payer, who might copy it.
    assert "ATTACKER" not in e.value.detail
    assert len(alerts) == 1 and alerts[0]["severity"] == "critical"
    assert len(pushes) == 1 and pushes[0]["priority"] == "urgent"


@pytest.mark.asyncio
async def test_the_block_survives_a_broken_alerting_path():
    """Recording the alert and sending the push are best-effort. Neither
    failing may turn a blocked send into an allowed one."""
    g.bip353_resolve = _dns("bitcoin:?sp=sp1qqATTACKER")

    class CF:
        domain = "whispawallet.com"

    async def cf():
        return CF()

    async def issued(user):
        return "sp1qqREAL"

    async def boom(**kw):
        raise RuntimeError("alerting is down")

    g.get_cloudflare_config = cf
    g.get_issued_bitmail_sp_address = issued
    g.create_admin_alert = boom
    g.send_ntfy_notification = boom

    with pytest.raises(HTTPException, match="does not match"):
        await g.resolve_recipient("bob@whispawallet.com")


@pytest.mark.asyncio
async def test_a_bitmail_on_another_domain_is_not_second_guessed():
    """We only hold records for names we issued. A name on someone else's
    domain resolves and is used — blocking it would be claiming knowledge we
    do not have."""
    g.bip353_resolve = _dns("bitcoin:?sp=sp1qqelsewhere")

    class CF:
        domain = "whispawallet.com"

    async def cf():
        return CF()

    async def issued(user):
        raise AssertionError("must not be consulted for another domain")

    g.get_cloudflare_config = cf
    g.get_issued_bitmail_sp_address = issued
    assert await g.resolve_recipient("bob@someoneelse.net") == "sp1qqelsewhere"
