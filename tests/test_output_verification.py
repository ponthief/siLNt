"""Is a detected Silent Payment output actually verified?

test_reverse_matching.py already proves the two matchers agree with each other.
Agreement is not correctness: both could be wrong the same way. These tests ask
different questions.

1. SPENDABILITY. For every output the scanner claims, does the recorded
   priv_key_tweak actually produce the key it recorded? b_spend + tweak must
   equal the output's key, or the wallet has found money it cannot move. This is
   checked with the spend SECRET, which the scanner never sees — so it is an
   independent check, not a restatement of the derivation.

2. WHAT IS TRUSTED. Which fields does the scanner verify cryptographically, and
   which does it copy from the oracle's answer? A wallet's threat model depends
   on knowing the difference.
"""

from __future__ import annotations

import random

import pytest
from coincurve import PublicKey
from conftest import scan

from test_reverse_matching import (
    LABEL_BY_M,
    LABELS,
    SCAN_SECRET,
    SPEND_PUB,
    SPEND_SECRET,
    build_tx,
)


def _spend_key_matches(owned) -> bool:
    """Can b_spend + priv_key_tweak actually spend this output?

    The scanner only ever has the scan secret and the spend PUBLIC key. Adding
    the tweak to the spend SECRET here is the receiver's real spending path, so
    if the x-coordinate comes out equal to the key the scanner recorded, the
    output is genuinely spendable.
    """
    full = scan.add_private_keys(SPEND_SECRET, owned.priv_key_tweak)
    derived = PublicKey.from_secret(full).format(compressed=True)[1:]
    return derived == owned.pub_key


def _block(rng, txs):
    """Turn (tweak, outputs) pairs into the oracle's two answers for a block."""
    tweaks, utxos = [], []
    for i, (tweak, outs) in enumerate(txs):
        tweaks.append(tweak.hex())
        txid = bytes([i + 1]) * 32
        for vout, opk in enumerate(outs):
            utxos.append({
                "txid": txid.hex(), "vout": vout, "amount": 1000 + vout,
                "pubkey": opk.hex(), "timestamp": 111,
            })
    return tweaks, utxos


# ── 1. every claimed output must be spendable ────────────────────────────────

@pytest.mark.parametrize("m", [None, 0, 1, 2, 3])
def test_claimed_output_is_spendable(m):
    """A payment to the base address and to each label in the production set."""
    rng = random.Random(1000 + (m if m is not None else 99))
    tweak, outs = build_tx(rng, ours=[m], n_decoys=3)
    tweaks, utxos = _block(rng, [(tweak, outs)])

    owned = scan.sync_block(tweaks, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    assert len(owned) == 1, f"m={m}: expected exactly one owned output"
    assert _spend_key_matches(owned[0]), (
        f"m={m}: DETECTED BUT NOT SPENDABLE — the recorded tweak does not "
        f"produce the recorded key"
    )


def test_every_claimed_output_is_spendable_over_random_blocks():
    """The same question over a randomised corpus, for both matchers.

    Covers k>0 (several outputs to us in one transaction), mixed labels, decoys
    and transactions that are nobody's.
    """
    rng = random.Random(4242)
    checked = 0
    for _ in range(40):
        txs = []
        for _ in range(rng.randrange(1, 4)):
            n_ours = rng.randrange(0, 3)
            ours = [rng.choice([None, 0, 1, 2, 3]) for _ in range(n_ours)]
            txs.append(build_tx(rng, ours=ours, n_decoys=rng.randrange(0, 3)))
        tweaks, utxos = _block(rng, txs)

        fwd = scan.sync_block(tweaks, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
        index = [
            {"txid": bytes([i + 1]).hex() * 32, "tweak": tw.hex()}
            for i, (tw, _) in enumerate(txs)
        ]
        rev = scan.sync_block_reverse(index, utxos, SCAN_SECRET, SPEND_PUB, LABELS)

        for name, result in (("forward", fwd), ("reverse", rev)):
            for o in result:
                assert _spend_key_matches(o), (
                    f"{name} matcher: detected {o.pub_key.hex()[:16]} but "
                    f"b_spend + tweak does not produce it"
                )
                checked += 1
    assert checked > 40, f"corpus too thin to mean anything ({checked} outputs)"


# ── 2. what the scanner verifies vs what it copies ───────────────────────────

def test_output_key_is_verified_not_trusted():
    """An oracle cannot put a UTXO in the wallet by asserting one.

    Pair a real tweak with an output key that is nobody's. The scanner derives
    candidate keys itself, so nothing matches and nothing is claimed.
    """
    rng = random.Random(7)
    tweak, _outs = build_tx(rng, ours=[None], n_decoys=0)
    forged = PublicKey.from_secret(bytes([9]) * 32).format(compressed=True)[1:]
    utxos = [{
        "txid": "11" * 32, "vout": 0, "amount": 100_000_000,
        "pubkey": forged.hex(), "timestamp": 1,
    }]
    owned = scan.sync_block([tweak.hex()], utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    assert owned == [], "a key the wallet never derived was accepted as owned"


def test_amount_txid_and_vout_come_from_the_oracle_verbatim():
    """These three fields are NOT verified — this pins that down.

    The output key is cryptographic, so the oracle cannot invent an owned
    output. But once an output IS ours, its amount, txid and vout are whatever
    the oracle said. Nothing in the scan path cross-checks them against a second
    source, so this asserts the current, trusting behaviour rather than
    pretending otherwise: if a future change starts verifying them, this test
    should fail and be rewritten.
    """
    rng = random.Random(11)
    tweak, outs = build_tx(rng, ours=[None], n_decoys=0)
    ours = outs[0]

    utxos = [{
        "txid": "ab" * 32,          # not a real transaction
        "vout": 7,                  # an arbitrary position
        "amount": 2_100_000_000_000,  # more than exists
        "pubkey": ours.hex(),
        "timestamp": 1,
    }]
    owned = scan.sync_block([tweak.hex()], utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    assert len(owned) == 1
    o = owned[0]
    assert o.txid.hex() == "ab" * 32
    assert o.vout == 7
    assert o.amount == 2_100_000_000_000
    # ...while the key it recorded is the one it derived, not merely echoed.
    assert _spend_key_matches(o)


# ── 3. the opt-in compute-index matcher ──────────────────────────────────────

def _shorts(outs):
    """The oracle's compute-index `outputs`: 8-byte key prefixes as hex."""
    return [o.hex()[:16] for o in outs]


def test_compute_index_matcher_finds_a_plain_payment():
    """Baseline: the path does work for an unlabeled payment."""
    rng = random.Random(21)
    tweak, outs = build_tx(rng, ours=[None], n_decoys=2)
    index = [{"txid": "11" * 32, "tweak": tweak.hex(), "outputs": _shorts(outs)}]
    owned = scan.sync_block_from_compute_index(index, SCAN_SECRET, SPEND_PUB, LABELS)
    assert len(owned) == 1


@pytest.mark.parametrize("m", [0, 1, 2, 3])
def test_compute_index_matcher_loses_labeled_payments(m):
    """Roughly half of labeled payments are invisible to this path.

    _tx_has_candidate's docstring says so outright: it tests one sign of the
    label only, and where the true P_0 is odd the scanner's even-forced
    reconstruction needs the other sign. Whether a given payment survives is
    decided by a parity nobody controls, so this walks a range of payments and
    asserts the path misses some — the point being that it is lossy, not that a
    particular one fails.
    """
    misses = 0
    total = 0
    for seed in range(40):
        rng = random.Random(9000 + seed * 7 + m)
        tweak, outs = build_tx(rng, ours=[m], n_decoys=1)
        index = [{"txid": "11" * 32, "tweak": tweak.hex(), "outputs": _shorts(outs)}]
        got = scan.sync_block_from_compute_index(
            index, SCAN_SECRET, SPEND_PUB, LABELS
        )
        total += 1
        if not got:
            misses += 1
    assert misses > 0, (
        f"m={m}: expected this path to lose some labeled payments; it found all "
        f"{total}. If the one-sign bug has been fixed, delete this test."
    )


def test_compute_index_matcher_fabricates_vout_and_amount():
    """What it does claim, it claims with vout 0 and amount 0.

    _scan_block_compute_index patches both afterwards from a /utxos fetch, but
    only `if full:` — when the lookup misses, an output enters the wallet with a
    zero amount and a vout pointing at the wrong place in the transaction.
    """
    rng = random.Random(33)
    tweak, outs = build_tx(rng, ours=[None], n_decoys=0)
    index = [{"txid": "11" * 32, "tweak": tweak.hex(), "outputs": _shorts(outs)}]
    owned = scan.sync_block_from_compute_index(index, SCAN_SECRET, SPEND_PUB, LABELS)
    assert len(owned) == 1
    assert owned[0].vout == 0
    assert owned[0].amount == 0
