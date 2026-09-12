"""sync_block_reverse must find exactly what sync_block finds.

This is the only thing that makes the reverse matcher safe to run. It is faster
because it tests a tweak against its own transaction's outputs instead of
enumerating every output the tweak could produce — but "faster" is worthless
here unless it is also "identical", and identical has to mean the same UTXOs
with the same amounts, vouts, key tweaks and labels, not merely the same count.

The corpus is randomised and covers what the forward matcher has to cope with:
plain payments, payments to each label, several outputs to us in one
transaction (k > 0), mixed labels within a transaction, decoy outputs belonging
to other people, and transactions that are entirely somebody else's.
"""

from __future__ import annotations

import random

import pytest
from coincurve import PublicKey
from conftest import scan

SCAN_SECRET = bytes.fromhex(
    "0101010101010101010101010101010101010101010101010101010101010101"
)
SPEND_SECRET = bytes.fromhex(
    "0202020202020202020202020202020202020202020202020202020202020202"
)
SPEND_PUB = PublicKey.from_secret(SPEND_SECRET).format(compressed=True)

# The production label set: change at m=0, legacy change at m=1, labeled
# addresses at m=2 and m=3.
LABELS = scan.create_labels(SCAN_SECRET, indices=[])
LABEL_BY_M = {lab.m: lab for lab in LABELS}


def _rand_pubkey(rng: random.Random) -> bytes:
    """An x-only key belonging to nobody."""
    secret = bytes(rng.randrange(1, 255) for _ in range(32))
    return PublicKey.from_secret(secret).format(compressed=True)[1:]


def build_tx(rng: random.Random, ours: list, n_decoys: int):
    """One transaction. `ours` is a list of label m (or None for plain) per output.

    Returns (tweak, outputs) with the outputs shuffled, so the matcher cannot
    rely on ours coming first.
    """
    secret = bytes(rng.randrange(1, 255) for _ in range(32))
    tweak = PublicKey.from_secret(secret).format(compressed=True)
    shared = scan.create_shared_secret(tweak, SCAN_SECRET)

    outputs = []
    for k, m in enumerate(ours):
        _opk, t_k = scan.create_output_pub_key_and_tweak(shared, SPEND_PUB, k)
        # The true P_k, with its real parity — the sender's view.
        p_k = (
            PublicKey(SPEND_PUB)
            .combine([PublicKey.from_secret(t_k)])
            .format(compressed=True)
        )
        if m is None:
            outputs.append(p_k[1:])
        else:
            labeled = (
                PublicKey(p_k)
                .combine([PublicKey(LABEL_BY_M[m].pub_key)])
                .format(compressed=True)
            )
            outputs.append(labeled[1:])

    for _ in range(n_decoys):
        outputs.append(_rand_pubkey(rng))

    rng.shuffle(outputs)
    return tweak, outputs


def build_block(rng: random.Random, txs: list):
    """Assemble a block. `txs` is a list of (ours, n_decoys) specs.

    Returns (tweaks, compute_index, utxos) — the two shapes the two matchers
    take, built from one underlying truth.
    """
    tweaks = []
    compute_index = []
    utxos = []

    for i, (ours, n_decoys) in enumerate(txs):
        tweak, outputs = build_tx(rng, ours, n_decoys)
        txid = bytes([i + 1]) * 32
        tweaks.append(tweak)
        compute_index.append(
            {
                "txid": txid.hex(),
                "tweak": tweak.hex(),
                # Real shape, though sync_block_reverse ignores it.
                "outputs": [o.hex()[:16] for o in outputs],
            }
        )
        for vout, out in enumerate(outputs):
            utxos.append(
                {
                    "txid": txid.hex(),
                    "vout": vout,
                    "amount": 1000 + i * 100 + vout,
                    "pubkey": out.hex(),
                    "timestamp": 1_700_000_000 + i,
                }
            )

    return tweaks, compute_index, utxos


def fingerprint(owned):
    """Everything that must agree, as a comparable set."""
    return sorted(
        (
            o.txid.hex(),
            o.vout,
            o.amount,
            o.pub_key.hex(),
            o.priv_key_tweak.hex(),
            o.label.m if o.label else None,
            o.timestamp,
        )
        for o in owned
    )


def assert_identical(tweaks, compute_index, utxos, note=""):
    forward = scan.sync_block(tweaks, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    reverse = scan.sync_block_reverse(
        compute_index, utxos, SCAN_SECRET, SPEND_PUB, LABELS
    )
    fwd, rev = fingerprint(forward), fingerprint(reverse)
    assert rev == fwd, (
        f"{note}\nforward found {len(fwd)}, reverse found {len(rev)}\n"
        f"only forward: {[x for x in fwd if x not in rev]}\n"
        f"only reverse: {[x for x in rev if x not in fwd]}"
    )
    return fwd


# --- targeted cases ---------------------------------------------------------


@pytest.mark.parametrize("m", [None, 0, 1, 2, 3])
def test_single_payment_each_label(m):
    """Plain, and each label in the production set."""
    found_any = False
    for seed in range(12):
        rng = random.Random(seed)
        tweaks, ci, utxos = build_block(rng, [([m], 2)])
        found = assert_identical(tweaks, ci, utxos, note=f"label m={m} seed={seed}")
        found_any = found_any or bool(found)
    assert found_any, f"no payment with m={m} was detected at all; test is vacuous"


def test_multiple_outputs_to_us_in_one_tx():
    """k > 0: the same recipient paid several times in one transaction."""
    for seed in range(10):
        rng = random.Random(1000 + seed)
        tweaks, ci, utxos = build_block(rng, [([None, None, None], 2)])
        found = assert_identical(tweaks, ci, utxos, note=f"k>0 seed={seed}")
        assert len(found) == 3, f"expected 3 outputs, got {len(found)}"


def test_mixed_labels_in_one_tx():
    for seed in range(10):
        rng = random.Random(2000 + seed)
        tweaks, ci, utxos = build_block(rng, [([None, 0, 2], 1)])
        assert_identical(tweaks, ci, utxos, note=f"mixed labels seed={seed}")


def test_block_with_nothing_for_us():
    for seed in range(10):
        rng = random.Random(3000 + seed)
        tweaks, ci, utxos = build_block(rng, [([], 3), ([], 2), ([], 4)])
        found = assert_identical(tweaks, ci, utxos, note=f"decoys seed={seed}")
        assert found == [], "matched an output belonging to nobody"


def test_empty_inputs():
    assert scan.sync_block_reverse([], [], SCAN_SECRET, SPEND_PUB, LABELS) == []
    assert (
        scan.sync_block_reverse(
            [],
            [{"txid": "aa" * 32, "vout": 0, "amount": 1, "pubkey": "bb" * 32}],
            SCAN_SECRET,
            SPEND_PUB,
            LABELS,
        )
        == []
    )


def test_no_labels_configured():
    """Degenerate but valid: with no labels only plain payments are findable."""
    rng = random.Random(4242)
    tweaks, ci, utxos = build_block(rng, [([None], 2)])
    forward = scan.sync_block(tweaks, utxos, SCAN_SECRET, SPEND_PUB, [])
    reverse = scan.sync_block_reverse(ci, utxos, SCAN_SECRET, SPEND_PUB, [])
    assert fingerprint(reverse) == fingerprint(forward)
    assert len(reverse) == 1


def test_compute_index_entry_with_no_matching_utxos():
    """A tweak whose transaction has no tracked outputs must not crash."""
    rng = random.Random(77)
    tweaks, ci, utxos = build_block(rng, [([None], 1)])
    ci.append({"txid": "ff" * 32, "tweak": ci[0]["tweak"], "outputs": []})
    assert_identical(tweaks, ci, utxos, note="orphan compute-index entry")


def test_malformed_entries_are_skipped():
    rng = random.Random(88)
    tweaks, ci, utxos = build_block(rng, [([None], 1)])
    expected = scan.sync_block(tweaks, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    ci = [
        *ci,
        {"txid": "", "tweak": "02" * 33},
        {"txid": "aa" * 32, "tweak": ""},
        {"txid": "bb" * 32, "tweak": "not-hex"},
        {},
    ]
    reverse = scan.sync_block_reverse(ci, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    assert fingerprint(reverse) == fingerprint(expected)


# --- the randomised sweep ---------------------------------------------------


def test_randomised_blocks_agree():
    """Many blocks of mixed shape. Both parities of P_0 occur throughout.

    This is the test that matters: the targeted cases above check situations
    someone thought of, and this one checks the ones nobody did.
    """
    rng = random.Random(0xBEEF)
    total_found = 0
    labeled_found = 0

    for block in range(120):
        n_txs = rng.randrange(1, 6)
        specs = []
        for _ in range(n_txs):
            if rng.random() < 0.45:
                n_ours = rng.randrange(1, 4)
                ours = [rng.choice([None, 0, 1, 2, 3]) for _ in range(n_ours)]
            else:
                ours = []
            specs.append((ours, rng.randrange(0, 4)))

        tweaks, ci, utxos = build_block(rng, specs)
        found = assert_identical(tweaks, ci, utxos, note=f"random block {block}")
        total_found += len(found)
        labeled_found += sum(1 for f in found if f[5] is not None)

    # The sweep has to actually exercise both kinds of detection.
    assert total_found > 100, f"only {total_found} payments across the sweep"
    assert labeled_found > 40, f"only {labeled_found} labeled payments; "
    "the label path is barely covered"


def test_filter_actually_filters(monkeypatch):
    """The correctness tests cannot see the speedup, so this does.

    A filter that returned True for everything would still be *correct* —
    extraction decides, not the filter — and every equality test above would
    still pass while the whole point of the change quietly evaporated. This
    counts how many transactions reach the expensive extraction.
    """
    calls = []
    real = scan.receiver_scan_transaction_with_shared_secret

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(scan, "receiver_scan_transaction_with_shared_secret", counting)

    rng = random.Random(31337)
    # 40 transactions, 4 of which pay us.
    specs = [([], 3) for _ in range(36)] + [([None], 2) for _ in range(4)]
    rng.shuffle(specs)
    _tweaks, ci, utxos = build_block(rng, specs)

    found = scan.sync_block_reverse(ci, utxos, SCAN_SECRET, SPEND_PUB, LABELS)

    assert len(found) == 4, f"expected 4 payments, got {len(found)}"
    assert len(calls) == 4, (
        f"extraction ran for {len(calls)} of {len(specs)} transactions; the "
        f"filter is letting non-candidates through and the saving is gone"
    )


def test_reverse_is_not_accidentally_matching_everything():
    """A sanity floor: a block of pure decoys must yield nothing.

    Without this, a matcher that returned every output would pass every
    equality check above only if forward did too — but a bug that over-matches
    would show up here.
    """
    rng = random.Random(999)
    tweaks, ci, utxos = build_block(rng, [([], 6) for _ in range(10)])
    reverse = scan.sync_block_reverse(ci, utxos, SCAN_SECRET, SPEND_PUB, LABELS)
    assert reverse == []
