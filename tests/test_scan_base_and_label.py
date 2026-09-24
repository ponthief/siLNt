"""One transaction paying our base address AND a labelled address of ours.

THE SHAPE THAT WAS INVISIBLE. BIP-352's scanning algorithm keeps one counter:
compute P_k = B_spend + t_k*G, look for it, accept a plain match or one whose
difference from P_k is a label, and on a hit increment k and go round again.
Correct whenever a sender pays one address of ours twice — the second payment
is k=1 of the same chain, which is the case it was written for.

It loses an output when one transaction pays our base address and a labelled
address of ours. Those are different spend keys, so BOTH are k=0, and a single
counter can only take one: the first hit consumes k=0 and every later pass
looks for k=1, which neither output is.

A Tango pays each side exactly that pair — the mixed share to the base address,
the change to the m=0 change label. Each side saw one of its two coins and the
other was simply absent from the wallet.

WHY THE EXISTING CORPUS COULD NOT CATCH IT. test_reverse_matching builds its
transactions with `for k, m in enumerate(ours)`, so every output to us gets its
own k. It covers "mixed labels within a transaction" and still could not
express two outputs at the same k, which is the only shape that fails. The same
lesson as the palindromic txids in test_payjoin_sp_assembly: a corpus that
cannot distinguish two behaviours is not testing the one it names.
"""

from __future__ import annotations

from coincurve import PublicKey
from conftest import scan

SCAN_SECRET = bytes.fromhex(
    "0303030303030303030303030303030303030303030303030303030303030303"
)
SPEND_SECRET = bytes.fromhex(
    "0404040404040404040404040404040404040404040404040404040404040404"
)
SPEND_PUB = PublicKey.from_secret(SPEND_SECRET).format(compressed=True)

LABELS = scan.create_labels(SCAN_SECRET, indices=[])
LABEL_BY_M = {lab.m: lab for lab in LABELS}
CHANGE_M = scan.BIP352_CHANGE_LABEL_INDEX


def tweak_and_secret():
    """A sender's input-derived tweak, and the shared secret it gives us."""
    tweak = PublicKey.from_secret(bytes([7]) * 32).format(compressed=True)
    return tweak, scan.create_shared_secret(tweak, SCAN_SECRET)


def p_k(shared: bytes, k: int) -> bytes:
    """The true P_k, compressed, with its real parity — the sender's view."""
    _opk, t_k = scan.create_output_pub_key_and_tweak(shared, SPEND_PUB, k)
    return (
        PublicKey(SPEND_PUB)
        .combine([PublicKey.from_secret(t_k)])
        .format(compressed=True)
    )


def labelled(point33: bytes, m: int) -> bytes:
    return (
        PublicKey(point33)
        .combine([PublicKey(LABEL_BY_M[m].pub_key)])
        .format(compressed=True)
    )


def decoy(seed: int) -> bytes:
    return PublicKey.from_secret(bytes([seed]) * 32).format(compressed=True)[1:]


def scan_outputs(outputs: list):
    _tweak, shared = tweak_and_secret()
    return scan.receiver_scan_transaction_with_shared_secret(
        SCAN_SECRET, SPEND_PUB, LABELS, outputs, shared
    )


def test_a_tango_pays_us_a_share_and_change_and_we_find_both():
    """The exact derivation both clients use: share on the base address at k=0,
    change on the m=0 label at k=0."""
    _tweak, shared = tweak_and_secret()
    share = p_k(shared, 0)[1:]
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]

    found = scan_outputs([change, decoy(11), share, decoy(12)])

    keys = {fo.output for fo in found}
    assert share in keys, "the mixed share was not found"
    assert change in keys, "the change was not found"
    assert len(found) == 2, [fo.output.hex() for fo in found]


def test_the_change_is_reported_as_change():
    """Its m has to survive, or the wallet cannot tell a share from change and
    the send guard has nothing to refuse on."""
    _tweak, shared = tweak_and_secret()
    share = p_k(shared, 0)[1:]
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]

    by_key = {fo.output: fo for fo in scan_outputs([share, change])}
    assert by_key[share].label is None
    assert by_key[change].label is not None
    assert by_key[change].label.m == CHANGE_M


def test_output_order_does_not_decide_which_one_survives():
    """The bug's signature was that each wallet kept whichever of its two coins
    came first in the transaction. Both orders must now give both coins."""
    _tweak, shared = tweak_and_secret()
    share = p_k(shared, 0)[1:]
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]

    for outputs in ([share, change], [change, share]):
        keys = {fo.output for fo in scan_outputs(outputs)}
        assert keys == {share, change}, outputs


def test_two_different_labels_at_the_same_k_are_both_found():
    """Not a shape our senders produce, but the same defect: m=0 and m=2 are
    two spend keys, so a sender paying both uses k=0 twice."""
    _tweak, shared = tweak_and_secret()
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]
    other = labelled(p_k(shared, 0), 2)[1:]

    found = scan_outputs([change, other])
    assert {fo.output for fo in found} == {change, other}
    assert {fo.label.m for fo in found} == {CHANGE_M, 2}


def test_the_plain_chain_still_counts_up_past_k_zero():
    """The case the single counter was written for must keep working: one
    sender paying our base address three times uses k = 0, 1, 2."""
    _tweak, shared = tweak_and_secret()
    outs = [p_k(shared, k)[1:] for k in range(3)]

    found = scan_outputs([*outs, decoy(21)])
    assert {fo.output for fo in found} == set(outs)
    assert all(fo.label is None for fo in found)


def test_a_label_chain_counts_up_too():
    """Two payments to the SAME labelled address are k=0 and k=1 of that
    chain."""
    _tweak, shared = tweak_and_secret()
    outs = [labelled(p_k(shared, k), CHANGE_M)[1:] for k in range(2)]

    found = scan_outputs(outs)
    assert {fo.output for fo in found} == set(outs)
    assert all(fo.label.m == CHANGE_M for fo in found)


def test_a_transaction_of_somebody_elses_finds_nothing():
    assert scan_outputs([decoy(31), decoy(32), decoy(33)]) == []


def test_no_output_is_claimed_twice():
    """Each chain scans what is left, so one output cannot satisfy two chains
    — which would double a balance."""
    _tweak, shared = tweak_and_secret()
    share = p_k(shared, 0)[1:]
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]

    found = scan_outputs([share, change])
    assert len({fo.output for fo in found}) == len(found)


def test_the_key_tweak_spends_what_it_is_paired_with():
    """A found output is only money if its tweak really unlocks it: the label's
    tweak has to be added for a labelled one and left out for a plain one, and
    getting that backwards would look like a successful scan."""
    _tweak, shared = tweak_and_secret()
    share = p_k(shared, 0)[1:]
    change = labelled(p_k(shared, 0), CHANGE_M)[1:]

    for fo in scan_outputs([share, change]):
        secret = (
            int.from_bytes(SPEND_SECRET, "big")
            + int.from_bytes(fo.sec_key_tweak, "big")
        ) % scan.SECP256K1_N
        derived = PublicKey.from_secret(
            secret.to_bytes(32, "big")
        ).format(compressed=True)[1:]
        assert derived == fo.output, (
            f"tweak does not spend {fo.output.hex()} (label="
            f"{None if fo.label is None else fo.label.m})"
        )
