"""
How big a transaction actually is, in one place.

The fee formula lived in four copies and one of them was wrong. wallet.py's
Silent Payments builder used

    vsize = 10 + 57.5 * inputs + 31 * 2

and 31 vB is a P2WPKH output — 8 value + 1 length + 22 script. Every output it
was sizing is P2TR, which is 43 vB, so a two-output send was short by 25 vB.
Nobody lost money; the transaction simply paid a lower rate than the user chose,
about 16% under at any rate, which during congestion is the difference between
hitting the block target they picked and not.

plain.py already had this right. These are its constants, moved somewhere both
builders can reach — plain.py imports wallet.py, so wallet.py cannot import
plain.py, and a third module is how the two stop disagreeing.

Every figure below is checked against real serialised transactions in
tests/test_txsize.py rather than derived on paper.
"""

from __future__ import annotations

import math

# nVersion (4) + nLockTime (4) + input count (1) + output count (1) = 10 base
# bytes at weight 4, plus the segwit marker and flag at weight 1 each:
#   (10 * 4 + 2) / 4 = 10.5
OVERHEAD_VBYTES = 10.5

# P2TR key-path input: 41 base bytes (36 outpoint + 1 empty scriptSig length +
# 4 sequence) and a 66-byte witness (1 item + 1 length + 64 signature).
#   (41 * 4 + 66) / 4 = 57.5
TAPROOT_INPUT_VBYTES = 57.5

# P2WPKH input: the same 41 base bytes with a 108-byte witness (1 item count +
# 1 + 72 signature + 1 + 33 pubkey).
#   (41 * 4 + 108) / 4 = 68
P2WPKH_INPUT_VBYTES = 68

# One output is 8 value bytes + 1 length byte + the script, all at weight 4, so
# vbytes == bytes. Keyed by script length because that is what the caller has.
_OUTPUT_VBYTES_BY_SCRIPT_LEN = {
    22: 31,  # P2WPKH   OP_0 <20>
    23: 32,  # P2SH     OP_HASH160 <20> OP_EQUAL
    25: 34,  # P2PKH    OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    34: 43,  # P2TR / P2WSH   OP_1 <32> / OP_0 <32>
}

# A Silent Payments output — the recipient's and the m=0 change alike — is
# always P2TR.
TAPROOT_OUTPUT_VBYTES = 43
P2WPKH_OUTPUT_VBYTES = 31


def output_vbytes(script_pubkey: bytes) -> int:
    """Serialized vbytes for an output with this scriptPubKey."""
    return _OUTPUT_VBYTES_BY_SCRIPT_LEN.get(
        len(script_pubkey), 8 + 1 + len(script_pubkey)
    )


def estimate_vsize(
    n_taproot_inputs: int,
    output_sizes: list[int],
    n_p2wpkh_inputs: int = 0,
) -> int:
    """Virtual size of a transaction with these inputs and outputs.

    Rounded up, because a fee is charged on whole vbytes and rounding down is
    how a transaction ends up a satoshi under the rate it quoted.
    """
    return math.ceil(
        OVERHEAD_VBYTES
        + TAPROOT_INPUT_VBYTES * n_taproot_inputs
        + P2WPKH_INPUT_VBYTES * n_p2wpkh_inputs
        + sum(output_sizes)
    )


def fee_for(vsize: int, fee_rate: float) -> int:
    """At least one satoshi, however small the transaction or the rate."""
    return max(1, math.ceil(vsize * fee_rate))
