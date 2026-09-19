"""
Silent Payments PayJoin — the two-party pieces, siLNt to siLNt.

helpers/payjoin_merge.py builds the OTHER PayJoin: imported descriptors,
P2WPKH, a PSBT that Sparrow signs. That one cannot carry Silent Payments,
because PSBT BIP32_DERIVATION is how the external signer recognises its inputs
and an SP UTXO has no derivation path — its key is a one-off from a tweak. So
this is a second implementation rather than a mode of the first, and both
parties are siLNt wallets.

WHY THIS IS POSSIBLE AT ALL. BIP-352's sender derivation is

    shared_secret = input_hash · a_sum · B_scan

summing the PRIVATE keys of every eligible input. In a PayJoin the inputs
belong to two people and neither can compute a_sum, which looks fatal and is:
derive from one party's inputs alone and the other's scanner never finds the
output. But the same secret is also

    shared_secret = input_hash · A_sum · b_scan

with A_sum the sum of the input PUBLIC keys — public once the inputs are
agreed. So each party derives its OWN outputs from its own scan key and a
public input set. No multi-party computation, no new cryptography.

helpers/_payjoin_sp_check.py is the spike that established this, including that
the production matcher in scan.py finds what this module builds.

WHAT THAT COSTS THE PROTOCOL. Every output depends on the whole input set, so
inputs must be frozen before any output is derived, and outputs must all exist
before anyone signs (a taproot key-path signature commits to every output).
That forces the order: commit inputs → both parties derive → both parties sign.
Adding an input afterwards invalidates every output in the transaction.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

import coincurve
from embit import ec
from embit.script import Script
from embit.transaction import TransactionOutput
from loguru import logger

from .curve import ser256
from .curve_native import point_add, point_mul, pubkey_point_gen_from_int
from .txsize import TAPROOT_OUTPUT_VBYTES, estimate_vsize, fee_for
from .wallet import (
    DUST_SATS,
    compressed_pubkey_to_point,
    tagged_hash,
)

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Sizes come from helpers/txsize.py, which is also what wallet.py uses, so the
# two builders cannot quote different fees for the same shape. This module had
# its own copies and inherited the P2WPKH-output bug along with them.


@dataclass
class PayjoinInput:
    """One contributed UTXO.

    `pub_key` is the 32-byte x-only key as it sits on chain, and is all that is
    needed to take part in the shared input set. `priv_key_tweak` is present
    only for inputs the caller can sign — the counterparty's tweak never leaves
    their side.
    """

    txid: str
    vout: int
    amount: int
    pub_key: bytes
    priv_key_tweak: Optional[bytes] = None

    @property
    def outpoint(self) -> bytes:
        """reversed_txid || vout_LE, the form BIP-352 orders and hashes."""
        return bytes.fromhex(self.txid)[::-1] + int(self.vout).to_bytes(4, "little")

    @property
    def script(self) -> bytes:
        return bytes([0x51, 0x20]) + self.pub_key


def canonical(inputs: list[PayjoinInput]) -> list[PayjoinInput]:
    """BIP-69 input order.

    Both parties must agree on one order before deriving anything, because the
    transaction they each sign has to be the same transaction. BIP-69 gives
    that without a negotiation round: it is a function of the outpoints, which
    both sides already know.
    """
    return sorted(inputs, key=lambda i: (i.txid, int(i.vout)))


def input_digest(inputs: list[PayjoinInput]) -> tuple[tuple[int, int], int]:
    """(A_sum point, input_hash) for a frozen input set — all public.

    Every input here is P2TR, so each contributes its x-only key lifted to even
    Y. That lift is the public-side counterpart of negating an odd-Y private
    key on the sender side (wallet.py::sp_scriptpubkey_from_inputs), and the
    two must agree or the output is one nobody can find. A P2WPKH input would
    contribute its 33-byte key unchanged; this module does not accept one,
    because an SP wallet has no P2WPKH coins to contribute.
    """
    if not inputs:
        raise ValueError("A PayJoin needs inputs from both parties.")

    points = []
    for i in inputs:
        if len(i.pub_key) != 32:
            raise ValueError(
                f"{i.txid}:{i.vout} is not a 32-byte x-only key — only taproot "
                f"inputs take part in this input set."
            )
        points.append(compressed_pubkey_to_point(bytes([0x02]) + i.pub_key))

    a_sum = points[0]
    for p in points[1:]:
        a_sum = point_add(a_sum, p)
    a_sum_bytes = bytes([0x02 + (a_sum[1] % 2)]) + ser256(a_sum[0])

    outpoint_l = min(i.outpoint for i in inputs)
    input_hash = int.from_bytes(
        tagged_hash("BIP0352/Inputs", outpoint_l + a_sum_bytes), "big"
    )
    return a_sum, input_hash


def own_output_point(
    scan_secret: bytes,
    spend_pub: bytes,
    inputs: list[PayjoinInput],
    k: int = 0,
):
    """P_k for an output paying the holder of `scan_secret`, from public inputs.

    Returns a POINT rather than a script, and that is deliberate. A labelled
    output is P_k + label, added on the curve, so it needs P_k's real Y parity.
    Hand back only the x-only key and a caller has to guess: half the time it
    builds an output nobody can spend, and the scanner STILL finds it, because
    the scanner tests both label signs. Detected-and-unspendable is the worst
    failure available, so the parity does not get thrown away here — and
    `change_script` below avoids the addition entirely instead.
    """
    a_sum, input_hash = input_digest(inputs)
    b_scan = int.from_bytes(scan_secret, "big") % SECP256K1_N

    ecdh = point_mul(a_sum, (b_scan * input_hash) % SECP256K1_N)
    ecdh_compressed = bytes([0x02 + (ecdh[1] % 2)]) + ser256(ecdh[0])
    t_k = int.from_bytes(
        tagged_hash("BIP0352/SharedSecret", ecdh_compressed + k.to_bytes(4, "big")),
        "big",
    )
    return point_add(
        compressed_pubkey_to_point(spend_pub), pubkey_point_gen_from_int(t_k)
    )


def _spk(point) -> bytes:
    return bytes([0x51, 0x20]) + ser256(point[0])


def payment_script(
    scan_secret: bytes, spend_pub: bytes, inputs: list[PayjoinInput]
) -> bytes:
    """The payee's output. Derived by the PAYEE, who is the only party with the
    scan key it needs; the payer cannot compute it and cannot check it."""
    return _spk(own_output_point(scan_secret, spend_pub, inputs))


def change_script(
    scan_secret: bytes,
    spend_pub: bytes,
    label_pub: bytes,
    inputs: list[PayjoinInput],
) -> bytes:
    """The payer's change, to their own m=0 labelled address.

    The label is folded into B_spend BEFORE deriving, which is what
    wallet.py::_derive_change_script does via generate_labeled_sp_address. Doing
    it that way round means (B_spend + label) + t_k·G is one point addition on
    full points, with no x-only key in the middle and no parity to get wrong.
    """
    labelled = coincurve.PublicKey(spend_pub).combine(
        [coincurve.PublicKey(label_pub)]
    ).format(compressed=True)
    return _spk(own_output_point(scan_secret, labelled, inputs))


def estimate_fee(n_inputs: int, n_outputs: int, fee_rate: float) -> tuple[int, int]:
    """(vsize, fee). Every input and every output in a PayJoin is P2TR."""
    vsize = estimate_vsize(n_inputs, [TAPROOT_OUTPUT_VBYTES] * n_outputs)
    return vsize, fee_for(vsize, fee_rate)


def plan(
    payer_inputs: list[PayjoinInput],
    payee_inputs: list[PayjoinInput],
    amount: int,
    fee_rate: float,
) -> dict:
    """Amounts for a sender-pays-fee PayJoin, before any derivation.

    The payee's contributed input comes straight back out in the payment, so
    the payee is no worse off for taking part and the payer pays only `amount`
    plus the fee — the same model as payjoin_merge.py.
    """
    if amount < DUST_SATS:
        raise ValueError(
            f"{amount} sats is below the {DUST_SATS} sat dust limit."
        )
    payer_total = sum(i.amount for i in payer_inputs)
    payee_total = sum(i.amount for i in payee_inputs)
    if not payer_inputs or not payee_inputs:
        raise ValueError("A PayJoin needs inputs from both parties.")

    n_in = len(payer_inputs) + len(payee_inputs)
    _vsize, fee = estimate_fee(n_in, 2, fee_rate)
    change = payer_total - amount - fee

    if change < 0:
        spendable = payer_total - fee
        if spendable < DUST_SATS:
            raise ValueError(
                f"Your coins total {payer_total} sats, which leaves {spendable} "
                f"after a {fee} sat fee — below the {DUST_SATS} sat dust limit."
            )
        raise ValueError(
            f"Not enough to cover {amount} sats plus a {fee} sat fee — your "
            f"selected coins total {payer_total} sats, and the most they can "
            f"send is {spendable} sats."
        )

    if change < DUST_SATS:
        # Uneconomic to create, so it goes to the miner — and the transaction
        # drops to one output, which is cheaper than the estimate assumed.
        _vsize, fee = estimate_fee(n_in, 1, fee_rate)
        fee += max(0, payer_total - amount - fee)
        change = 0

    return {
        "payer_in": payer_total,
        "payee_in": payee_total,
        "payment": amount + payee_total,
        "amount": amount,
        "fee": fee,
        "change": change,
        "vsize": estimate_fee(n_in, 2 if change else 1, fee_rate)[0],
    }


def outputs_for(amounts: dict, payment_spk: bytes, change_spk: Optional[bytes]):
    """Transaction outputs in BIP-69 order, from the two derived scripts."""
    outs = [TransactionOutput(amounts["payment"], Script(payment_spk))]
    if amounts["change"]:
        if change_spk is None:
            raise ValueError("change is non-zero but no change script was derived")
        outs.append(TransactionOutput(amounts["change"], Script(change_spk)))
    outs.sort(key=lambda o: (o.value, bytes(o.script_pubkey.data)))
    return outs


def signing_key(spend_secret: bytes, priv_key_tweak: bytes, pub_key: bytes) -> ec.PrivateKey:
    """The full key for one of your own SP inputs: b_spend + tweak, negated if
    the resulting point has odd Y.

    Same rule as wallet.py::_prepare_inputs. It is repeated rather than shared
    because that function also builds embit Scripts and sorts, and the one line
    that matters here is the negation — which, got wrong, produces a signature
    that verifies against a key nobody expects and a transaction the network
    rejects.
    """
    total = (
        int.from_bytes(spend_secret, "big") + int.from_bytes(priv_key_tweak, "big")
    ) % SECP256K1_N
    if total == 0:
        raise ValueError("degenerate signing key for input")
    point = pubkey_point_gen_from_int(total)
    if point[1] % 2 == 1:
        total = SECP256K1_N - total
        point = pubkey_point_gen_from_int(total)
    derived = ser256(point[0])
    if derived != pub_key:
        raise ValueError(
            "b_spend + tweak does not reproduce this input's key — wrong wallet, "
            "or the stored tweak belongs to another output"
        )
    return ec.PrivateKey(total.to_bytes(32, "big"))
