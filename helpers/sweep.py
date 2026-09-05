"""
sweep.py — pull coins off a plain BIP-84 P2WPKH address into a Silent Payment
wallet.

Why this exists: plenty of services can only pay a bech32 address. An exchange
withdrawal, a payroll provider, a mining pool — none of them will send to an
sp1… address, and none of them will for years. Without this the user has to
withdraw to some other wallet and forward manually.

What it is NOT: a second wallet. There is one address (m/84'/coin'/0'/0/0 — the
same one the swap refund uses), it is not tracked in silnt.utxos, it never
appears in coin control, and nothing here can spend a Silent Payment UTXO. It is
a doormat: coins land on it, and the sweep moves all of them, in one
single-input-type transaction, into the wallet proper.

Address reuse is a real cost and it is deliberate. Tracking a chain of receive
addresses would mean handing the server an xpub, which lets it derive and watch
every address the user will ever have — exactly the surveillance property Silent
Payments exists to remove. One reused address tells the server one address. The
UI says so plainly.

Key handling matches the rest of the wallet: the private key arrives with the
request, is used to sign, and is never written down. It is derived on the device
from the seed phrase at sweep time, because the BIP-84 branch is deliberately
NOT stored in the device keystore.
"""

from __future__ import annotations

import math

from embit import ec, script
from embit.networks import NETWORKS
from embit.script import Script
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionInput,
    TransactionOutput,
)
from loguru import logger

from .electrum_client import (
    ElectrumClient,
    address_to_scriptpubkey,
    electrum_scripthash,
)
from .wallet import sp_scriptpubkey_from_inputs

# A P2WPKH input is 68 vB (41 base + 27 witness), a P2TR output 43 vB, and the
# version/counts/locktime overhead with a segwit marker is 10.5 vB. The sweep has
# exactly one output and no change, so this is exact rather than an estimate —
# the only variable is the ECDSA signature, which `grind=True` keeps at 71 bytes
# or fewer (its DER length is already counted at the maximum).
INPUT_VBYTES = 68
OUTPUT_VBYTES = 43
OVERHEAD_VBYTES = 10.5

# Below this the sweep costs more than it moves. 546 is the wallet's dust floor
# elsewhere (helpers/wallet.py), kept the same here rather than dropping to the
# lower P2TR figure — a sweep worth less than this is not worth broadcasting.
DUST_SATS = 546


def _net(network: str):
    n = (network or "").lower()
    if n == "mainnet":
        return NETWORKS["main"]
    if n == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]  # signet shares testnet's parameters


def hrp_for(network: str) -> str:
    """Segwit v0 human-readable part. Signet shares testnet's 'tb' (BIP-173)."""
    n = (network or "").lower()
    if n == "mainnet":
        return "bc"
    if n == "regtest":
        return "bcrt"
    return "tb"


def is_p2wpkh_for_network(address: str, network: str) -> bool:
    """
    True only for a native segwit v0 pubkey-hash address on `network`. Decodes
    rather than pattern-matching, so a bech32m address, a P2WSH, or a mainnet
    address on signet all fail here instead of downstream.
    """
    addr = (address or "").strip()
    if not addr.lower().startswith(hrp_for(network) + "1"):
        return False
    try:
        spk = address_to_scriptpubkey(addr)
    except Exception:
        return False
    return len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14


def sweep_address_for_key(sweep_key_hex: str, network: str) -> str:
    """The P2WPKH address the given private key controls."""
    priv = ec.PrivateKey(bytes.fromhex(sweep_key_hex))
    return script.p2wpkh(priv.get_public_key()).address(_net(network))


def estimate_fee(num_inputs: int, fee_rate: float) -> tuple[int, int]:
    """(vsize, fee_sats) for a sweep of `num_inputs` inputs to one P2TR output."""
    vsize = math.ceil(OVERHEAD_VBYTES + INPUT_VBYTES * num_inputs + OUTPUT_VBYTES)
    return vsize, max(1, math.ceil(vsize * fee_rate))


def fetch_address_utxos(
    address: str, host: str, port: int, use_tls: bool = False
) -> dict:
    """
    Every UTXO currently sitting on `address`, straight from Fulcrum.

    Blocking — call it from a worker thread, not the event loop. Returns
    confirmed and unconfirmed separately: a sweep only ever spends confirmed
    coins, since an exchange withdrawal sitting in the mempool can still be
    replaced, and rebuilding on top of it would just orphan the sweep.
    """
    sh = electrum_scripthash(address)
    client = ElectrumClient(host, port, use_tls=use_tls)
    try:
        client.connect()
        client.server_version()
        unspent = client.list_unspent(sh)
    finally:
        client.close()

    confirmed: list[dict] = []
    confirmed_sats = 0
    unconfirmed_sats = 0
    for u in unspent:
        height = int(u.get("height", 0) or 0)
        value = int(u.get("value", 0) or 0)
        if height <= 0:
            unconfirmed_sats += value
            continue
        confirmed_sats += value
        confirmed.append(
            {
                "txid": u.get("tx_hash"),
                "vout": int(u.get("tx_pos")),
                "amount": value,
                "height": height,
            }
        )

    # Deterministic order, so a preview and the build that follows it agree on
    # which coins they are talking about.
    confirmed.sort(key=lambda u: (u["txid"], u["vout"]))
    return {
        "address": address,
        "utxos": confirmed,
        "confirmed_sats": confirmed_sats,
        "unconfirmed_sats": unconfirmed_sats,
    }


def build_sweep_transaction(
    sweep_key_hex: str,
    sp_address: str,
    utxos: list[dict],
    fee_rate: float,
    network: str,
) -> dict:
    """
    Spend every UTXO in `utxos` to `sp_address` in one transaction. No change
    output: the sweep empties the address by definition, and the fee comes out
    of the total.
    """
    if not utxos:
        raise ValueError("Nothing to sweep — the address holds no confirmed coins.")

    priv = ec.PrivateKey(bytes.fromhex(sweep_key_hex))
    pub = priv.get_public_key()
    spk = script.p2wpkh(pub)

    total_input = sum(int(u["amount"]) for u in utxos)
    vsize, fee = estimate_fee(len(utxos), fee_rate)
    amount = total_input - fee
    if amount < DUST_SATS:
        raise ValueError(
            f"Sweep would leave {amount} sats after a {fee} sat fee, below the "
            f"{DUST_SATS} sat dust limit. Wait for more coins or a lower fee rate."
        )

    # BIP-69 order, matching the Silent Payments send path. The outpoints below
    # feed BIP-352's smallest-outpoint rule, which is order-independent, but a
    # deterministic transaction is easier to reason about after the fact.
    ordered = sorted(utxos, key=lambda u: (u["txid"], int(u.get("vout", 0))))

    # Every input here is P2WPKH controlled by the one sweep key, so every input
    # contributes that same key UNNEGATED — see sp_scriptpubkey_from_inputs on
    # why the taproot flag matters.
    priv_int = int.from_bytes(priv.secret, "big")
    sp_inputs = [
        (
            priv_int,
            bytes.fromhex(u["txid"])[::-1] + int(u.get("vout", 0)).to_bytes(4, "little"),
            False,
        )
        for u in ordered
    ]
    out_script = Script(sp_scriptpubkey_from_inputs(sp_address, sp_inputs))

    tx = Transaction(
        vin=[
            TransactionInput(bytes.fromhex(u["txid"]), int(u.get("vout", 0)))
            for u in ordered
        ],
        vout=[TransactionOutput(amount, out_script)],
    )

    # BIP-143: the scriptCode for a P2WPKH input is its P2PKH equivalent, not the
    # witness program.
    script_code = script.p2pkh_from_p2wpkh(spk)
    for i, u in enumerate(ordered):
        sighash = tx.sighash_segwit(i, script_code, int(u["amount"]), SIGHASH.ALL)
        tx.vin[i].witness = script.witness_p2wpkh(
            priv.sign(sighash), pub, SIGHASH.ALL
        )

    tx_hex = tx.serialize().hex()
    logger.info(
        f"Built sweep of {len(ordered)} input(s), {total_input} sats "
        f"→ {amount} sats to SP, fee {fee} sats ({vsize} vB)"
    )
    return {
        "tx_hex": tx_hex,
        "amount": amount,
        "fee": fee,
        "total_input": total_input,
        "vsize": vsize,
        "fee_rate_used": fee_rate,
        "input_count": len(ordered),
        "sweep_address": spk.address(_net(network)),
    }
