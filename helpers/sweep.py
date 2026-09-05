"""
sweep.py — pull coins off a plain BIP-84 P2WPKH address into a Silent Payment
wallet.

Why this exists: plenty of services can only pay a bech32 address. An exchange
withdrawal, a payroll provider, a mining pool — none of them will send to an
sp1… address, and none of them will for years. Without this the user has to
withdraw to some other wallet and forward manually.

What it is NOT: a second wallet. These addresses are not tracked in silnt.utxos,
never appear in coin control, and nothing here can spend a Silent Payment UTXO.
It is a doormat: coins land on it, and the sweep moves all of them into the
wallet proper in one single-input-type transaction.

The addresses come from the standard BIP-84 external chain, m/84'/coin'/0'/0/i —
the same chain a swap refund lands on. The client derives them, walks the chain
to find the first unused one, and hands over only the addresses it wants
checked. The server is never given the xpub: it learns the addresses actually
used and cannot derive the next one, let alone every address the seed will ever
produce.

Key handling matches the rest of the wallet: private keys arrive with the
request, are used to sign, and are never written down server-side. Only the keys
for addresses that actually hold coins are ever sent — normally exactly one.
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


def _scan_one(client: ElectrumClient, address: str) -> dict:
    """One address: has it ever been used, and what is unspent on it now."""
    sh = electrum_scripthash(address)
    # get_history, not list_unspent, decides "used" — an address that received
    # and was swept has no unspent outputs but must never be handed out again.
    used = bool(client.get_history(sh))
    unspent = client.list_unspent(sh) if used else []

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
                "address": address,
                "txid": u.get("tx_hash"),
                "vout": int(u.get("tx_pos")),
                "amount": value,
                "height": height,
            }
        )

    return {
        "address": address,
        "used": used,
        "utxos": confirmed,
        "confirmed_sats": confirmed_sats,
        "unconfirmed_sats": unconfirmed_sats,
    }


def scan_addresses(
    addresses: list[str], host: str, port: int, use_tls: bool = False
) -> dict:
    """
    Walk a batch of addresses on one Fulcrum connection.

    Blocking — call it from a worker thread, not the event loop. Confirmed and
    unconfirmed are kept apart: a sweep only ever spends confirmed coins, since
    an exchange withdrawal sitting in the mempool can still be replaced, and a
    sweep built on top of it would be orphaned with it.
    """
    client = ElectrumClient(host, port, use_tls=use_tls)
    try:
        client.connect()
        client.server_version()
        per_address = [_scan_one(client, a) for a in addresses]
    finally:
        client.close()

    utxos = [u for a in per_address for u in a["utxos"]]
    # Deterministic order, so a preview and the build that follows it agree on
    # which coins they are talking about.
    utxos.sort(key=lambda u: (u["txid"], u["vout"]))
    return {
        "addresses": per_address,
        "utxos": utxos,
        "confirmed_sats": sum(a["confirmed_sats"] for a in per_address),
        "unconfirmed_sats": sum(a["unconfirmed_sats"] for a in per_address),
    }


def build_sweep_transaction(
    sweep_keys: list[str],
    sp_address: str,
    utxos: list[dict],
    fee_rate: float,
    network: str,
) -> dict:
    """
    Spend every UTXO in `utxos` to `sp_address` in one transaction.

    `sweep_keys` are the private keys for the addresses those UTXOs sit on, in
    any order — each input is matched to its key by address. Rotating the
    receive address means a sweep can span several of them, so this is a list,
    though in practice it is usually one.

    No change output: a sweep empties the addresses by definition, and the fee
    comes out of the total.
    """
    if not utxos:
        raise ValueError("Nothing to sweep — no confirmed coins on these addresses.")
    if not sweep_keys:
        raise ValueError("No keys supplied to sign the sweep.")

    # address → (key, pubkey), so each input is signed with the key that
    # actually controls it.
    by_address: dict[str, tuple] = {}
    for key_hex in sweep_keys:
        priv = ec.PrivateKey(bytes.fromhex(key_hex))
        pub = priv.get_public_key()
        by_address[script.p2wpkh(pub).address(_net(network))] = (priv, pub)

    missing = {u.get("address") for u in utxos} - set(by_address)
    if missing:
        # Refuse rather than sign what we can: a partial sweep would leave coins
        # behind while the user is told the address was emptied.
        raise ValueError(
            f"No key supplied for {len(missing)} address(es) holding coins."
        )

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

    # Every input is P2WPKH, so every key contributes UNNEGATED — see
    # sp_scriptpubkey_from_inputs on why the taproot flag matters.
    sp_inputs = [
        (
            int.from_bytes(by_address[u["address"]][0].secret, "big"),
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

    for i, u in enumerate(ordered):
        priv, pub = by_address[u["address"]]
        # BIP-143: the scriptCode for a P2WPKH input is its P2PKH equivalent,
        # not the witness program.
        script_code = script.p2pkh_from_p2wpkh(script.p2wpkh(pub))
        sighash = tx.sighash_segwit(i, script_code, int(u["amount"]), SIGHASH.ALL)
        tx.vin[i].witness = script.witness_p2wpkh(priv.sign(sighash), pub, SIGHASH.ALL)

    tx_hex = tx.serialize().hex()
    swept = sorted({u["address"] for u in ordered})
    logger.info(
        f"Built sweep of {len(ordered)} input(s) across {len(swept)} address(es), "
        f"{total_input} sats → {amount} sats to SP, fee {fee} sats ({vsize} vB)"
    )
    return {
        "tx_hex": tx_hex,
        "amount": amount,
        "fee": fee,
        "total_input": total_input,
        "vsize": vsize,
        "fee_rate_used": fee_rate,
        "input_count": len(ordered),
        "swept_addresses": swept,
    }
