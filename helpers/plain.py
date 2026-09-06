"""
plain.py — a plain bech32 pocket beside the Silent Payments wallet.

Why this exists: plenty of services can only pay a bech32 address. An exchange,
a payroll provider, a mining pool — none of them will send to an sp1… address,
and none of them will for years. Without this the user has to receive somewhere
else entirely and forward by hand.

Coins land on this chain and are spent STRAIGHT OUT of it. They never enter the
Silent Payments wallet, and that is the point, not a limitation:

  * It costs one transaction instead of two. Moving them into the SP wallet
    first and paying from there is a second transaction and a second fee for no
    gain, when the coins were only passing through.

  * It keeps them unlinked. Bringing them into the SP wallet ties them to an
    output that then sits alongside the wallet's own coins; paying out directly
    ties them only to where they were going anyway.

Somebody who does want them in the SP wallet can still send them there — the
destination takes an sp1… address like any other. It is a destination, not a
special mode.

What this is NOT: a second wallet. These addresses are not tracked in
silnt.utxos, never appear in coin control, and nothing here can spend a Silent
Payment UTXO.

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
from typing import Optional

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

# A P2WPKH input is 68 vB (41 base + 27 witness) and the version/counts/locktime
# overhead with a segwit marker is 10.5 vB. Output sizes vary by type, below.
# The only variable left is the ECDSA signature, which `grind=True` keeps at 71
# bytes or fewer — already counted at its maximum — so these are exact, not
# estimates.
INPUT_VBYTES = 68
OUTPUT_VBYTES = 43  # P2TR, e.g. a Silent Payments destination
OVERHEAD_VBYTES = 10.5

# Serialized size of one output, by scriptPubKey shape: 8 value bytes + 1 length
# byte + the script. Used when paying out of the pool, where the destination can
# be any address type the sender chose.
_OUTPUT_VBYTES_BY_SCRIPT_LEN = {
    22: 31,  # P2WPKH   OP_0 <20>
    34: 43,  # P2WSH / P2TR  <push> <32>
    23: 32,  # P2SH     OP_HASH160 <20> OP_EQUAL
    25: 34,  # P2PKH
}
# Change always goes back to a fresh address on the same P2WPKH chain.
CHANGE_VBYTES = 31


def output_vbytes(script_pubkey: bytes) -> int:
    """Serialized vbytes for an output with this scriptPubKey."""
    return _OUTPUT_VBYTES_BY_SCRIPT_LEN.get(len(script_pubkey), 8 + 1 + len(script_pubkey))

# Below this an output costs more to spend than it holds. 546 is the wallet's
# dust floor elsewhere (helpers/wallet.py), kept the same here rather than
# dropping to the lower P2TR figure.
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


def plain_address_for_key(key_hex: str, network: str) -> str:
    """The P2WPKH address the given private key controls."""
    priv = ec.PrivateKey(bytes.fromhex(key_hex))
    return script.p2wpkh(priv.get_public_key()).address(_net(network))


def estimate_fee(num_inputs: int, fee_rate: float) -> tuple[int, int]:
    """(vsize, fee_sats) for `num_inputs` inputs paying one P2TR output."""
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
    unconfirmed are kept apart: only confirmed coins are ever spent, since an
    incoming payment sitting in the mempool can still be replaced, and anything
    built on top of it would be orphaned with it.
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


def build_plain_transaction(
    keys: list[str],
    destination: str,
    utxos: list[dict],
    fee_rate: float,
    network: str,
    amount: Optional[int] = None,
    change_address: Optional[str] = None,
) -> dict:
    """
    Spend `utxos` from the plain BIP-84 chain.

    Two shapes, and the difference is `amount`:

      * amount=None — send everything, no change output. The chosen addresses
        are emptied and the fee comes out of the total.

      * amount=N — send N and return the rest to `change_address`, which must be
        another address on this same chain.

    `destination` may be any ordinary address, or a Silent Payment one — paying
    the user's own SP address is how coins move into that wallet, if they want
    them there. It is a destination, not a special mode. Change, when there is
    any, is always P2WPKH on this chain.

    `keys` are the private keys for the addresses those UTXOs sit on, in any
    order — each input is matched to its key by address.
    """
    if not utxos:
        raise ValueError("No confirmed coins on these addresses.")
    if not keys:
        raise ValueError("No keys supplied to sign with.")
    if amount is not None and amount < DUST_SATS:
        raise ValueError(f"Amount must be at least {DUST_SATS} sats.")

    # address → (key, pubkey), so each input is signed with the key that
    # actually controls it.
    by_address: dict[str, tuple] = {}
    for key_hex in keys:
        priv = ec.PrivateKey(bytes.fromhex(key_hex))
        pub = priv.get_public_key()
        by_address[script.p2wpkh(pub).address(_net(network))] = (priv, pub)

    missing = {u.get("address") for u in utxos} - set(by_address)
    if missing:
        # Refuse rather than sign what we can: a partial spend would leave coins
        # behind while the user is told the address was emptied.
        raise ValueError(
            f"No key supplied for {len(missing)} address(es) holding coins."
        )

    total_input = sum(int(u["amount"]) for u in utxos)

    # BIP-69 order. The outpoints below feed BIP-352's smallest-outpoint rule,
    # which is order-independent, but a deterministic transaction is easier to
    # reason about after the fact.
    ordered = sorted(utxos, key=lambda u: (u["txid"], int(u.get("vout", 0))))

    # Every input is P2WPKH, so every key contributes UNNEGATED — see
    # sp_scriptpubkey_from_inputs on why the taproot flag matters. Only used for
    # a Silent Payments destination, but computed the same way regardless.
    sp_inputs = [
        (
            int.from_bytes(by_address[u["address"]][0].secret, "big"),
            bytes.fromhex(u["txid"])[::-1] + int(u.get("vout", 0)).to_bytes(4, "little"),
            False,
        )
        for u in ordered
    ]
    dest = destination.strip()
    if dest.startswith("sp1") or dest.startswith("tsp1"):
        out_script = Script(sp_scriptpubkey_from_inputs(dest, sp_inputs))
    else:
        try:
            out_script = script.address_to_scriptpubkey(dest)
        except Exception as e:
            raise ValueError(f"Invalid destination address: {e}")

    dest_bytes = out_script.data if hasattr(out_script, "data") else bytes(out_script)
    vsize = math.ceil(
        OVERHEAD_VBYTES
        + INPUT_VBYTES * len(ordered)
        + output_vbytes(dest_bytes)
        + (CHANGE_VBYTES if amount is not None else 0)
    )
    fee = max(1, math.ceil(vsize * fee_rate))

    change = 0
    if amount is None:
        # Everything goes, and the fee comes out of it.
        send_amount = total_input - fee
        if send_amount < DUST_SATS:
            raise ValueError(
                f"Would leave {send_amount} sats after a {fee} sat fee, below the "
                f"{DUST_SATS} sat dust limit. Wait for more coins or a lower fee "
                f"rate."
            )
    else:
        send_amount = amount
        change = total_input - amount - fee
        if change < 0:
            raise ValueError(
                f"Not enough to cover {amount} sats plus a {fee} sat fee — these "
                f"coins total {total_input} sats."
            )
        if change < DUST_SATS:
            # Uneconomic to create; give it to the miner rather than making an
            # output that costs more to spend than it holds.
            fee += change
            change = 0
            vsize -= CHANGE_VBYTES

    tx_outputs = [TransactionOutput(send_amount, out_script)]
    if change:
        if not change_address:
            raise ValueError("A change address is required when not sending everything.")
        if not is_p2wpkh_for_network(change_address, network):
            # Change must come back to this chain. Refusing anything else means a
            # malformed request cannot quietly route the remainder elsewhere.
            raise ValueError("Change address must be a native segwit address on this network.")
        tx_outputs.append(
            TransactionOutput(change, script.address_to_scriptpubkey(change_address))
        )
        # Do not leak which output is change by its position.
        tx_outputs.sort(
            key=lambda o: (
                o.value,
                (o.script_pubkey.data if hasattr(o.script_pubkey, "data") else bytes(o.script_pubkey)).hex(),
            )
        )

    tx = Transaction(
        vin=[
            TransactionInput(bytes.fromhex(u["txid"]), int(u.get("vout", 0)))
            for u in ordered
        ],
        vout=tx_outputs,
    )

    for i, u in enumerate(ordered):
        priv, pub = by_address[u["address"]]
        # BIP-143: the scriptCode for a P2WPKH input is its P2PKH equivalent,
        # not the witness program.
        script_code = script.p2pkh_from_p2wpkh(script.p2wpkh(pub))
        sighash = tx.sighash_segwit(i, script_code, int(u["amount"]), SIGHASH.ALL)
        tx.vin[i].witness = script.witness_p2wpkh(priv.sign(sighash), pub, SIGHASH.ALL)

    tx_hex = tx.serialize().hex()
    spent = sorted({u["address"] for u in ordered})
    logger.info(
        f"Built plain spend of {len(ordered)} input(s) across {len(spent)} "
        f"address(es), {total_input} sats → {send_amount} sats out, "
        f"{change} change, fee {fee} sats ({vsize} vB)"
    )
    return {
        "tx_hex": tx_hex,
        "amount": send_amount,
        "change": change,
        "fee": fee,
        "total_input": total_input,
        "vsize": vsize,
        "fee_rate_used": fee_rate,
        "input_count": len(ordered),
        "swept_addresses": spent,
    }
