"""
spend_watch.py — noticing coins leaving a wallet that did not ask them to.

A compromised spend key is silent. The attacker signs with exactly the authority
the owner has, so the transaction looks like any other spend; the wallet finds
out when it next scans and the balance is gone. The point of this module is to
turn "next time you look" into "within about a block, on your lock screen".

It needs NO SECRET. Every Silent Payments output the wallet owns is P2TR, and
silnt.utxos already stores the 32-byte x-only output key, so the scriptPubKey is
0x51 0x20 || pub_key and the server can watch it read-only. Two consequences
worth stating: the alert works for wallets that never opted into background
scanning, and nothing here widens what the server knows — it is watching outputs
it already has in a table.

WHAT IT CANNOT DO, and the copy must not pretend otherwise: this does not stop
the spend, and RBF is not the remedy people expect. Replacing the attacker's
transaction means spending the same inputs with the same keys they hold, so it
is a fee auction against someone who can counter-replace, and winning it changes
nothing durable because they still have the key. What actually helps is moving
whatever is left to a wallet whose keys they do not have, immediately — a race
that is winnable for coins they have not touched yet.

The plain BIP-84 chain is deliberately NOT watched here. The server is told a
plain address only when asked to look at one and persists nothing, which is the
property that whole feature rests on; watching it server-side would mean keeping
a permanent record of which addresses are yours.
"""

from __future__ import annotations

import asyncio

from loguru import logger

from .electrum_client import ElectrumClient, scripthash_for_scriptpubkey


def scriptpubkey_for_output_key(pub_key_hex: str) -> bytes:
    """P2TR scriptPubKey for a BIP-352 output key.

    Matches helpers/wallet.py, which builds the same script when it verifies an
    input: Script(bytes([0x51, 0x20]) + x_only).
    """
    x_only = bytes.fromhex(pub_key_hex)
    if len(x_only) != 32:
        raise ValueError(f"expected a 32-byte x-only key, got {len(x_only)}")
    return bytes([0x51, 0x20]) + x_only


def find_spending_txids(
    client: ElectrumClient, utxos: list[dict]
) -> dict[str, str]:
    """Which of these coins have been spent, and by what.

    Returns {"<txid>:<vout>": spending_txid} for the ones that are gone.

    A Silent Payments output has a scriptPubKey unique to that one payment, so
    the address history holds at most two transactions: the one that created it
    and the one that spent it. Anything in the history that is not the funding
    txid IS the spend — no guessing, and no need to fetch and parse transactions.

    Batched, so a wallet with thirty coins costs one round trip rather than
    thirty (see ElectrumClient.call_batch). Falls back to one call at a time if
    the server does not batch.
    """
    if not utxos:
        return {}

    shs = []
    keep = []
    for u in utxos:
        try:
            shs.append(scripthash_for_scriptpubkey(scriptpubkey_for_output_key(u["pub_key"])))
            keep.append(u)
        except Exception as exc:
            # A malformed key is a data problem, not evidence of a spend. Skip
            # it: raising here would take the whole sweep down, and reporting it
            # as spent would be an alarm about nothing.
            logger.warning(f"spend watch: skipping unwatchable utxo {u.get('txid')}: {exc}")

    method = "blockchain.scripthash.get_history"
    try:
        results = client.call_batch([(method, [sh]) for sh in shs])
        histories = []
        for r in results:
            if r.get("error"):
                raise ValueError(f"get_history failed: {r['error']}")
            histories.append(r.get("result") or [])
    except Exception as exc:
        logger.info(f"spend watch: batch unavailable ({exc}); falling back")
        histories = [client.get_history(sh) for sh in shs]

    spent: dict[str, str] = {}
    for u, history in zip(keep, histories):
        for entry in history or []:
            other = entry.get("tx_hash")
            if other and other != u["txid"]:
                spent[f"{u['txid']}:{u['vout']}"] = other
                break
    return spent


async def check_wallet_for_unexpected_spends(
    wallet, host: str, port: int, use_tls: bool = False
) -> list[str]:
    """Spending txids for this wallet that the wallet itself did not broadcast.

    Blocking Electrum work is pushed to a thread — this runs inside the
    extension's event loop alongside the scan.
    """
    from ..crud import record_spend_alert, utxos_to_watch, was_broadcast_by_us

    utxos = await utxos_to_watch(wallet.id)
    if not utxos:
        return []

    def _walk() -> dict[str, str]:
        client = ElectrumClient(host, port, use_tls=use_tls)
        try:
            client.connect()
            client.server_version()
            return find_spending_txids(client, utxos)
        finally:
            client.close()

    try:
        spent = await asyncio.to_thread(_walk)
    except Exception as exc:
        # An unreachable indexer is not evidence of anything. Staying quiet is
        # the only safe failure here: crying compromise because Fulcrum was down
        # would teach users to ignore the alert that matters.
        logger.warning(f"spend watch: could not check wallet {wallet.id}: {exc}")
        return []

    unexpected: list[str] = []
    for outpoint, spending_txid in spent.items():
        if await was_broadcast_by_us(wallet.id, spending_txid):
            continue
        # Recorded before it is announced, and only announced if the record was
        # new — so a spend of five coins in one transaction is one alert, and a
        # later pass does not repeat it.
        if await record_spend_alert(wallet.id, spending_txid):
            logger.warning(
                f"spend watch: wallet {wallet.id} coin {outpoint} spent by "
                f"{spending_txid}, which this wallet did not broadcast"
            )
            unexpected.append(spending_txid)
    return unexpected
