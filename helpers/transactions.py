import time
import httpx
from loguru import logger
from ..crud import (
    get_blindbit_config,
    get_wallet_receives,
    get_wallet_sends,
    get_utxos_for_txid,
    get_utxos_spent_in_tx,
    get_owned_pubkeys,
)


# Per-process in-memory cache. Keyed by (mempool_base, txid).
# Acceptable to lose on restart — this is non-critical metadata.
_TX_CACHE: dict[tuple[str, str], tuple[float, dict]] = {}
_TX_CACHE_TTL = 3600  # 1 hour


async def _fetch_tx_from_mempool(txid: str, mempool_base: str) -> dict | None:
    """Fetch a tx's full mempool.space data, cached for 1hr."""
    key = (mempool_base, txid)
    now = time.time()
    cached = _TX_CACHE.get(key)
    if cached and now - cached[0] < _TX_CACHE_TTL:
        return cached[1]

    base = mempool_base.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(f"{base}/api/tx/{txid}")
            if r.status_code != 200:
                return None
            data = r.json()
            _TX_CACHE[key] = (now, data)
            return data
    except Exception as e:
        logger.warning(f"Tx fetch failed for {txid}: {e}")
        return None


async def list_wallet_transactions(
    wallet_id: str,
    limit:     int = 50,
    offset:    int = 0,
) -> list[dict]:
    """
    Build the combined chronological transaction list. No mempool calls here —
    everything from local DB. Fast.

    Each row:
      { kind: 'receive'|'send'|'self_send',
        txid, timestamp, amount_sats,
        input_sum, output_sum,        # both populated for self_send
        output_count, input_count,
        labels: [str],
        confirmed: bool                # heuristic from UTXO state
      }
    """
    receives = {r["txid"]: r for r in await get_wallet_receives(wallet_id)}
    sends    = {s["txid"]: s for s in await get_wallet_sends(wallet_id)}

    txids = set(receives) | set(sends)
    rows = []
    for txid in txids:
        rcv = receives.get(txid)
        snd = sends.get(txid)

        if snd and rcv:
            kind        = "self_send"
            timestamp   = snd["spent_at"] or rcv["timestamp"]
            # Net amount = what came back minus what went out (negative = net outflow,
            # equals fee + any external recipient amount)
            amount_sats = rcv["output_sum"] - snd["input_sum"]
            labels      = rcv["labels"]
            input_sum   = snd["input_sum"]
            output_sum  = rcv["output_sum"]
            input_count = snd["input_count"]
            output_count= rcv["output_count"]
        elif snd:
            kind        = "send"
            timestamp   = snd["spent_at"]
            amount_sats = -snd["input_sum"]   # fully outgoing (will refine on detail)
            labels      = []
            input_sum   = snd["input_sum"]
            output_sum  = 0
            input_count = snd["input_count"]
            output_count= 0
        else:
            kind        = "receive"
            timestamp   = rcv["timestamp"]
            amount_sats = rcv["output_sum"]
            labels      = rcv["labels"]
            input_sum   = 0
            output_sum  = rcv["output_sum"]
            input_count = 0
            output_count= rcv["output_count"]

        rows.append({
            "kind":         kind,
            "txid":         txid,
            "timestamp":    timestamp,
            "amount_sats":  amount_sats,
            "input_sum":    input_sum,
            "output_sum":   output_sum,
            "input_count":  input_count,
            "output_count": output_count,
            "labels":       labels,
        })

    # Newest first
    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows[offset:offset + limit]


async def get_wallet_transaction_detail(
    wallet_id: str,
    txid:      str,
) -> dict:
    """
    Enriched view of one transaction. Pulls our own UTXOs from DB, then queries
    mempool.space for the full tx (fee, recipient, confirmation status).
    """
    blindbit       = await get_blindbit_config()
    mempool_base   = blindbit.mempool_url or "https://mempool.space"

    own_outputs    = await get_utxos_for_txid(wallet_id, txid)
    spent_inputs   = await get_utxos_spent_in_tx(wallet_id, txid)
    owned_pubkeys  = await get_owned_pubkeys(wallet_id)
    tx             = await _fetch_tx_from_mempool(txid, mempool_base)

    detail = {
        "txid":          txid,
        "own_outputs":   own_outputs,
        "spent_inputs":  spent_inputs,
        "fee_sats":      None,
        "recipients":    [],     # outputs NOT owned by us
        "confirmed":     None,
        "block_height":  None,
        "block_time":    None,
        "explorer_url":  f"{mempool_base.rstrip('/')}/tx/{txid}",
    }

    if tx is None:
        return detail

    # Fee
    detail["fee_sats"] = tx.get("fee")

    # Confirmation
    status = tx.get("status", {})
    detail["confirmed"]    = bool(status.get("confirmed"))
    detail["block_height"] = status.get("block_height")
    detail["block_time"]   = status.get("block_time")

    # Recipients = outputs whose x-only key is NOT one of ours
    for vout_data in tx.get("vout", []):
        spk_asm = vout_data.get("scriptpubkey_asm") or ""
        # Taproot: "OP_PUSHNUM_1 OP_PUSHBYTES_32 <x-only-key>"
        xonly = None
        parts = spk_asm.split()
        if len(parts) >= 3 and parts[0] == "OP_PUSHNUM_1":
            xonly = parts[-1]
        if xonly and xonly in owned_pubkeys:
            continue
        detail["recipients"].append({
            "address": vout_data.get("scriptpubkey_address"),
            "amount":  int(vout_data.get("value") or 0),
            "type":    vout_data.get("scriptpubkey_type"),
        })

    return detail