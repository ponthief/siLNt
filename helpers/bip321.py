"""
The Silent Payments parameter of a BIP-321 / BIP-353 payment URI.

BIP-321: "New payment instructions using bech32 or bech32m encodings SHOULD reuse
their address format's Human Readable Part as the parameter key." A mainnet
Silent Payments address (``sp1…``) therefore travels as ``sp=``, and a signet or
testnet one (``tsp1…``) as ``tsp=`` — the same way a testnet SegWit address goes
in ``tb=`` and never in ``bc=``.

This extension published ``sp=`` for every network, signet included, and parsed
by ``str.replace("sp=", "")``. Sparrow reads ``tsp=`` on signet and found no
instruction in ``bitcoin:?sp=tsp1…`` (reported 2026-11-21). So:

* what is WRITTEN follows the spec: the key is the address's own HRP;
* what is READ accepts both keys, because records published before this one
  carry ``sp=tsp1…`` and must keep resolving until they are rewritten;
* and nothing parses a URI with ``replace`` any more — ``"bitcoin:?tsp=…"
  .replace("sp=", "")`` is not an address, it is ``bitcoin:?ttsp1…``.
"""

from urllib.parse import parse_qsl, unquote


def sp_param_key(sp_address: str) -> str:
    """The BIP-321 key for this address: its HRP. ``tsp`` for tsp1…, else ``sp``."""
    return "tsp" if (sp_address or "").strip().lower().startswith("tsp1") else "sp"


def sp_uri(sp_address: str) -> str:
    """The TXT record content for a Silent Payments address with no fallback."""
    addr = (sp_address or "").strip()
    return f"bitcoin:?{sp_param_key(addr)}={addr}"


def sp_from_uri(uri: str) -> str:
    """The Silent Payments address in a payment URI, or '' if it carries none.

    Accepts ``sp`` and ``tsp`` keys in any case, a bare address (which is what a
    caller that already stripped the URI hands back), and the legacy
    ``bitcoin:?sp=tsp1…`` shape. Never returns anything but an address-looking
    value: a URI whose only instruction is something else (``lno=``, a SegWit
    address) yields '', so the caller refuses it rather than paying garbage.
    """
    s = (uri or "").strip()
    if not s:
        return ""
    low = s.lower()
    if low.startswith(("sp1", "tsp1")):
        return s
    if not low.startswith("bitcoin:"):
        return ""
    query = s.split("?", 1)[1] if "?" in s else ""
    found = [
        unquote(v).strip()
        for k, v in parse_qsl(query, keep_blank_values=True)
        if k.lower() in ("sp", "tsp")
    ]
    found = [v for v in found if v.lower().startswith(("sp1", "tsp1"))]
    # More than one is ambiguous; BIP-353 refuses ambiguous records and so do we.
    return found[0] if len(found) == 1 else ""


def client_resolve_shape(resolved: dict) -> dict:
    """What ``GET /bip353/resolve`` hands the WhiSPa apps.

    Builds that predate ``tsp=`` read ``result`` with ``str.replace('sp=', '')``.
    Handed ``bitcoin:?tsp=tsp1…`` they compute ``bitcoin:?ttsp1…``, which is not
    the wallet's address, and the wallet screen reports **"Tampering detected"**
    against a record that is perfectly correct. So ``result`` stays in the shape
    those builds can read, and the truth about the record travels beside it:

    * ``result``     - ``bitcoin:?sp=<address>`` (legacy shape, parseable by every build)
    * ``uri``        - the record exactly as published in DNS
    * ``sp_address`` - the bare address

    Current builds parse either; nothing is lost. A record carrying no Silent
    Payments address is returned untouched, so it still fails every comparison.
    """
    sp = sp_from_uri((resolved or {}).get("result", ""))
    if not sp:
        return resolved
    return {
        **resolved,
        "uri": resolved["result"],
        "sp_address": sp,
        "result": f"bitcoin:?sp={sp}",
    }
