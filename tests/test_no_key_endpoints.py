"""The server takes no private key from a client.

Removed 2026-11-21, on the user's instruction, after an audit of both clients
(thrilla `check:keywire`) found they sign on the device and send none. Three
endpoints were still here for builds that predate that:

    POST /api/v1/tx/build                    took `spend_key`
    POST /api/v1/plain/spend                 took the BIP-84 chain's `keys`
    POST /api/v1/wallet/{id}/recover-keys    took an encrypted mnemonic and the
                                             passphrase, and returned the keys

With the clients not calling them, what they did was let anything holding an
admin key hand the server a spend key. That is what these tests keep from coming
back. The signing helpers they used (`build_transaction`,
`build_plain_transaction`) stay: `helpers/_*_signing_fixtures.py` runs them to
generate the vectors both clients are held to.

Reads source rather than importing views_api, which needs the LNbits runtime.
Comments are stripped by tokenize before anything is asserted, because the
explanations of why these are gone name every string they look for.
"""
import io
import re
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

REMOVED_ROUTES = ("/api/v1/tx/build", "/api/v1/plain/spend", "/recover-keys")
REMOVED_MODELS = ("BuildTxRequest", "SpendPlainRequest", "RecoverKeysRequest")


def _code(rel: str) -> str:
    """Source with comments dropped. Strings are kept (a route is a string);
    docstrings are dropped, because they explain rather than do."""
    src = (ROOT / rel).read_text()
    out, prev = [], None
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and prev in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.NL, None):
            # a bare string statement: a docstring or a stray literal
            prev = tok.type
            continue
        out.append(tok.string)
        prev = tok.type
    return " ".join(out)


def test_the_key_taking_routes_are_gone():
    code = _code("views_api.py")
    for route in REMOVED_ROUTES:
        assert route not in code, f"{route} is back: it took a private key"


def test_their_request_models_are_gone():
    for rel in ("views_api.py", "models.py"):
        code = _code(rel)
        for name in REMOVED_MODELS:
            assert not re.search(rf"\b{name}\b", code), f"{name} in {rel}"


def test_no_handler_reads_a_spend_key_or_a_key_list_off_a_request():
    """The shape of the removed handlers, not their names: a new route that
    reads `data.spend_key` or `data.keys` is the same hole under another path.
    `ScanWalletRequest.spend_key` is deprecated, ignored and never read."""
    code = _code("views_api.py")
    for attr in ("spend_key", "keys", "xprv", "sweep_account", "priv_key"):
        assert not re.search(rf"\bdata \. {attr}\b", code), f"data.{attr} is read"


def test_the_signing_helpers_the_fixtures_depend_on_survive():
    """Removing the endpoints must not take the reference implementations with
    them: both clients are held to vectors generated from these."""
    wallet = _code("helpers/wallet.py")
    plain = _code("helpers/plain.py")
    assert re.search(r"\bdef build_transaction\b", wallet)
    assert re.search(r"\bdef build_plain_transaction\b", plain)
    assert re.search(r"\bdef plain_address_for_key\b", plain)
