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
    """Source with comments dropped. Strings are kept (a route is a string, and
    so is a dict key); a bare string STATEMENT is dropped, because that is a
    docstring and docstrings explain rather than do. Bracket depth is what tells
    the two apart: a string at the start of a line inside a call or a dict is an
    argument, not a statement."""
    src = (ROOT / rel).read_text()
    out, prev, depth = [], None, 0
    starts = (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.NL, None)
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.OP and tok.string in "([{":
            depth += 1
        elif tok.type == tokenize.OP and tok.string in ")]}":
            depth -= 1
        if tok.type == tokenize.STRING and depth == 0 and prev in starts:
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


# ── the create path ─────────────────────────────────────────────────────────
# POST /api/v1/wallet used to derive on the server when a client sent no
# sp_address: it took a mnemonic (or generated one) and a passphrase and
# answered with the scan key, the spend key and the phrase. Removed the same day
# as the three endpoints above; both clients send only {title, network,
# sp_address, last_height} (thrilla check:seed pins the payloads).

import pytest
from pydantic import ValidationError

from models import CreateWallet


@pytest.mark.parametrize("field", ["mnemonic", "passphrase"])
def test_a_seed_phrase_or_passphrase_in_the_body_is_refused_not_dropped(field):
    """Dropping it quietly would still have carried it here; refusing it says so
    to whoever is running a build that has not moved on-device."""
    with pytest.raises(ValidationError) as e:
        CreateWallet(title="w", sp_address="tsp1x", **{field: "words go here"})
    assert "does not accept a seed phrase or passphrase" in str(e.value)


@pytest.mark.parametrize("empty", [None, ""])
def test_an_empty_one_is_not_a_secret(empty):
    """An older client that always sends the field, empty, still creates."""
    CreateWallet(title="w", sp_address="tsp1x", passphrase=empty, mnemonic=empty)


def test_a_wallet_is_created_from_an_address_and_a_title():
    w = CreateWallet(title="w", network="signet", sp_address="tsp1x", last_height=5)
    assert (w.title, w.sp_address, w.last_height) == ("w", "tsp1x", "5")


def test_the_wallet_update_cannot_carry_a_secret_either():
    """PUT /wallet/{id} takes the same model."""
    with pytest.raises(ValidationError):
        CreateWallet(title="w", mnemonic="a b c")


def _create_handler() -> str:
    code = _code("views_api.py")
    start = code.index("async def api_wallet_create")
    return code[start: code.index("@ silnt_api_router . put", start)]


def test_the_create_handler_derives_nothing_and_returns_no_key():
    body = _create_handler()
    for name in ("generate_silent_wallet_address", "decrypt_mnemonic", "Mnemonic",
                 "mnemonic_plain", "passphrase", "scan_secret", "spend_key"):
        # WalletAccount(... spend_key="", scan_secret="") are blank columns, not keys
        stripped = re.sub(r'\b(spend_key|scan_secret) = ""', "", body)
        assert name not in stripped, f"{name} is back in the create handler"


def test_the_create_response_is_four_public_fields():
    body = _create_handler()
    ret = body[body.rindex("return {"):]
    keys = set(re.findall(r'"(\w+)" :', ret))
    assert keys == {"wallet_id", "sp_address", "last_height", "network"}, keys


def test_a_wallet_without_an_address_is_refused():
    body = _create_handler()
    assert "sp_address is required" in body
