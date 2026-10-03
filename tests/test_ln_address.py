"""The Lightning address a Tango's change is sent to.

WHY IT IS VERIFIED WHEN IT IS SAVED AND NOT WHEN IT IS PAID. By payout time
the change output has already left the user's wallet and become the
instance's: an address that turns out to be unreachable, or a provider whose
minimum is above a typical change, is then a problem nobody can hand back.
Both are cheap to find out while the person is looking at the field.

AND WHY THE HOST IS CHECKED AT ALL. Resolving a Lightning address makes the
server fetch a URL whose host the user chose. That is a server-side request
forgery primitive pointed at whatever the backend can reach — the LNbits admin
API on localhost, a cloud metadata endpoint, anything on the same network.
`_safe_host` is not a complete defence and is not claimed as one (a hostname
whose DNS answer is private still resolves there); what it stops is the
obvious form, which is someone typing bob@127.0.0.1 into a settings field.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _mod():
    spec = importlib.util.spec_from_file_location(
        "silnt_lnaddress_for_tests", ROOT / "helpers" / "lnaddress.py"
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


LN = _mod()
LnAddressError = LN.LnAddressError


# ── the shape ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "address,local,domain",
    [
        ("satoshi@coinos.io", "satoshi", "coinos.io"),
        ("  Satoshi@CoinOS.io  ", "satoshi", "coinos.io"),
        ("a.b_c-d@sub.example.co.uk", "a.b_c-d", "sub.example.co.uk"),
    ],
)
def test_a_lightning_address_splits(address, local, domain):
    assert LN.split_address(address) == (local, domain)


@pytest.mark.parametrize(
    "bad",
    [
        "", "   ", "satoshi", "@coinos.io", "satoshi@",
        "satoshi@@coinos.io", "satoshi@coinos", "satoshi@.io",
        "sat oshi@coinos.io", "satoshi@coin os.io",
        "satoshi@-coinos.io", "satoshi@coinos-.io",
    ],
)
def test_anything_that_is_not_one_is_refused(bad):
    with pytest.raises(LnAddressError):
        LN.split_address(bad)


def test_the_refusal_says_what_one_looks_like():
    """It is a settings field, and "invalid" is not a correction."""
    with pytest.raises(LnAddressError, match="name@domain"):
        LN.split_address("satoshi")


# ── the host the server would fetch ─────────────────────────────────────────


def test_the_well_known_url_is_lud16():
    assert LN.lnurlp_url("satoshi@coinos.io") == (
        "https://coinos.io/.well-known/lnurlp/satoshi"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "bob@localhost",
        "bob@something.local",
        "bob@svc.internal",
        "bob@box.lan",
        "bob@nas.home",
        "bob@x.onion",
        "bob@metadata.google.internal",
    ],
)
def test_an_internal_host_is_refused(bad):
    """The SSRF guard, on the names it can recognise."""
    with pytest.raises(LnAddressError):
        LN.lnurlp_url(bad)


@pytest.mark.parametrize("bad", ["bob@127.0.0.1", "bob@10.0.0.1", "bob@169.254.169.254"])
def test_an_ip_literal_is_refused(bad):
    """169.254.169.254 is the cloud metadata address, and the reason this test
    names it is that it is the one worth naming."""
    with pytest.raises(LnAddressError):
        LN.lnurlp_url(bad)


def test_the_url_is_always_https():
    """Never derived from anything a response says, either — see the redirect
    setting in resolve()."""
    assert LN.lnurlp_url("satoshi@coinos.io").startswith("https://")
    src = (ROOT / "helpers" / "lnaddress.py").read_text()
    assert "follow_redirects=False" in src, (
        "a redirect can move the request to a host that never passed _safe_host"
    )


# ── the payRequest document ─────────────────────────────────────────────────


def _doc(**over):
    d = {
        "tag": "payRequest",
        "callback": "https://coinos.io/api/lnurlp/satoshi/callback",
        "minSendable": 1000,
        "maxSendable": 100_000_000,
        "metadata": '[["text/plain","pay satoshi"]]',
    }
    d.update(over)
    return d


def test_a_good_document_parses():
    ep = LN.parse_pay_response(_doc())
    assert ep.min_sendable_msat == 1000 and ep.max_sendable_msat == 100_000_000
    assert ep.callback.startswith("https://")


def test_the_limits_are_read_in_millisatoshis():
    """LUD-06 is msat and a change is sats. Getting this backwards by a factor
    of a thousand would accept every provider and then fail at payout."""
    ep = LN.parse_pay_response(_doc(minSendable=1000, maxSendable=10_000_000))
    assert ep.accepts_sats(1)            # 1 sat == 1000 msat == the minimum
    assert not ep.accepts_sats(0)
    assert ep.accepts_sats(10_000)       # the maximum
    assert not ep.accepts_sats(10_001)


@pytest.mark.parametrize(
    "doc",
    [
        {"tag": "withdrawRequest"},                     # not a pay endpoint
        _doc(callback="http://coinos.io/cb"),           # insecure callback
        _doc(callback=""),
        _doc(minSendable=0),
        _doc(maxSendable=0),
        _doc(minSendable=5000, maxSendable=1000),       # reversed
        {"status": "ERROR", "reason": "no such user"},
        {},
        "not a dict",
        _doc(minSendable="lots"),
    ],
)
def test_a_document_that_cannot_be_paid_is_refused(doc):
    with pytest.raises(LnAddressError):
        LN.parse_pay_response(doc)


def test_a_provider_error_is_passed_on_in_its_own_words():
    with pytest.raises(LnAddressError, match="no such user"):
        LN.parse_pay_response({"status": "ERROR", "reason": "no such user"})


def test_a_provider_error_cannot_paste_an_essay_into_the_ui():
    with pytest.raises(LnAddressError) as e:
        LN.parse_pay_response({"status": "ERROR", "reason": "x" * 5000})
    assert len(str(e.value)) <= 220


def test_string_limits_are_accepted():
    """Some providers send them as strings. Refusing those would reject
    working addresses for a JSON-typing detail."""
    ep = LN.parse_pay_response(_doc(minSendable="1000", maxSendable="2000"))
    assert ep.min_sendable_msat == 1000


# ── and the endpoints that use it ───────────────────────────────────────────


def _fn(path: str, name: str) -> str:
    src = (ROOT / path).read_text()
    at = src.index(f"def {name}(")
    nxt = src.find("\nasync def ", at + 10)
    other = src.find("\ndef ", at + 10)
    dec = src.find("\n@silnt_api_router", at + 10)
    ends = [i for i in (nxt, other, dec) if i != -1]
    return src[at:min(ends)] if ends else src[at:]


def test_saving_resolves_the_address_first():
    body = _fn("views_api.py", "api_tango_ln_address_set")
    assert "await resolve_ln_address(data.address)" in body
    assert "LnAddressError" in body


def test_saving_refuses_a_provider_that_cannot_take_the_smallest_payout():
    """A provider with a 1,000-sat minimum cannot receive a 546-sat change,
    and finding that out at payout is finding it out too late."""
    body = _fn("views_api.py", "api_tango_ln_address_set")
    assert "accepts_sats(smallest.net_sats)" in body
    assert "min_change_to_route(" in body


def test_every_endpoint_is_scoped_to_a_network():
    for name in (
        "api_tango_ln_address_get",
        "api_tango_ln_address_set",
        "api_tango_ln_address_delete",
    ):
        assert "network: str = Query(...)" in _fn("views_api.py", name), name


def test_saving_is_refused_off_mainnet():
    assert "_require_payout_network(network)" in _fn(
        "views_api.py", "api_tango_ln_address_set"
    )
    guard = _fn("views_api.py", "_require_payout_network")
    assert "payout_offered(network)" in guard


def test_removing_it_is_not_refused_off_mainnet():
    """If a network ever stops being offered, whatever was saved for it has to
    remain removable — otherwise the setting is a one-way door."""
    body = _fn("views_api.py", "api_tango_ln_address_delete")
    assert "_require_payout_network" not in body


def test_the_get_tells_the_client_what_the_backend_would_do():
    """So the clients do not hardcode a fee or a threshold the backend can
    change under them."""
    body = _fn("views_api.py", "api_tango_ln_address_get")
    for field in ('"fee_pct"', '"fee_floor_sats"', '"min_change_sats"',
                  '"offered"', '"ready"'):
        assert field in body, field


def test_the_address_is_encrypted_at_rest():
    """It is a recipient identity, like a saved contact — and it is the one
    piece of off-chain metadata this extension holds about its users."""
    body = _fn("crud.py", "set_tango_ln_address")
    assert "_pj_encrypt(" in body
    assert "_pj_decrypt(" in _fn("crud.py", "get_tango_ln_address")


def test_deleting_the_account_takes_it_with_it():
    """tango_rounds and background_scan were both found missing from this
    list. A new table joins it in the same change that creates it."""
    body = _fn("crud.py", "delete_all_silnt_data_for_user")
    assert "DELETE FROM silnt.tango_ln_addresses WHERE user_id = :uid" in body


def test_the_table_is_keyed_per_user_per_network():
    src = (ROOT / "migrations.py").read_text()
    body = src[src.index("async def m040_tango_ln_address"):]
    assert "PRIMARY KEY (user_id, network)" in body
    # The provider's limits are stored from the moment it was verified.
    assert "min_sendable" in body and "max_sendable" in body


# ── off, but remembered ─────────────────────────────────────────────────────
#
# "Turn off" used to DELETE the row. The address was the only record that the
# setting had ever been configured, so switching it off left an empty field
# and no way back on but remembering what had been typed. The switch and the
# address are now separate, and the three states below are what the clients
# read.


def test_the_switch_is_its_own_endpoint():
    """Not the DELETE, and not the PUT either: turning it back on must not
    depend on the provider answering right now."""
    body = _fn("views_api.py", "api_tango_ln_address_enabled")
    assert "set_tango_ln_address_enabled(" in body
    assert "resolve_ln_address" not in body, (
        "turning it back on must not re-resolve: a provider that is down "
        "today would make the switch itself fail"
    )
    assert "network: str = Query(...)" in body


def test_turning_it_on_is_still_mainnet_only():
    body = _fn("views_api.py", "api_tango_ln_address_enabled")
    assert "_require_payout_network(network)" in body
    # But turning it OFF is not: a network that stops being offered must not
    # strand somebody with a setting they cannot switch off.
    assert "if data.enabled:" in body


def test_the_switch_needs_something_to_switch():
    """Enabling with nothing saved would leave the setting looking on and
    routing nothing."""
    body = _fn("views_api.py", "api_tango_ln_address_enabled")
    assert "HTTPStatus.NOT_FOUND" in body
    crud = _fn("crud.py", "set_tango_ln_address_enabled")
    assert "return False" in crud


def test_switching_off_keeps_the_address():
    """The point of the whole change. Off must not touch the address."""
    crud = _fn("crud.py", "set_tango_ln_address_enabled")
    assert "SET enabled = :on" in crud
    # The table is called tango_ln_addresses, so look for the assignment.
    assert "address =" not in crud, "the switch must not write the address"
    assert "address," not in crud, "nor read it back out"
    assert "DELETE" not in crud


def test_saving_an_address_switches_it_on():
    """Nobody types an address in to leave it off, and a saved-but-off state
    reached by saving would look configured and route nothing."""
    body = _fn("crud.py", "set_tango_ln_address")
    assert "enabled = true" in body          # the update path
    assert "enabled)" in body and ":hi, true)" in body   # the insert path


def test_the_get_reports_the_switch():
    body = _fn("views_api.py", "api_tango_ln_address_get")
    assert '"enabled"' in body
    assert '.get("enabled")' in body


def test_a_round_reads_the_switch_not_just_the_address():
    """Someone who turned it off keeps their address. "Has an address" stopped
    meaning "wants this", and a round that ignored the switch would take a
    change coin from somebody who opted out."""
    body = _fn("views_api.py", "_tango_routes_change")
    assert 'if not saved.get("enabled"):' in body
    assert "return False" in body


def _code_lines(body: str) -> list[str]:
    """Only the lines that run. A comment saying `enabled` is the opposite of
    a bug here, and two of them say exactly why."""
    out = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(line.split("#", 1)[0])
    return out


def test_a_payout_already_owed_ignores_the_switch():
    """THE OTHER DIRECTION, and it is the one that loses money if it is wrong.
    By enqueue time the round has routed: the change output already paid this
    instance and the value is owed. Reading the switch here would strand it.
    Same for a retry of an owed payout."""
    for name in ("enqueue_tango_payouts", "api_admin_tango_payout_retry"):
        body = _fn("views_api.py", name)
        assert "get_tango_ln_address(" in body, name
        offenders = [ln for ln in _code_lines(body) if "enabled" in ln]
        assert not offenders, (name, offenders)


def test_the_switch_column_defaults_to_on():
    """Every row that existed was an address somebody saved while this was the
    only state there was. They were all on."""
    src = (ROOT / "migrations.py").read_text()
    body = src[src.index("async def m043_tango_ln_address_switch"):]
    assert "ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true" in body
    # IF NOT EXISTS because the renumbering means an instance can arrive
    # at these migrations having already run some of them.


def test_forgetting_it_is_still_possible():
    """Switching off is about future rounds; forgetting is about what this
    server holds. Both have to exist."""
    body = _fn("crud.py", "delete_tango_ln_address")
    assert "DELETE FROM silnt.tango_ln_addresses" in body
