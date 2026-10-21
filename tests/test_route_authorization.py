"""Authentication is not authorization, and six routes proved it.

WHAT WENT WRONG. FastAPI lets a route declare its guard two ways:

    @router.get("/x/{id}", dependencies=[Depends(require_trusted_device)])
    async def handler(id: str): ...

    @router.get("/x/{id}")
    async def handler(id: str, key_info: WalletTypeInfo = Depends(require_trusted_device)): ...

They authenticate identically. The first THROWS THE IDENTITY AWAY — the
dependency runs, raises if the caller holds no valid key, and its return value
goes nowhere. A handler written that way cannot compare the resource against
the caller even if somebody wants it to, so it does not, and the result reads
as a working guard in review.

Four routes were written that way with a resource id in them and none of the
four checked ownership: GET and DELETE /api/v1/wallet/{wallet_id},
GET /api/v1/wallet/{wallet_id}/scan/progress, POST /api/v1/utxos/restore. Two
more took `key_info` and never used it: PUT /api/v1/wallet/{wallet_id} and
POST /api/v1/tx/broadcast — whose neighbours /tx/prepare and /tx/build both
have the check, which is what makes it an oversight rather than a convention.

WHY IT WAS WORSE THAN A NORMAL IDOR. A wallet id is
`"sp" + sha256(f"{network}:{sp_address}")[:20]` (api_wallet_create), and an SP
address is PUBLISHED — handing it out is the product. So the id is not
guessable, it is COMPUTABLE from information the victim gives to everyone who
pays them. DELETE needed one request built from a public address.

These tests read the source rather than exercising the app, because the whole
class of bug is visible there and nothing else in the suite can start FastAPI.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
ROUTE_FILES = ["views_api.py", "boltz_swap.py", "boltz_refund_api.py"]
METHODS = ("get", "post", "put", "delete", "patch")
PATH_PARAM = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class Route:
    def __init__(self, file, func, src, method, path, decorator):
        self.file = file
        self.name = func.name
        self.line = func.lineno
        self.method = method
        self.path = path
        self.body = ast.get_source_segment(src, func) or ""
        self.params = PATH_PARAM.findall(path)
        # Does the SIGNATURE take a Depends(...)? That is the only form that
        # hands the handler the caller's identity.
        self.has_key_info = False
        args = func.args
        defaults = list(args.defaults or []) + list(args.kw_defaults or [])
        for d in defaults:
            if isinstance(d, ast.Call) and getattr(d.func, "id", "") == "Depends":
                self.has_key_info = True
        # And does the DECORATOR carry dependencies=[...]?
        self.decorator_only_deps = False
        for kw in decorator.keywords:
            if kw.arg == "dependencies":
                self.decorator_only_deps = not self.has_key_info

    def __repr__(self):
        return f"{self.file}:{self.line} {self.method.upper()} {self.path}"


def _routes():
    out = []
    for fn in ROUTE_FILES:
        src = (ROOT / fn).read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for d in node.decorator_list:
                if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)):
                    continue
                if d.func.attr not in METHODS:
                    continue
                path = ast.unparse(d.args[0]).strip("'\"") if d.args else "?"
                out.append(Route(fn, node, src, d.func.attr, path, d))
    return out


ROUTES = _routes()


def test_the_audit_found_the_routes():
    """A parser that silently matched nothing would make every test below
    pass. views_api.py alone carries well over a hundred routes."""
    assert len(ROUTES) > 120, len(ROUTES)


# ── the shape that caused it ─────────────────────────────────────────────────

def test_no_route_with_a_resource_id_discards_the_caller():
    """`dependencies=[Depends(...)]` and no `key_info` parameter, on a route
    that names a resource, is the bug itself: the handler is handed an id and
    nothing to check it against.

    Routes with no resource id may use that form — /oracle/tip,
    /fees/recommended and /rate/usd are global read-only data where holding a
    key is the whole of the question.
    """
    offenders = [
        r for r in ROUTES
        if r.decorator_only_deps and r.params
    ]
    assert not offenders, (
        "take key_info as a parameter and resolve the id through "
        f"_get_owned_wallet: {offenders}"
    )


# ── and the check that has to be there ───────────────────────────────────────

OWNS = re.compile(
    r"_get_owned_wallet\(|_plain_wallet_or_403\(|_pj_own_wallet\(|"
    r"\.user\s*!=\s*key_info\.wallet\.user|"
    r"wallet\.user\s*!=|not wallet or wallet\.user"
)


def test_every_handler_resolving_a_wallet_id_checks_who_owns_it():
    """`get_silnt_wallet(x)` takes an id and nothing else, so a handler that
    calls it on caller-supplied input and does not compare the owner has
    reached into whatever wallet the id named.

    Admin routes are exempt: `require_admin` is the authorization, and acting
    on another user's wallet is the job.
    """
    bad = []
    for r in ROUTES:
        if "get_silnt_wallet(" not in r.body:
            continue
        if "require_admin(" in r.body:
            continue
        if not OWNS.search(r.body):
            bad.append(r)
    assert not bad, f"resolve the wallet through _get_owned_wallet: {bad}"


@pytest.mark.parametrize(
    "path,method",
    [
        ("/api/v1/wallet/{wallet_id}", "get"),
        ("/api/v1/wallet/{wallet_id}", "put"),
        ("/api/v1/wallet/{wallet_id}", "delete"),
        ("/api/v1/wallet/{wallet_id}/scan/progress", "get"),
        ("/api/v1/tx/broadcast", "post"),
        ("/api/v1/utxos/restore", "post"),
    ],
)
def test_the_six_named_routes_go_through_the_ownership_helper(path, method):
    """Named one by one, because a general rule can be satisfied by an
    accident of phrasing and these are the six that were actually wrong. Each
    must resolve its wallet through _get_owned_wallet specifically."""
    found = [r for r in ROUTES if r.path == path and r.method == method]
    assert found, f"route disappeared: {method.upper()} {path}"
    for r in found:
        assert "_get_owned_wallet(" in r.body, r
        assert r.has_key_info, f"{r} must take key_info as a parameter"


def _tries_around_ownership_call(route):
    """Every `try` whose BODY encloses a `_get_owned_wallet(...)` call.

    By AST, because the question is containment and a regex cannot answer it:
    api_wallet_delete and the background-scan PUT both call the helper at the
    top of the function and have `except Exception` further down for
    best-effort cleanup, which a source-order match flags and should not. Only
    a try that actually wraps the call can swallow what it raises — and only
    its `body`, never its `handlers` or `orelse`.
    """
    tree = ast.parse(route.body.lstrip())
    found = []

    def walk(node, stack):
        if isinstance(node, ast.Call):
            f = node.func
            if getattr(f, "id", None) == "_get_owned_wallet" or \
               getattr(f, "attr", None) == "_get_owned_wallet":
                found.extend(stack)
        for field, value in ast.iter_fields(node):
            children = value if isinstance(value, list) else [value]
            for child in children:
                if not isinstance(child, ast.AST):
                    continue
                nxt = stack + [node] if (isinstance(node, ast.Try) and field == "body") \
                    else (stack if not isinstance(node, ast.Try) else [])
                walk(child, nxt)

    walk(tree, [])
    return found


def _swallows_http_exception(try_node):
    """True when this try would convert an HTTPException into something else.

    A handler catching Exception (or bare) swallows it, UNLESS a handler that
    re-raises HTTPException comes first — Python tries handlers in order.
    """
    for h in try_node.handlers:
        name = ast.unparse(h.type) if h.type else "BaseException"
        # Exact names, split for the `except (A, B):` tuple form. A substring
        # test would accept `except HTTPExceptionSomethingElse` as the guard,
        # which is how this check first passed its own negative control.
        caught = {n.strip() for n in name.strip("()").split(",") if n.strip()}
        if "HTTPException" in caught:
            # Only a re-raise counts. A handler that catches HTTPException and
            # returns something else is the same bug wearing a better name.
            if any(isinstance(s, ast.Raise) and s.exc is None for s in h.body):
                return False
        if name in ("Exception", "BaseException"):
            return True
    return False


def test_a_refusal_is_not_swallowed_by_a_catch_all():
    """A handler that wraps its body in `except Exception -> 400` converts the
    404 above into `400 "404: Wallet does not exist."` — wrong status, doubled
    message, and an authorization refusal that reads as a validation error.
    api_wallet_update did exactly that, to its own NOT_FOUND as well, until an
    `except HTTPException: raise` was put in front of it.

    Checked on the handlers that both resolve a wallet and catch broadly, so
    the ordering cannot be lost in a later edit.
    """
    bad = []
    for r in ROUTES:
        if "_get_owned_wallet(" not in r.body:
            continue
        for enclosing in _tries_around_ownership_call(r):
            if _swallows_http_exception(enclosing):
                bad.append(r)
                break
    assert not bad, (
        "put `except HTTPException: raise` before the catch-all: " f"{bad}"
    )


def test_the_swap_status_read_refuses_a_swap_that_is_not_the_callers():
    """/funded, /refund and DELETE all carry this check; the status read did
    not, and returned Boltz's answer for any swap id."""
    found = [r for r in ROUTES if r.path == "/api/v1/swap/in/{swap_id}"]
    assert found
    for r in found:
        assert "Not your swap" in r.body, r


# ── somebody else's wallet is 404, not 403 ───────────────────────────────────

def _owned_wallet_fn(wallet, caller_user):
    """Exec `_get_owned_wallet` in isolation with a stubbed lookup.

    By source, not by import: views_api.py reaches LNbits at module scope.
    `ast.get_source_segment` rather than a line slice, because a slice runs
    past the end of a function into whatever follows it — which is how an
    earlier helper in this suite ended up executing module constants.
    """
    src = (ROOT / "views_api.py").read_text()
    tree = ast.parse(src)
    fn_src = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
           node.name == "_get_owned_wallet":
            fn_src = ast.get_source_segment(src, node)
    assert fn_src, "_get_owned_wallet is gone — the fix has been reverted"

    class HTTPException(Exception):
        def __init__(self, status_code=None, detail=None):
            self.status_code = status_code
            self.detail = detail

    class HTTPStatus:
        NOT_FOUND = 404
        FORBIDDEN = 403

    async def get_silnt_wallet(_id):
        return wallet

    ns = {
        "HTTPException": HTTPException,
        "HTTPStatus": HTTPStatus,
        "get_silnt_wallet": get_silnt_wallet,
        "WalletTypeInfo": object,
    }
    exec(compile(fn_src, "_get_owned_wallet", "exec"), ns)  # noqa: S102

    class W:
        def __init__(self, user):
            self.user = user

    class KeyInfo:
        def __init__(self, user):
            self.wallet = W(user)

    # asyncio.run, NOT get_event_loop().run_until_complete. The latter passes
    # when this file runs alone and raises "no current event loop" once any
    # other test in the suite has closed one — a test that is green by itself
    # and red in CI is worse than no test, because it gets deleted rather than
    # read.
    import asyncio
    try:
        got = asyncio.run(ns["_get_owned_wallet"]("sp-any-id", KeyInfo(caller_user)))
        return ("ok", got)
    except HTTPException as e:
        return ("raised", e.status_code)


class _Wallet:
    def __init__(self, user):
        self.user = user


def test_the_owner_gets_their_wallet():
    kind, got = _owned_wallet_fn(_Wallet("alice"), "alice")
    assert kind == "ok"
    assert got.user == "alice"


def test_a_stranger_gets_404_and_not_403():
    """403 on a wallet id that is COMPUTABLE from a published SP address is an
    existence oracle: it answers "is this address registered here, and does it
    belong to someone else" for any address an attacker types. 404 for both a
    missing wallet and somebody else's answers nothing, and costs a legitimate
    client nothing — it only ever asks for its own."""
    assert _owned_wallet_fn(_Wallet("bob"), "alice") == ("raised", 404)


def test_a_missing_wallet_is_the_same_404():
    """Indistinguishable from the case above, which is the point."""
    assert _owned_wallet_fn(None, "alice") == ("raised", 404)


def test_the_helper_never_answers_403():
    """Pinned against a well-meaning change back to 'Access denied', which
    reads as the more informative answer and is the oracle."""
    src = (ROOT / "views_api.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
           node.name == "_get_owned_wallet":
            body = ast.get_source_segment(src, node) or ""
            assert "FORBIDDEN" not in body, body
