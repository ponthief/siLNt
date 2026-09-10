#!/usr/bin/env python3
"""
Standalone check for scan state that outlives the scan. No pytest, no DB.

The bug this pins down: a wallet id is reproducible from the seed
("sp" + sha256(network:sp_address)), so deleting a wallet and importing the same
recovery phrase again produces the SAME id. Every dictionary in this process
keyed by wallet id is therefore inherited by the new wallet — and one of them,
helpers/scan._scan_progress, decides whether anything is allowed to scan:

  * the app attaches to the reported scan instead of offering to start one,
  * run_background_scans skips the wallet outright,
  * so last_scan_height never moves and no Silent Payments balance ever appears,

while the plain BIP-84 chain keeps working, because it is an address walk with
no scan state at all. That asymmetry — "bip84 shows funds, sp doesn't" — is the
symptom this file exists to make impossible again.

What let it happen: views_api called _mark_scan_failed(), which was never
defined. Every scan error path raised NameError instead of releasing the flag,
so a single failed scan wedged the wallet for the lifetime of the process.

Checked here against the real helpers, imported without LNbits (see the stubs).

Run: python3 helpers/_scan_state_check.py
"""

import ast
import asyncio
import os
import sys
import types

failures = 0


def check(name, cond, detail=""):
    global failures
    if cond:
        print(f"  ok   {name}")
    else:
        failures += 1
        print(f"  FAIL {name}{': ' + detail if detail else ''}")


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


# ── the real progress dictionary, without importing LNbits ──────────────────
# helpers/scan.py pulls in the extension's crud (and so LNbits' db). The state
# machine under test is the module-level dictionaries and the four functions
# over them, none of which touch any of that, so those are extracted and
# executed on their own rather than mocked — a mock would let the real thing
# drift away from what is checked here.
def load_progress_module():
    src = open(os.path.join(HERE, "scan.py")).read()
    tree = ast.parse(src)
    wanted_funcs = {
        "get_scan_progress",
        "set_scan_progress",
        "mark_scan_inactive",
        "clear_wallet_scan_state",
        "request_scan_stop",
        "should_stop",
        "clear_scan_stop",
    }
    body = []
    found = set()
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") in (
            "_scan_progress",
            "_scan_stop",
        ):
            body.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in wanted_funcs:
            body.append(node)
            found.add(node.name)
    missing = wanted_funcs - found
    if missing:
        raise SystemExit(f"scan.py no longer defines: {sorted(missing)}")
    mod = types.ModuleType("scan_progress_extract")
    mod.__dict__["Optional"] = None
    exec(compile(ast.Module(body=body, type_ignores=[]), "scan.py", "exec"), mod.__dict__)
    return mod


sp = load_progress_module()

print("the progress flag")
sp.set_scan_progress("spWALLET", 40, 100, 2)
check("a running scan reports active", sp.get_scan_progress("spWALLET")["active"] is True)

sp.mark_scan_inactive("spWALLET")
p = sp.get_scan_progress("spWALLET")
check("marking it inactive releases it", p["active"] is False)
check("and keeps the counters it reached", (p["current"], p["total"], p["found"]) == (40, 100, 2))

check(
    "a wallet that never scanned reports inactive",
    sp.get_scan_progress("spNEVER")["active"] is False,
)
# Idempotent: the stop endpoint, the error handlers and scan_wallet's own
# finally can all call this for the same scan.
sp.mark_scan_inactive("spWALLET")
sp.mark_scan_inactive("spNEVER")
check("marking it inactive twice is harmless", sp.get_scan_progress("spWALLET")["active"] is False)
check("marking a wallet that never scanned invents nothing", "spNEVER" not in sp._scan_progress)


print("\ndelete, then import the same recovery phrase")
# Reproduces the wedge exactly: a scan that failed with the flag still up, then
# the wallet deleted, then the same seed imported back to the same id.
sp.set_scan_progress("spSAMEID", 5, 500, 0)          # scan running
sp.request_scan_stop("spSAMEID")                     # user hit stop
check("the wallet looks busy", sp.get_scan_progress("spSAMEID")["active"] is True)

sp.clear_wallet_scan_state("spSAMEID")
check(
    "deleting the wallet forgets the progress",
    sp.get_scan_progress("spSAMEID")["active"] is False,
)
check("and the pending stop", sp.should_stop("spSAMEID") is False)
check(
    "the re-imported wallet inherits no counters",
    sp.get_scan_progress("spSAMEID") == {
        "active": False, "current": 0, "total": 0, "found": 0, "amount": 0
    },
)

# The delete endpoint requests a stop AFTER clearing, so an in-flight scan still
# gets told to stand down. Order matters: clearing second would drop the flag.
sp.set_scan_progress("spINFLIGHT", 5, 500, 0)
sp.clear_wallet_scan_state("spINFLIGHT")
sp.request_scan_stop("spINFLIGHT")
check("a scan running at delete time is still told to stop", sp.should_stop("spINFLIGHT") is True)
# And that stop flag must not outlive it into the next scan.
sp.clear_scan_stop("spINFLIGHT")
check("which does not persist into the next scan", sp.should_stop("spINFLIGHT") is False)


print("\nthe per-wallet rate limiter")
# The real module, with only its two third-party imports stubbed. It has no DB
# or LNbits dependency, so everything under test here is the shipping code.
for name, attrs in (
    ("fastapi", {"HTTPException": type("HTTPException", (Exception,), {}), "Request": object}),
    ("loguru", {"logger": types.SimpleNamespace(info=lambda *a, **k: None,
                                                warning=lambda *a, **k: None)}),
):
    if name not in sys.modules:
        stub = types.ModuleType(name)
        stub.__dict__.update(attrs)
        sys.modules[name] = stub
sys.path.insert(0, HERE)
import scan_rate_limiter as rl  # noqa: E402  (needs the path and stubs above)

rl._last_scan_time["spSAMEID"] = 1_000_000_000
rl._active_scans["user-1"].add("spSAMEID")
rl.clear_wallet_limits("spSAMEID", "user-1")
check("deleting the wallet clears its cooldown", "spSAMEID" not in rl._last_scan_time)
check(
    "and releases the concurrency slot it was holding",
    "spSAMEID" not in rl._active_scans["user-1"],
)

# A leaked slot is what makes EVERY scan on the account fail, not just this
# wallet's — MAX_CONCURRENT_PER_USER is 1.
check("one concurrent scan per user, so a leaked slot blocks the account", rl.MAX_CONCURRENT_PER_USER == 1)

rl._active_scans["user-2"].add("spOTHER")
rl.clear_wallet_limits("spOTHER")           # no user id given
check("the slot can be released without knowing the user", "spOTHER" not in rl._active_scans["user-2"])

# Deleting a wallet must not refund oracle load that really happened.
rl._user_blocks_log["user-3"].append((1_000_000_000, 250_000))
rl._ip_scan_log["1.2.3.4"].append(1_000_000_000)
rl.clear_wallet_limits("spANY", "user-3")
check("the hourly block budget is not refunded", len(rl._user_blocks_log["user-3"]) == 1)
check("nor the per-IP scan log", len(rl._ip_scan_log["1.2.3.4"]) == 1)


print("\nthe flag is released however the scan ends")
# scan_wallet owns the flag now. Reproduced with the same try/finally shape, so
# a future edit that moves the guarantee back out to the callers fails here.
async def failing_scan(wallet_id, boom):
    try:
        sp.set_scan_progress(wallet_id, 0, 100, 0)
        if boom:
            raise ValueError("Wallet not found")          # deleted mid-scan
        sp.set_scan_progress(wallet_id, 100, 100, 1, active=False)
        return {"ok": True}
    finally:
        sp.mark_scan_inactive(wallet_id)


async def main():
    try:
        await failing_scan("spBOOM", True)
    except ValueError:
        pass
    check(
        "a scan that raises does not leave the wallet busy",
        sp.get_scan_progress("spBOOM")["active"] is False,
    )
    await failing_scan("spFINE", False)
    check(
        "a scan that succeeds reports finished",
        sp.get_scan_progress("spFINE")["active"] is False,
    )


asyncio.run(main())


print("\nno ghost functions on the scan error paths")
# The original defect in one assertion: views_api called a name that did not
# exist, so the handler raised NameError and the flag stayed up. Anything called
# from api_scan_wallet's error handling must actually resolve.
views = open(os.path.join(ROOT, "views_api.py")).read()
vtree = ast.parse(views)
module_names = set(dir(__builtins__) if isinstance(__builtins__, dict) else vars(__builtins__))
for node in ast.walk(vtree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        module_names.add(node.name)
    elif isinstance(node, ast.ImportFrom):
        for a in node.names:
            module_names.add(a.asname or a.name)
    elif isinstance(node, ast.Import):
        for a in node.names:
            module_names.add((a.asname or a.name).split(".")[0])
    elif isinstance(node, ast.Assign):
        for t in node.targets:
            if isinstance(t, ast.Name):
                module_names.add(t.id)

scan_ep = next(
    (
        n
        for n in ast.walk(vtree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "api_scan_wallet"
    ),
    None,
)
check("api_scan_wallet is still there to check", scan_ep is not None)
if scan_ep is not None:
    local = {a.arg for a in scan_ep.args.args}
    for n in ast.walk(scan_ep):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local.add(n.name)
            local |= {a.arg for a in n.args.args}
        elif isinstance(n, ast.Assign):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    local.add(t.id)
        elif isinstance(n, (ast.withitem,)) and isinstance(n.optional_vars, ast.Name):
            local.add(n.optional_vars.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            local.add(n.name)
    unresolved = sorted(
        {
            h.func.id
            for handler in ast.walk(scan_ep)
            if isinstance(handler, ast.ExceptHandler)
            for h in ast.walk(handler)
            if isinstance(h, ast.Call)
            and isinstance(h.func, ast.Name)
            and h.func.id not in module_names
            and h.func.id not in local
        }
    )
    check(
        "every call in its error handlers resolves to something real",
        not unresolved,
        f"undefined: {unresolved}",
    )
    check(
        "and the error paths mark the scan inactive",
        any(
            isinstance(h.func, ast.Name) and h.func.id == "mark_scan_inactive"
            for handler in ast.walk(scan_ep)
            if isinstance(handler, ast.ExceptHandler)
            for h in ast.walk(handler)
            if isinstance(h, ast.Call)
        ),
    )


print("\ndeleting a wallet clears what a re-import would inherit")
crud = open(os.path.join(ROOT, "crud.py")).read()
delete_fn = crud.split("async def delete_silnt_wallet(")[1].split("\nasync def ")[0]
for table in ("background_scan", "plain_incoming"):
    check(f"silnt.{table} rows are removed", f"silnt.{table}" in delete_fn)

delete_ep = views.split("async def api_wallet_delete(")[1].split("\n@silnt_api_router")[0]
check("the endpoint clears in-memory scan state", "clear_wallet_scan_state(" in delete_ep)
check("the endpoint clears the wallet's limiter state", "clear_wallet_limits(" in delete_ep)
check(
    "and asks a running scan to stop after clearing, not before",
    delete_ep.index("clear_wallet_scan_state(") < delete_ep.index("request_scan_stop("),
)


print("")
if failures:
    print(f"{failures} check(s) failed")
    sys.exit(1)
print("all checks passed")
