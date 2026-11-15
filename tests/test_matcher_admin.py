"""The admin page's say over whispa-matcher, and the probe behind its status.

Four things have a way of going wrong quietly:

* **Who rules.** Once the page has saved settings they are the whole answer and
  the environment is not consulted — including "off": a page that says disabled
  over an environment that still names a network would not be the switch. Never
  saved, and the environment decides exactly as before.
* **The token is write-only.** Stored encrypted, never in what the page reads
  back, blank keeps it and "-" clears it.
* **A save refuses what a scan would ignore.** A plain-http remote URL is
  `_build`'s refusal; the page must say so at save, not leave "enabled" over a
  configuration nothing uses.
* **The probe checks the token without spending a secret.** /healthz is
  unauthenticated, so reachability alone proves nothing about the credential.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import sqlite3
import time
from typing import Optional

import httpx
import pytest
from conftest import scan
from pydantic import BaseModel

rm = scan.rust_matcher
ROOT = pathlib.Path(__file__).resolve().parent.parent
TOKEN = "abcdefgh12345678ABCDEFGH87654321"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for key in list(os.environ):
        if key.startswith("SILNT_RUST_MATCHER"):
            monkeypatch.delenv(key)
    rm.set_admin_settings(None)
    rm.reset()
    yield
    rm.set_admin_settings(None)
    rm.reset()


def admin(**kw):
    base = dict(enabled=True, networks="signet", url="http://127.0.0.1:8787",
                token=TOKEN, mode="shadow", timeout=120.0)
    base.update(kw)
    rm.set_admin_settings(base)


# ---------------------------------------------------------------- who rules

def test_saved_settings_drive_matching():
    admin()
    cfg = rm.config_for("signet")
    assert cfg is not None and cfg.url == "http://127.0.0.1:8787" and cfg.mode == "shadow"
    assert rm.config_for("mainnet") is None, "only the named network"
    assert rm.settings_source() == "admin"


def test_disabled_in_the_page_is_off_even_if_the_environment_says_on(monkeypatch):
    monkeypatch.setenv("SILNT_RUST_MATCHER_NETWORKS", "signet")
    monkeypatch.setenv("SILNT_RUST_MATCHER_URL", "http://127.0.0.1:8787")
    monkeypatch.setenv("SILNT_RUST_MATCHER_TOKEN", TOKEN)
    rm.reset()
    assert rm.config_for("signet") is not None, "environment alone still works"
    admin(enabled=False)
    assert rm.config_for("signet") is None
    assert rm.active_networks() == set()


def test_never_saved_means_the_environment_decides(monkeypatch):
    assert rm.settings_source() == "environment"
    assert rm.config_for("signet") is None
    monkeypatch.setenv("SILNT_RUST_MATCHER_NETWORKS", "all")
    monkeypatch.setenv("SILNT_RUST_MATCHER_URL", "http://localhost:9")
    monkeypatch.setenv("SILNT_RUST_MATCHER_TOKEN", TOKEN)
    rm.reset()
    assert rm.config_for("mainnet") is not None
    assert rm.active_networks() == {"all"}


def test_admin_url_still_goes_through_the_plain_http_refusal():
    admin(url="http://matcher.example.com:8787")
    assert rm.config_for("signet") is None


def test_any_config_probes_regardless_of_network():
    admin(networks="signet,mainnet")
    assert rm.any_config() is not None
    admin(enabled=False)
    assert rm.any_config() is None


# ------------------------------------------------------------ URL at save time

@pytest.mark.parametrize("url,bad", [
    ("http://127.0.0.1:8787", False),
    ("http://localhost:8787", False),
    ("http://10.0.0.5:8787", False),
    ("https://matcher.example.com", False),
    ("http://matcher.example.com:8787", True),
    ("http://8.8.8.8:8787", True),
    ("ftp://127.0.0.1", True),
    ("127.0.0.1:8787", True),
    ("", True),
])
def test_url_problem(url, bad):
    assert (rm.url_problem(url, allow_http=False) is not None) is bad


def test_url_problem_honours_the_remote_http_override():
    assert rm.url_problem("http://matcher.example.com", allow_http=True) is None


# ------------------------------------------------------------------ the token

class _Db:
    def __init__(self):
        self.c = sqlite3.connect(":memory:")
        self.c.row_factory = sqlite3.Row
        self.c.execute("ATTACH DATABASE ':memory:' AS silnt")
        self.c.execute("CREATE TABLE silnt.backend_config (id TEXT PRIMARY KEY, json_data TEXT)")

    async def execute(self, sql, params=None):
        return self.c.execute(sql, params or {})

    async def fetchone(self, sql, params=None):
        return self.c.execute(sql, params or {}).fetchone()


def _crud():
    from loguru import logger
    models = (ROOT / "models.py").read_text()
    mblock = models[models.index("class RustMatcherConfig("):models.index("class TurnstileConfig(")]
    src = (ROOT / "crud.py").read_text()
    cblock = src[src.index("async def get_rust_matcher_config("):src.index("async def get_turnstile_config(")]
    ns = {"BaseModel": BaseModel, "Optional": Optional, "json": json, "logger": logger,
          "db": _Db(), "RUST_MATCHER_CONFIG_ID": "rust_matcher_config",
          # reversible and visibly not the plaintext
          "_pj_encrypt": lambda t: "v2:" + t[::-1],
          "_pj_decrypt": lambda t: t[3:][::-1]}
    exec(mblock, ns)
    exec(cblock, ns)
    return ns


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_token_is_encrypted_at_rest_and_round_trips():
    ns = _crud()
    cfg = ns["RustMatcherConfig"](enabled=True, token=TOKEN)
    run(ns["update_rust_matcher_config"](cfg))
    raw = ns["db"].c.execute("SELECT json_data FROM silnt.backend_config").fetchone()[0]
    assert TOKEN not in raw and "v2:" in raw
    assert run(ns["get_rust_matcher_config"]()).token == TOKEN


def test_blank_token_keeps_the_stored_one_and_dash_clears_it():
    ns = _crud()
    run(ns["update_rust_matcher_config"](ns["RustMatcherConfig"](enabled=True, token=TOKEN)))
    run(ns["update_rust_matcher_config"](ns["RustMatcherConfig"](enabled=True, token="", mode="active")))
    saved = run(ns["get_rust_matcher_config"]())
    assert saved.token == TOKEN and saved.mode == "active"
    run(ns["update_rust_matcher_config"](ns["RustMatcherConfig"](enabled=False, token="-")))
    assert run(ns["get_rust_matcher_config"]()).token == ""


def test_never_saved_is_none_and_forget_returns_to_it():
    ns = _crud()
    assert run(ns["get_rust_matcher_config"]()) is None
    run(ns["update_rust_matcher_config"](ns["RustMatcherConfig"](enabled=True, token=TOKEN)))
    assert run(ns["get_rust_matcher_config"]()) is not None
    run(ns["forget_rust_matcher_config"]())
    assert run(ns["get_rust_matcher_config"]()) is None


def test_an_undecryptable_token_reads_as_unset_not_as_ciphertext():
    ns = _crud()
    run(ns["update_rust_matcher_config"](ns["RustMatcherConfig"](enabled=True, token=TOKEN)))

    def boom(_):
        raise ValueError("key gone")
    ns["_pj_decrypt"] = boom
    assert run(ns["get_rust_matcher_config"]()).token == ""


def test_the_view_never_carries_the_token():
    src = (ROOT / "views_api.py").read_text()
    view = src[src.index("def _matcher_view("):src.index('@silnt_api_router.get("/api/v1/admin/matcher/config")')]
    assert '"token_set"' in view and '"token":' not in view


def test_save_refuses_enabling_without_a_usable_token_or_url():
    src = (ROOT / "views_api.py").read_text()
    put = src[src.index("async def api_update_matcher_config("):src.index("async def api_forget_matcher_config(")]
    assert "url_problem" in put and "< 16" in put
    assert put.index("url_problem") < put.index("update_rust_matcher_config(data)"), \
        "refuse before storing"


# ------------------------------------------------------------------- the probe

def _patch_service(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)
    monkeypatch.setattr(rm.httpx, "AsyncClient", factory)


def _cfg():
    admin()
    return rm.config_for("signet")


def _service(token=TOKEN):
    def handler(request: httpx.Request):
        if request.url.path == "/healthz":
            return httpx.Response(200, json={"status": "ok", "version": "0.1.0"})
        if request.url.path == "/v1/match":
            if request.headers.get("authorization") != f"Bearer {token}":
                return httpx.Response(401, json={"error": "missing or wrong bearer token"})
            return httpx.Response(400, json={"error": "bad body"})
        return httpx.Response(404)
    return handler


def test_probe_ok(monkeypatch):
    _patch_service(monkeypatch, _service())
    out = run(rm.probe(_cfg()))
    assert out["ok"] and out["reachable"] and out["token_ok"] and out["version"] == "0.1.0"
    assert out["latency_ms"] is not None


def test_probe_reachable_but_wrong_token_is_not_ok(monkeypatch):
    _patch_service(monkeypatch, _service(token="z" * 32))
    out = run(rm.probe(_cfg()))
    assert out["reachable"] and out["token_ok"] is False and not out["ok"]
    assert "token" in out["error"].lower()


def test_probe_sends_no_scan_secret(monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.content)
        return _service()(request)
    _patch_service(monkeypatch, handler)
    run(rm.probe(_cfg()))
    assert all(c in (b"", b"{}") for c in seen)


def test_probe_service_down(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("refused")
    _patch_service(monkeypatch, handler)
    out = run(rm.probe(_cfg()))
    assert not out["ok"] and not out["reachable"] and "ConnectError" in out["error"]


def test_probe_something_else_on_the_port(monkeypatch):
    _patch_service(monkeypatch, lambda r: httpx.Response(200, text="<html>hi</html>"))
    out = run(rm.probe(_cfg()))
    assert not out["ok"] and "whispa-matcher" in out["error"]
    _patch_service(monkeypatch, lambda r: httpx.Response(200, json={"status": "nope"}))
    assert not run(rm.probe(_cfg()))["ok"]


def test_probe_service_5xx(monkeypatch):
    _patch_service(monkeypatch, lambda r: httpx.Response(503))
    out = run(rm.probe(_cfg()))
    assert not out["ok"] and "503" in out["error"]


# --------------------------------------------------------------------- the stats

def test_stats_accumulate_and_record_the_last_error():
    before = rm.stats()
    rm.note(blocks=3, seconds=0.5)
    rm.note(fallbacks=2, error="service unreachable: ConnectError")
    rm.note(mismatches=1)
    s = rm.stats()
    assert s["blocks"] - before["blocks"] == 3
    assert s["fallbacks"] - before["fallbacks"] == 2
    assert s["mismatches"] - before["mismatches"] == 1
    assert s["last_error"].startswith("service unreachable")
    assert s["last_ok"] and s["last_error_at"] and s["last_mismatch_at"]


def test_scan_reports_into_the_totals():
    src = (ROOT / "helpers" / "scan.py").read_text()
    for needle in ("rust_matcher.note(blocks=1)", "rust_matcher.note(mismatches=1)",
                   "rust_matcher.note(fallbacks=len(jobs)", "await rust_matcher.refresh_from_db()"):
        assert needle in src, needle
    assert src.index("await rust_matcher.refresh_from_db()") < src.index("cfg = rust_matcher.config_for(network)")


def test_refresh_is_a_timestamp_check_when_fresh():
    rm._admin_checked = time.monotonic()
    marker = {"called": False}

    async def go():
        import sys, types
        mod = types.ModuleType("x")

        async def boom():
            marker["called"] = True
        mod.get_rust_matcher_config = boom
        # fresh: must return before importing or reading anything
        await rm.refresh_from_db()
    run(go())
    assert marker["called"] is False


def test_the_probe_runs_in_the_health_loop_and_only_when_enabled():
    src = (ROOT / "views_api.py").read_text()
    loop = src[src.index("async def run_health_probes("):][:600]
    assert "probe_matcher_health()" in loop
    probe = src[src.index("async def probe_matcher_health("):src.index("async def run_health_probes(")]
    assert "active_networks()" in probe and probe.index("active_networks()") < probe.index("probe(cfg)")
