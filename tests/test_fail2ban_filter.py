"""The fail2ban filter for LNbits' request log, tested without fail2ban.

`deploy/fail2ban/filter.d/lnbits-probe.conf` bans addresses that ask for paths
no legitimate client asks for. It was built against real log lines from this
instance, and it has two ways of going wrong that are both silent:

* **It matches nothing.** fail2ban reports a healthy jail either way. The first
  version of this filter matched zero lines because its date pattern left the
  fractional seconds at the start of the line, and the only symptom was that
  nobody was ever banned.
* **It matches a real user.** A ban on an address is a ban from the whole site.
  A 404 is normal traffic here (a pending label is answered 404 by design), so
  the filter is a list of *paths* and never "any 404", and the guard below keeps
  every route this extension defines from ever matching it.

The filter file is read with the same interpolation fail2ban applies, `<ADDR>`
is replaced with an address pattern, and fail2ban's own matching is
case-insensitive, so that is what is compiled here. The lines are the ones from
the instance's log.
"""

from __future__ import annotations

import configparser
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILTER = ROOT / "deploy" / "fail2ban" / "filter.d" / "lnbits-probe.conf"
JAIL = ROOT / "deploy" / "fail2ban" / "jail.d" / "lnbits.local"

ADDR = r"(?P<host>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]+)"


def _filter() -> configparser.ConfigParser:
    cp = configparser.ConfigParser(interpolation=configparser.BasicInterpolation())
    cp.read(FILTER)
    return cp


def _regexes() -> list[re.Pattern]:
    raw = _filter()["Definition"]["failregex"]
    lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith("#")]
    assert lines, "the filter has no failregex"
    return [re.compile(l.replace("<ADDR>", ADDR), re.IGNORECASE) for l in lines]


def _after_date(line: str) -> str:
    """What fail2ban hands the regexes: the line with its date cut off. The date
    pattern stops at the seconds, so the fraction is still there."""
    m = re.match(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d", line)
    assert m, line
    return line[m.end():]


def hit(line: str):
    rest = _after_date(line)
    for rx in _regexes():
        m = rx.search(rest)
        if m:
            return m.group("host")
    return None


def req(path: str, status: int = 404, method: str = "GET", ip: str = "198.51.100.7") -> str:
    return f'2026-11-15 02:46:39.24 | INFO | {ip}:0 - "{method} {path} HTTP/1.1" {status}'


# What the instance logged, verbatim, and who sent it.
REAL = [
    ('2026-11-15 02:46:39.24 | INFO | 43.157.105.119:0 - "GET /api/.env HTTP/1.1" 404', "43.157.105.119"),
    ('2026-11-15 02:46:41.33 | INFO | 43.157.105.119:0 - "GET /api/v1/.env HTTP/1.1" 404', "43.157.105.119"),
    ('2026-11-15 02:46:42.13 | INFO | 43.157.105.119:0 - "GET /api/v2/.env HTTP/1.1" 404', "43.157.105.119"),
    ('2026-11-15 02:58:40.49 | INFO | 45.138.12.103:0 - "GET /api/v1/auto_login HTTP/1.1" 404', "45.138.12.103"),
    ('2026-11-15 02:58:40.67 | INFO | 45.138.12.103:0 - "POST /api/v1/validate/code HTTP/1.1" 404', "45.138.12.103"),
    ('2026-11-15 05:36:54.54 | INFO | 139.59.231.238:0 - "POST /api/gql HTTP/1.1" 404', "139.59.231.238"),
    ('2026-11-15 05:37:20.03 | INFO | 81.171.74.60:0 - "GET /api/.env HTTP/1.1" 404', "81.171.74.60"),
    ('2026-11-15 06:06:24.95 | INFO | 167.71.175.236:0 - "POST /api/graphql HTTP/1.1" 404', "167.71.175.236"),
    ('2026-11-15 06:06:33.84 | INFO | 138.68.86.32:0 - "POST /api/graphql HTTP/1.1" 404', "138.68.86.32"),
    ('2026-11-15 06:06:33.85 | INFO | 206.189.19.19:0 - "POST /api/graphql HTTP/1.1" 404', "206.189.19.19"),
]


def test_every_probe_line_from_the_real_log_is_attributed_to_its_sender():
    for line, ip in REAL:
        assert hit(line) == ip, line


def test_the_error_line_without_an_address_is_not_matched():
    # It cannot be paired with the INFO line after it (they interleave), and an
    # address-less match would have nobody to ban.
    assert hit("2026-11-15 02:46:38.39 | ERROR | lnbits.exceptions:error_handler_404:167 | 404: /api/.env 404: Not Found") is None


PROBES = [
    "/.env", "/.env.production", "/api/v1/.env.local", "/.git/config", "/.aws/credentials",
    "/.ssh/id_rsa", "/.DS_Store", "/graphql", "/api/graphql", "/graphiql", "/api/gql",
    "/index.php", "/wp-login.php", "/wp-admin/setup-config.php", "/xmlrpc.php",
    "/phpmyadmin/index.php", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/luci", "/boaform/admin/formLogin", "/actuator/env", "/jenkins/login",
    "/manager/html", "/server-status", "/_ignition/execute-solution",
    "/backup.sql", "/site.tar.gz", "/www.zip", "/db.bak",
    "/../../etc/passwd", "/api/..%2f..%2fetc/passwd", "/%2e%2e/%2e%2e/etc/passwd",
    "/api/v1/auto_login", "/api/v1/validate/code", "/validate/code",
]


def test_probe_paths_are_matched_for_any_method_and_for_4xx_statuses():
    for path in PROBES:
        assert hit(req(path)) == "198.51.100.7", path
    assert hit(req("/api/.env", method="POST")) == "198.51.100.7"
    assert hit(req("/.env", status=405)) == "198.51.100.7"
    assert hit(req("/.env", status=400)) == "198.51.100.7"
    assert hit(req("/graphql?query=%7B__schema%7D")) == "198.51.100.7"
    assert hit(req("/.env", ip="2001:db8::1")) == "2001:db8::1"


def test_a_probe_that_was_actually_served_is_not_counted():
    # A 200 or a redirect is not a failed probe: whatever answered it was ours.
    for status in (200, 204, 301, 302, 500):
        assert hit(req("/.env", status=status)) is None, status


LEGITIMATE = [
    "/", "/favicon.ico", "/docs", "/redoc", "/openapi.json", "/api/v1/wallet", "/api/v1/auth",
    "/api/v1/health", "/api/v1/payments", "/static/js/base.js", "/static/vendor/vue.min.js",
    # a pending label is answered 404 by design
    "/siLNt/api/v1/wallet/abc123/utxos/0f0f0f0f/label",
    "/siLNt/api/v1/tango/rounds/7e180d9e", "/siLNt/api/v1/plain/abc",
    # words that only CONTAIN a probe word
    "/api/v1/environment", "/api/v1/envelope", "/api/v1/consoleish", "/api/v1/gqlish-not",
    "/api/v1/ownership", "/api/v1/solrish", "/static/zipcode.js", "/api/v1/old-wallets",
    "/api/v1/gitlab-webhook-not-here", "/siLNt/api/v1/admin/matcher/health",
]


def test_ordinary_paths_and_words_that_merely_contain_a_probe_word_never_match():
    for path in LEGITIMATE:
        assert hit(req(path)) is None, path
        assert hit(req(path, status=200)) is None, path


def test_no_route_this_extension_defines_can_match_even_when_it_404s():
    """The guard against banning a user. Every path the router declares is turned
    into a request and must not match; a path param is replaced with a plain id."""
    src = (ROOT / "views_api.py").read_text()
    routes = re.findall(r'@silnt_api_router\.(?:get|post|put|delete|patch)\(\s*"([^"]+)"', src)
    assert len(routes) > 100, "route extraction found too little to be a guard"
    for route in routes:
        path = "/siLNt" + re.sub(r"\{[^}]+\}", "abc123", route)
        assert hit(req(path)) is None, f"a legitimate route matches the probe filter: {route}"


def test_the_templates_and_static_pages_cannot_match_either():
    for name in ("index.html", "features.html", "how-it-works.html", "download.html", "try.html",
                 "privacy.html", "styles.css", "whispa-og.png", "clip-send.mp4"):
        assert hit(req("/" + name)) is None, name


# --- the jail --------------------------------------------------------------

def _jail() -> dict:
    cp = configparser.ConfigParser(interpolation=None, inline_comment_prefixes=None)
    cp.read(JAIL)
    return dict(cp["lnbits-probe"])


def test_the_jail_reads_a_file_not_the_journal():
    j = _jail()
    # Debian and Ubuntu default every jail to backend=systemd, which ignores
    # logpath entirely: the jail starts, looks healthy, and reads nothing.
    assert j["backend"] == "auto"
    assert j["logpath"].endswith("logs/lnbits.log")
    assert j["filter"] == "lnbits-probe"


def test_the_jail_never_bans_the_proxy_or_the_host_itself():
    ignore = _jail()["ignoreip"].split()
    for net in ("127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
        assert net in ignore, net


def test_the_jail_closes_the_proxys_ports_and_is_not_trigger_happy():
    j = _jail()
    assert j["port"] == "http,https"
    assert int(j["maxretry"]) >= 3, "one stray request must not ban an address"
    assert j["findtime"] and j["bantime"]


def test_the_filter_handles_the_percent_signs_in_encoded_traversal():
    # A bare % in a fail2ban filter is an interpolation error; the traversal
    # patterns need %%, which BasicInterpolation here decodes exactly as
    # fail2ban's reader does.
    raw = FILTER.read_text()
    assert "%%2e%%2e" in raw and "%%2f" in raw
    assert re.search(r"(?<!%)%2e", raw) is None
