#!/usr/bin/env python3
"""Generate the static redirect pages that retire the thrilla.me hosts.

One template, one entry per old host, so the pages cannot drift apart. Run it
from anywhere; it writes next to itself:

    python3 redirects/make-redirects.py

Each page preserves the path, query string and fragment. That is the whole
point rather than a nicety: siLNt mails absolute links built from the frontend
origin — `{origin}/verify?token=...` in helpers/email_verification.py and the
reset link in helpers/forgot_password.py — so every verification and reset mail
already delivered points at the OLD host. A redirect that drops the path sends
someone holding a valid token to a home page, and the token expires in an hour.
"""

import pathlib

HOSTS = [
    {
        "dir": "thrilla.me",
        "old": "thrilla.me",
        "new": "https://whispawallet.com",
        "what": "the WhiSPa Wallet site",
    },
    {
        "dir": "signet.thrilla.me",
        "old": "signet.thrilla.me",
        "new": "https://signet.whispawallet.com",
        "what": "the WhiSPa Wallet app on Signet",
    },
]

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>Moved to {new_host}</title>
<link rel="canonical" href="{new}/">

<!-- Two mechanisms, deliberately. The script runs first and carries the path,
     query and fragment across, so a /verify?token=... link still lands on the
     right page. The meta refresh is the no-JavaScript fallback and cannot
     preserve the path, so it is given a 2s delay to let the script win, and
     only ever sends someone to the site root. -->
<script>
  (function () {
    try {
      var tail = location.pathname + location.search + location.hash;
      if (tail === '/' || tail === '') tail = '';
      // replace(), not assign(): the old URL must not sit in history, or Back
      // bounces the visitor straight back here.
      location.replace('{new}' + tail);
    } catch (e) { /* fall through to the meta refresh below */ }
  })();
</script>
<meta http-equiv="refresh" content="2;url={new}/">

<style>
  :root { color-scheme: light; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    min-height: 100vh; display: grid; place-items: center;
    padding: calc(24px + env(safe-area-inset-top, 0px)) 20px
             calc(24px + env(safe-area-inset-bottom, 0px));
    background: #fbfaf7; color: #16130f;
    font: 15.5px/1.6 'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif;
    text-align: center;
  }
  .card {
    max-width: 30rem; width: 100%;
    border: 1px solid #e7e2d8; border-radius: 14px; background: #fff;
    padding: 34px 26px;
    box-shadow: 0 1px 2px rgba(22,19,15,.05), 0 8px 24px rgba(22,19,15,.05);
  }
  .tag {
    font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px; letter-spacing: .12em; text-transform: uppercase;
    color: #b95c00; margin-bottom: 14px;
  }
  h1 { font-size: 25px; line-height: 1.2; font-weight: 600; letter-spacing: -.01em; margin-bottom: 12px; }
  p { color: #55504a; font-size: 14.5px; }
  p + p { margin-top: 10px; }
  .host {
    font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 13px; color: #16130f;
  }
  .go {
    display: inline-flex; align-items: center; gap: 8px; margin-top: 22px;
    padding: 11px 19px; border-radius: 10px;
    background: #f7931a; color: #1a1206;
    font-weight: 600; font-size: 14.5px; text-decoration: none;
    border: 1px solid transparent;
  }
  .go:hover { filter: brightness(1.04); }
  .note { margin-top: 18px; font-size: 12.5px; color: #857e74; }
  @media (prefers-color-scheme: dark) {
    body { background: #14120f; color: #f4f1ea; }
    .card { background: #1c1916; border-color: #2c2723; }
    h1 { color: #f4f1ea; }
    p { color: #b3aca2; }
    .host { color: #f4f1ea; }
    .note { color: #8a8278; }
  }
</style>
</head>
<body>
  <main class="card">
    <div class="tag">WhiSPa Wallet</div>
    <h1>{old_host} has moved</h1>
    <p>Thrilla is now <strong>WhiSPa Wallet</strong>. {what_cap} now lives at
       <span class="host">{new_host}</span>.</p>
    <p>Taking you there now.</p>
    <a class="go" id="go" href="{new}/">Continue <span aria-hidden="true">&rarr;</span></a>
    <p class="note">Update your bookmarks. Links you already have — including
       email verification and password-reset links — keep working: this page
       carries the rest of the address across with you.</p>
  </main>
  <script>
    // If the redirect above was blocked, at least point the button at the full
    // destination rather than the bare home page.
    (function () {
      try {
        var a = document.getElementById('go');
        var tail = location.pathname + location.search + location.hash;
        if (tail && tail !== '/') a.href = '{new}' + tail;
      } catch (e) {}
    })();
  </script>
</body>
</html>
"""

here = pathlib.Path(__file__).resolve().parent
for host in HOSTS:
    new_host = host["new"].replace("https://", "")
    page = (
        TEMPLATE.replace("{new_host}", new_host)
        .replace("{new}", host["new"])
        .replace("{old_host}", host["old"])
        .replace("{what_cap}", host["what"][0].upper() + host["what"][1:])
        .replace("{what}", host["what"])
    )
    out_dir = here / host["dir"]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "index.html").write_text(page, encoding="utf-8")
    print(f"wrote {out_dir.relative_to(here.parent)}/index.html  ->  {host['new']}")
