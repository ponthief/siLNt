# Retiring the thrilla.me hosts

Two standalone pages that send the old hosts to their WhiSPa equivalents:

| Deploy this folder to | It sends visitors to |
|---|---|
| `thrilla.me` | `https://whispawallet.com` |
| `signet.thrilla.me` | `https://signet.whispawallet.com` |

Each is a single `index.html` with no external requests — no fonts, no images,
no stylesheet — so it redirects in one round trip. Regenerate both from the one
template with:

    python3 redirects/make-redirects.py

## They preserve the path, and that is the point

siLNt mails **absolute** links built from the frontend origin:

    helpers/email_verification.py:237   verify_url = f"{origin}/verify?token={token}"
    helpers/forgot_password.py          the reset link, the same way

So every verification and reset mail already delivered points at the old host,
and a verification token is only valid for an hour
(`VERIFICATION_TOKEN_TTL_SECONDS`). A redirect that drops the path would land
someone holding a good token on a home page and the token would expire while
they worked out what happened. These pages carry the path, query string and
fragment across, so `signet.thrilla.me/verify?token=…` arrives at
`signet.whispawallet.com/verify?token=…`.

Tested in Chromium, 8 paths per host, with JavaScript both on and off:

| | JavaScript on | JavaScript off |
|---|---|---|
| `/` | → `/` | → `/` |
| `/verify?token=abc123.def` | → same path and query | → site root |
| `/reset?key=XYZ&u=7#done` | → same path, query and fragment | → site root |
| `/download.html` | → same path | → site root |

The script runs first and does the path-preserving redirect with
`location.replace()`, so the old URL does not enter history and Back does not
bounce the visitor straight back. The `<meta http-equiv="refresh">` is the
no-JavaScript fallback; it cannot preserve a path, so it is given a 2s delay to
let the script win and only ever goes to the site root.

## One condition these pages depend on

**The old host must answer an unknown path with this `index.html`.** A browser
asking for `/verify?token=…` only runs the redirect if the host serves the page
instead of a hard 404 — otherwise the visitor gets a 404 and the redirect never
happens. Both hosts already behave this way (an unknown path returns
`index.html` with HTTP 200), so dropping the folder in is enough. If you move
them somewhere stricter, turn on the SPA/404 fallback.

## A real 301 is better, where you can do it

These pages only redirect *browser navigations to HTML*. They cannot redirect
anything else, because nothing else runs JavaScript:

- an API call to `lnbits.thrilla.me`
- an APK download link
- a `curl`, a feed reader, a link checker

A redirect rule at the edge covers all of it, returns a real `301` so search
engines transfer the ranking, and needs no page at all. On Cloudflare, one
Bulk Redirect per host with "subpath matching" and "preserve query string":

    thrilla.me/*         ->  https://whispawallet.com/$1          301
    signet.thrilla.me/*  ->  https://signet.whispawallet.com/$1   301

Do that and these pages become belt-and-braces rather than the mechanism. Keep
them anyway: they cost nothing and they explain the move to anyone who arrives
with an old bookmark.

## Still on the old domain

`thrilla.me` and `signet.thrilla.me` are handled here. These are not, and are
worth a decision of their own:

- `lnbits.thrilla.me` — the API. A redirect is **not** appropriate: moving an
  API host needs the clients pointed at the new one (`VITE_LNBITS_URL`,
  `LNBITS_URL`), and old app builds in the wild will keep calling the old name
  until their users update. Keep it serving, or 301 it at the edge so those
  builds follow.
- `admin.thrilla.me` / `admin-signet.thrilla.me` — the admin portal builds.
- `dominus@thrilla.me` — the BitMail donation name on the site. A live
  identifier, not copy: renaming it breaks resolution. Now
  `dominus@whispawallet.com`.
- `thrilla@bitaurus.net` — retired. It was two separate things wearing one
  address, and both are now `admin@whispawallet.com`:
  - **the device-confirmation sender**, which followed the mail server;
  - **the GPG signing key's uid**. The key was *not* rotated: a new uid was
    added, made primary, and the old one revoked, so the fingerprint
    `F061 E3E9 56FC F57F 99D2  FE48 81DC EBD9 74E9 CABE` is unchanged and every
    release signed before the change still verifies. download.html's
    signing-key block and its sample `gpg` output both show the new uid,
    because they have to match what `gpg` prints character for character — a
    verify page showing anything else teaches people to accept a mismatch.

  Two things revocation does not do, worth knowing before anyone reports them
  as bugs: the old uid is still physically present in the key
  (`gpg --list-options show-unusable-uids --list-keys`), and anyone who
  imported the key before the change keeps seeing the old name until they run
  `gpg --refresh-keys` or re-import. Only a brand-new key would remove the
  string, at the cost of a new fingerprint and re-signing every release.
