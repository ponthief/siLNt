# fail2ban for LNbits

Bans addresses that probe the instance for paths that are not ours, read from
LNbits' own request log:

```
2026-11-15 02:46:39.24 | INFO | 43.157.105.119:0 - "GET /api/.env HTTP/1.1" 404
```

## Install

```bash
sudo cp filter.d/lnbits-probe.conf /etc/fail2ban/filter.d/
sudo cp jail.d/lnbits.local        /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/lnbits.local     # set logpath to <data folder>/logs/lnbits.log

# Does it match the real log? (the number of matches should be your probe count)
sudo fail2ban-regex /path/to/data/logs/lnbits.log lnbits-probe

sudo fail2ban-client reload
sudo fail2ban-client status lnbits-probe
```

`fail2ban-regex` is the first thing to run, and its **"matched"** line is the
one that matters: a filter that matches nothing leaves a jail that looks
perfectly healthy.

## What it bans, and what it deliberately does not

It matches a request for a **path** nobody legitimate asks for (dotfiles such
as `/.env` and `/.git/`, GraphQL, PHP admin panels, backup and archive names,
directory traversal, and two endpoints of other products that were asked of
this instance), answered 400–405. Three consecutive hits in an hour is a day's
ban, doubling on each repeat up to four weeks.

It is **not** "ban anything that 404s". A 404 is ordinary here: the clients ask
about a coin the scan has not found yet and are answered 404 by design, and a
stale cached client calls routes that have moved. A volume rule would ban those
users and leave the scanners alone. `tests/test_fail2ban_filter.py` takes every
route this extension declares and checks none of them can match, so a pattern
that would ban a real user fails the build instead of the user.

To add a pattern, add a line to `failregex` and a sample to the test.

## Things that will bite

- **The jail must read a file.** Debian and Ubuntu default every jail to the
  systemd journal, which ignores `logpath` entirely; the jail starts, reports
  healthy and reads nothing. `backend = auto` in the jail is what prevents that.
- **The log must contain real client addresses.** Behind Caddy that needs
  uvicorn to trust the proxy's forwarded address (`--proxy-headers` and
  `--forwarded-allow-ips`, or LNbits' equivalent). Check the log: if every line
  says `127.0.0.1`, LNbits is seeing the proxy, and the first scanner would ban
  your reverse proxy. `ignoreip` in the jail is the safety net for exactly that,
  and it also means nothing is banned until the address is fixed.
- **Docker.** If Caddy runs in a container, the host firewall's `INPUT` chain
  never sees its traffic. Use `banaction = iptables-multiport` with
  `chain = DOCKER-USER`, or ban in Caddy instead.
- **The ban closes the proxy's ports** (`http,https`), which is where the
  scanner arrives. LNbits itself listens on loopback.
- `bantime.increment` needs fail2ban 0.11 or later; older versions ignore it
  and ban for `bantime` each time.
- Unban a mistake with `fail2ban-client set lnbits-probe unbanip <address>`.

## Not covered

Caddy answers some of these probes itself and never forwards them, so they are
in Caddy's access log and not here; the same filter fits it once its log is in
the format above, which it is not by default. Failed logins are not matched
either: that needs a log line this instance does not currently write.
