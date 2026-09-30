# Tango change paid out over Lightning — design

**Status: design only. Nothing below is implemented.**

A Tango round gives each side its share back as `pieces` equal outputs. Coins
rarely total the denomination plus a fee share exactly, so the excess becomes a
change output. This describes routing that change to the **instance's** Silent
Payments address instead, and paying the owner the value over Lightning at a
**Lightning address they supply**.

Optional, per user. No Lightning address, no routing: the change output lands
in their own wallet exactly as it does today.

## Superseded

An earlier version of this document credited the owner's **LNbits wallet on
this instance**. That is no longer the plan: the instance should not be in the
business of running Lightning wallets for its users. The differences that
matter:

| | LNbits wallet (old) | Lightning address (now) |
| --- | --- | --- |
| destination | a wallet row on this instance | `satoshi@coinos.io`, theirs |
| outbound liquidity | none needed — an internal ledger entry | **real, on our node** |
| routing fees | none | ours to pay, on every payout |
| custody after payout | ours, indefinitely | ends when the payment settles |
| what we learn | nothing new | their Lightning address |
| failure mode | none worth naming | the payment can simply not go through |

The move is right — custody that ends is better than custody that does not —
but rows two, three and six are new work, not details. They are why the fee
exists at all.

## The problem it addresses

**The change coin is the strongest remaining linkability problem in Tango.**

It is attributable **by construction**: its value is fixed by the round's
arithmetic. Two ways it gives the round away, and the wallet can only defend
against one of them.

* **Spent alongside a Tangoed coin**, it links them directly — a share and its
  own round's change add up to what that side put in.
  `helpers/tangolabels.py::undoes_a_round` refuses exactly this.
* **Spent on its own**, later, to anyone, it still shows which of the two
  change outputs was its owner's. That resolves the input partition, and
  therefore which of the identical shares were theirs. Retroactively, from a
  transaction made months afterwards. Nothing in the wallet can prevent this:
  the guard covers co-spending inside one wallet, and the coin has to be spent
  eventually.

Getting that coin out of the owner's wallet is the only clean fix. No
reshaping of the round achieves it, because the coin is the problem.

## Opt-in is free here, which it was not before

The old design's second open question was whether routing should be always-on
or opt-in, because "a round where one side routes and the other does not has an
asymmetric output set, which is itself a signal".

**That worry was wrong, and it is worth being explicit about why.** Either way
the transaction has one change output per side, of exactly the same value. What
differs is only which key can spend it — the instance's or the owner's — and
that is not on the chain. An observer sees two fresh taproot outputs in both
cases. Boltzmann agrees: linkability is a function of the output *values*, and
those do not move.

So per-user opt-in costs nothing observable, and the decision is settled:
**optional, per user, and asymmetry is fine.** Both sides routing is also fine
— two credit outputs to the instance's SP address use successive `k` and are
two unrelated-looking taproot keys.

## On-chain shape

Today: `[share × 2p] + [a_change] + [b_change]`

Proposed, when A has supplied a Lightning address and B has not:

`[share × 2p] + [a_change → instance SP] + [b_change → B's own wallet]`

Byte-for-byte the same shape, which is the shape already measured. Measured
over the real signet round `76d0a639…` (8 inputs, 25,000 a side as 2×12,500,
change 750 and 751):

| outputs | nb_cmbn | entropy | deterministic links |
| --- | --- | --- | --- |
| 12500×4, 750, 751 — as broadcast | 25 | 4.64 | 0 |
| 12500×4, 750, 751 — one or both routed | 25 | 4.64 | 0 |

Identical, because only the controlling key changes. Worth recording so the
feature is not sold on the wrong claim: the transaction was never where the
change did its damage. The gain is entirely that the coin is not in the
owner's wallet afterwards.

**A Silent Payments address for the instance, not a fixed on-chain one.** Not
optional. A reused address tags every Tango publicly the instant two of them
pay it, and retroactively identifies the protocol on every round the instance
has ever coordinated. With an SP address each credit output is a fresh taproot
key.

## Deriving and verifying the credit output

Every output in a round is derived from the whole input set, and a taproot
key-path signature commits to all of them, so both clients must compute the
credit output before either signs.

They can: deriving an output for a *recipient* needs only that recipient's SP
address and the input set, which is the ordinary send path
(`helpers/payjoin_sp.py::payment_script`). The instance's SP address is public.

Two credit outputs in one round (both sides routing) use successive `k`, as
`pieces` already does, and the round must fix the assignment — A's at `k=0`,
B's at `k=1` — so both sides derive the same scripts.

**`checkBeforeSigning` on both clients must verify every credit output against
the configured address.** This is the load-bearing check: without it the
coordinator can point a change output anywhere and both sides will sign it.

## The 546-sat floor is already there

The requirement is that the instance's SP address must not accumulate amounts
too small to be worth moving, with 546 sats as the floor.

`helpers/tango.py::plan()` already enforces exactly this, for its own reasons:
a change below `DUST_SATS` (546) is dropped and added to the miner fee, twice
over, because dropping one change shrinks the transaction and can lift the
other back above dust. So a change output below 546 never exists, and the
floor costs nothing to honour — "there is a change output at all" and "it is
over 546" are the same statement.

What is **not** already handled is the floor on the *net* payout, after the fee
comes out. See below.

## The fee, and the arithmetic problem with it

The specification is **0.5% of the total transaction**, deducted from the
change, with the change output going to the instance's SP address.

**0.5% of the round does not fit inside the change.** The two are unrelated
quantities: the denomination is what the two sides agreed to mix, and the
change is whatever their coin selection happened to leave over. A large round
with a small change is not an edge case — it is the normal case.

Taking the total as both sides' denomination (`2 × denom`):

| denom | total | 0.5% fee | change 750 → net | change 2,500 → net |
| --- | --- | --- | --- | --- |
| 25,000 | 50,000 | 250 | 500 | 2,250 |
| 100,000 | 200,000 | 1,000 | **−250** | 1,500 |
| 250,000 | 500,000 | 2,500 | **−1,750** | **0** |
| 1,000,000 | 2,000,000 | 10,000 | **−9,250** | **−7,500** |

Three of those are a fee larger than the money it is charged on. On a
1,000,000-sat round the user hands over a 750-sat change coin and is owed
minus nine thousand sats.

Charging 0.5% **of the change** instead is the Boltz-analogous reading — Boltz
charges a percentage of the amount being moved, and the amount being moved
here is the change — and it cannot go negative. But on its own it collects
almost nothing:

| change | 0.5% | our cost to deliver it |
| --- | --- | --- |
| 750 | 3.75 sats | one LN routing fee + one day's SP output to sweep |
| 2,500 | 12.5 sats | same |
| 12,000 | 60 sats | same |

Our cost per payout is an LN routing fee (a few sats, sometimes more) plus,
eventually, 57.5 vB to spend the collected SP output — 58 sats at 1 sat/vB,
575 at 10. So 0.5% of the change under-recovers on every realistic round, the
same way 0.15% did in the old design.

**Recommendation: `fee = min(change − DUST_SATS, max(0.5% × change, floor))`,
and skip the routing entirely when that leaves less than the floor worth
sending.** The percentage is revenue, the floor is cost recovery, the `min`
makes it arithmetically impossible to charge more than the change. Needs a
number for `floor`; something like 50–100 sats covers a routing fee and part
of the sweep.

This needs deciding, and it is the one thing blocking implementation.

## Paying it out

Their wording is "we create an invoice". Precisely: **we ask their provider for
one and pay it.** A Lightning address is LNURL-pay (LUD-16):

1. `user@domain` → `GET https://domain/.well-known/lnurlp/user`, which returns
   `{tag: "payRequest", callback, minSendable, maxSendable, metadata}` in msat.
2. Check `minSendable ≤ net_payout ≤ maxSendable`. A provider with a 1,000-sat
   minimum cannot be paid a 500-sat change, and that has to be caught before
   the round, not after.
3. `GET callback?amount=<net_payout_msat>` → `{pr: "<bolt11>"}`.
4. Pay `pr` from the instance's Lightning wallet.

Step 2 is worth noting at proposal time: the address should be resolved and its
limits read when the user *saves* it, so an address that cannot receive a
typical change is rejected while they are looking at the setting rather than
silently failing weeks later.

**On confirmation, not on broadcast.** A round that never confirms would
otherwise pay out against nothing. After N confirmations, configurable,
default 3 — a one-confirmation payout can be reversed by a reorg, and a
Lightning payment cannot be clawed back.

**Idempotent, keyed by `txid:vout`.** A rescan, a restart or a duplicate
notification must not pay twice. A new table, roughly:

```
tango_change_payouts(
  txid, vout, user_id, ln_address, gross_sats, fee_sats, net_sats,
  status, attempts, last_error, bolt11, paid_at,
  PRIMARY KEY (txid, vout)
)
```

with `status` in `pending | invoiced | paid | failed | unpayable`.

## When the payout fails

This is the part with no equivalent in the old design, and it is the part that
makes this custody.

The change output is ours the moment the round confirms. If their Lightning
address is down, has no inbound capacity, or no route exists, we hold their
money and cannot deliver it. Retrying is right for a while and is not an
answer on its own.

Needed, and not yet designed:

* a retry schedule with a cap, then `status = failed` and the user told in the
  app rather than left to notice;
* a way for them to change the address and have it retried, since a dead
  address is the likely cause;
* an on-chain fallback — pay it to their SP address — for a payout that never
  succeeds. This costs more than the change is worth on a small one, which
  argues for a "claim it with your next round" credit instead;
* an admin view of everything outstanding, because a solvency shortfall should
  be visible to the operator before a user discovers it.

Until that path exists, this feature takes money it might not be able to
give back.

## Signet must not pay out over mainnet Lightning

A Tango on signet produces **worthless** change. A Lightning address is not
network-scoped — `satoshi@coinos.io` is a mainnet endpoint — so a signet round
whose change is routed would pay real sats for test coins. Every signet user
would be able to mint money out of a faucet.

So one of:

* the feature is **mainnet-only**, and the Lightning-address setting does not
  appear on a signet build at all (simplest, and honest);
* the payout goes to signet Lightning, which almost nothing supports;
* `tango_change_payout_enabled` is per network in `BackendConfig`, defaults
  false everywhere, and turning it on for signet is the operator's mistake to
  make.

The setting is stored per user; whether it is offered is per network.

## Solvency

Between confirmation and payout the instance holds the collected outputs on
chain and owes Lightning payments. Checkable, not assumed:

```
sum(unspent collected outputs) + sum(already paid out)
  >= sum(gross of all non-failed payouts)
```

Expose it to admin.

## Spending what is collected

**Individually, not in one sweep.** A transaction consolidating many collected
outputs is a permanent public statement that all those rounds were Tangos
coordinated by this instance, and it re-links them to each other. That would
cost more privacy than the whole feature buys. One at a time, unhurriedly, is
part of what the fee floor is paying for.

## Configuration

`BackendConfig` is a per-network JSON blob (`crud.py::get_backend_config`):

* `tango_change_payout_enabled` — default **false**
* `tango_change_sp_address` — the instance's SP address for this network
* `tango_change_fee_pct` — default `0.005`
* `tango_change_fee_floor_sats` — cost recovery; needs a number
* `tango_change_min_confirmations` — default `3`

Disabled by default, and with no address configured it stays off regardless.

## What the user is told

It is their money going to a third party and coming back over someone else's
network, so it cannot be silent:

* the setting says plainly that the change leaves their wallet, what the fee
  is, and that it arrives at the address they gave;
* the confirmation dialog before signing names the gross, the fee and the net;
* the round's history row shows the payout the way it shows the fee share, and
  shows a failed one as failed;
* `helpers/tango.py`'s docstring currently states the instance holds no coins
  at any point in a round. That stops being true, and the docstring must say
  so — a stale claim about custody is worse than no claim.

## What this costs in metadata

Worth stating because the feature is sold on privacy. Today the instance never
learns anything about a user off its own chain. After this it holds their
Lightning address, linked to their rounds; and their Lightning provider learns
that someone paid them, when, and how much.

Against that: a change coin that retroactively identifies which side of a
round was theirs, publicly and permanently, the first time it is spent. The
trade is clearly worth it — but it is a trade, and the setting should not
pretend otherwise.

## Open decisions

1. **The fee basis.** 0.5% of the total round does not fit inside the change
   and goes negative on any large round with a small change. See the tables
   above. Recommendation:
   `min(change − DUST_SATS, max(0.5% × change, floor))`, with a floor around
   50–100 sats.
2. **Which networks offer it.** Mainnet-only, or per-network config defaulting
   to off. A signet round paying out real Lightning sats is free money.
3. **The failed-payout path**, above. Needed before this can hold anyone's
   money, not after.
