# Tango change as Lightning credit — design

**Status: design only. Nothing below is implemented.**

A Tango round gives each side its share back as `pieces` equal outputs. Coins
rarely total the denomination plus a fee share exactly, so the excess becomes a
change output. This describes routing that change to the LNbits instance
instead, and crediting the owner's LNbits wallet.

## The problem it addresses

The change coin is a liability that follows its owner around. It is
attributable **by construction**: its value is fixed by the round's arithmetic.
The moment it is spent — to anyone, for anything — its owner has shown which of
the two change outputs was theirs, and therefore which input subset was theirs,
and therefore which of the identical shares are theirs. Retroactively, from a
transaction made months later.

`helpers/tangolabels.py::undoes_a_round` refuses to spend a share together with
a change coin, but that only covers co-spending inside one wallet. It cannot
stop the coin being spent at all, and eventually it has to be.

## What it fixes, and what it does not

Measured with a Boltzmann implementation over the real signet round
`76d0a639…` (8 inputs, 25,000 a side as 2×12,500, change 750 and 751):

| outputs | nb_cmbn | entropy | deterministic links |
| --- | --- | --- | --- |
| 12500×4, 750, 751 — as broadcast | 25 | 4.64 | 0 |
| 12500×4, 750, 751 — paid to the service instead | 25 | 4.64 | 0 |

**Identical.** Linkability is a property of the transaction's shape — the set
of output values — and this changes only who can spend them. An LN credit is a
bookkeeping entry; the sats still have to land in an output.

So the gain is entirely **after** the transaction: the owner's wallet no longer
holds a coin that is provably from that round. That is worth having, and it is
the only thing this buys. It must not be described as making the round itself
less linkable.

A separate, non-custodial change — equalising the two change amounts and
burning the difference to the miner — is what fixes the in-transaction leak,
and only in lopsided rounds:

| A excess | B excess | as-is (links) | equalised |
| --- | --- | --- | --- |
| 750 / 751 | | 0 | 0 |
| 750 / 1,500 | | 2 | 0 |
| 750 / 4,750 | | 2 | 0 |
| 200 / 9,000 | | 1 | 0 |

The two are independent and can be done together.

## On-chain shape

Today: `[share × 2p] + [a_change] + [b_change]`

Proposed: `[share × 2p] + [a_credit] + [b_credit]`, where the two credit
outputs pay the **instance's own Silent Payments address**.

Two separate outputs, not one combined. Combining them was measured and
collapses the transaction to a single valid interpretation (nb_cmbn = 1), which
Boltzmann reports as every input linked to every output. Two outputs keep the
shape byte-for-byte identical to today's, which is the shape already measured
and understood.

**A Silent Payments address, not a fixed on-chain one.** This is not optional.
A reused address tags every Tango publicly the instant two of them pay it, and
retroactively identifies the protocol on every round the instance has ever
coordinated. With an SP address each credit output is a fresh taproot key,
indistinguishable from any other output.

## Deriving and verifying the credit outputs

Every output in a round is derived from the whole input set, and a taproot
key-path signature commits to all of them, so both clients must be able to
compute the credit outputs before either signs.

They can: deriving an output for a *recipient* needs only that recipient's SP
address and the input set, which is the ordinary send path
(`helpers/payjoin_sp.py::payment_script`). The instance's SP address is public.

Two outputs to one recipient from one transaction use successive `k` values, as
the `pieces` feature already does. The round must fix the assignment — A's
credit at `k=0`, B's at `k=1` — so both sides derive the same scripts.
`checkBeforeSigning` on both clients must verify both credit outputs against
the configured address, or a coordinator could redirect them.

## The fee

0.15% of the change, configurable. **As specified it is economically
inverted**, and this is the main thing to settle before building.

0.15% of a realistic change:

| change | 0.15% |
| --- | --- |
| 750 | 1.12 sats |
| 2,500 | 3.75 sats |
| 12,000 | 18 sats |

What it costs the instance to ever *spend* one collected output — one taproot
input, 57.5 vB:

| fee rate | cost per output | 0.15% covers it only above |
| --- | --- | --- |
| 1 sat/vB | 58 sats | 38,333 sats of change |
| 5 sat/vB | 288 sats | 191,667 sats |
| 10 sat/vB | 575 sats | 383,333 sats |
| 20 sat/vB | 1,150 sats | 766,667 sats |

A typical change is hundreds to a few thousand sats, so at every realistic fee
rate the instance loses money on every credit. Three ways out:

1. `fee = max(pct × change, 57.5 × fee_rate)` — the percentage is revenue, the
   floor is cost recovery. Recommended.
2. A flat fee.
3. Percentage only, instance absorbs the rest — viable, but it is a subsidy and
   should be a deliberate, documented one rather than an accident.

Under (1), what the user actually receives:

| change | 1 sat/vB | 5 | 10 | 20 |
| --- | --- | --- | --- | --- |
| 750 | 692 | 462 ✗ | 175 ✗ | −400 ✗ |
| 1,500 | 1,442 | 1,212 | 925 | 350 ✗ |
| 2,500 | 2,442 | 2,212 | 1,925 | 1,350 |
| 12,000 | 11,942 | 11,712 | 11,425 | 10,850 |

✗ = below the dust limit after fees.

## When it applies

Route the change only when all of these hold; otherwise keep today's behaviour
exactly.

* The change would exist at all — below `DUST_SATS` (546) it is already
  absorbed into the miner fee and there is no output to route.
* `change − fee ≥ DUST_SATS`. Routing a change that nets less than dust means
  paying to create an output worth less than the credit it produces.
* The instance has a configured SP address for this network.
* Both sides' clients understand the feature. A round where one side routes and
  the other does not has an asymmetric output set, which is itself a signal —
  see the open decisions.

## Credit lifecycle

* **Credit on confirmation, not on broadcast.** A round that never confirms
  would otherwise mint credit from nothing.
* **After N confirmations**, configurable, default 3. A one-confirmation credit
  can be reversed by a reorg, and a credit that has already been spent over
  Lightning cannot be clawed back.
* **Idempotent, keyed by `txid:vout`.** A rescan, a restart or a duplicate
  notification must not credit twice.
* A new table, roughly:
  `tango_change_credits(txid, vout, user_id, wallet_id, gross_sats, fee_sats, net_sats, status, credited_at)`
  with `PRIMARY KEY (txid, vout)` and `status` in
  `pending | credited | unspendable`.
* Crediting an LNbits wallet is a settled payment row. Every WhiSPa account has
  one — registration goes through LNbits `create_account`
  (`helpers/email_verification.py`), and the extension already authenticates on
  that wallet's `inkey`/`adminkey`.

## Solvency

The instance holds the collected outputs on chain and owes the credits. This is
custody and should be checkable rather than assumed:

```
sum(unspent collected outputs) + sum(already swept into LN)
  >= sum(outstanding credits)
```

Expose it to admin. A shortfall is the signal that something has gone wrong
before users discover it by being unable to spend.

## Spending what is collected

**Individually, not in one sweep.** A transaction consolidating many collected
outputs is a permanent public statement that all those rounds were Tangos
coordinated by this instance, and it re-links them to each other. That would
cost more privacy than the whole feature buys.

Spending them one at a time, unhurriedly, and ideally into the instance's own
mixing keeps the footprint uncorrelated. It is more expensive in fees, which is
part of what the fee floor above is paying for.

## Configuration

`BackendConfig` is a per-network JSON blob (`crud.py::get_backend_config`), so:

* `tango_change_credit_enabled` — default **false**
* `tango_change_sp_address` — the instance's SP address for this network
* `tango_change_fee_pct` — default `0.0015`
* `tango_change_fee_floor_vb` — default `57.5`, the cost basis above
* `tango_change_min_confirmations` — default `3`

Disabled by default, and with no address configured it stays off regardless.

## What the user is told

It is their money going to a third party, so it cannot be silent:

* the confirmation dialog before signing names the amount, the fee, and that it
  arrives as Lightning balance rather than as a coin;
* the round's history row shows the credit the same way it shows the fee share;
* `helpers/tango.py`'s docstring currently states the instance holds no coins at
  any point in a round. That stops being true for the change, and the docstring
  must say so — a stale claim about custody is worse than no claim.

## Open decisions

1. **Which fee model** — the floor (recommended), flat, or a deliberate
   subsidy.
2. **Always or opt-in per round.** Always is simpler and gives every round the
   same shape. Opt-in keeps a non-custodial path, at the cost of two behaviours
   and an asymmetric output set when the two sides disagree — which is a new
   signal, and arguably worse than what it preserves.
