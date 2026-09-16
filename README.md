# SiLNt — Silent Payments Wallet Extension for LNbits

A [LNbits](https://lnbits.com) extension for managing [Silent Payment](https://silentpayments.xyz) Bitcoin wallets, with blockchain scanning powered by a self-hosted [BlindBit Oracle](https://github.com/ponthief/blindbit-oracle).

---

## Features

- Generate Silent Payment addresses from a BIP39 mnemonic
- Store and manage multiple Silent Payment wallet accounts per user
- Generate up to 10 BIP352 labeled SP subaccount addresses per wallet
- Human Readable Address support ([BIP353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) email format) — validated against SP address on create/update
- Blockchain scanning via a self-hosted BlindBit Oracle with real-time progress tracking and stop/resume
- UTXO tracking with automatic balance updates (unspent only)
- Send to Silent Payment, on-chain, or BIP353 email addresses
- Configurable Mempool URL (supports local instances via http or https)
- Admin-controlled BlindBit Oracle connection settings
- QR code display for SP addresses and subaccount addresses

---

## Requirements

- LNbits instance (self-hosted)
- Python dependencies: `embit`, `httpx`, `coincurve`, `cryptography`, `dnspython`, `ecdsa`
- A running [blindbit-oracle](https://github.com/ponthief/blindbit-oracle) instance for blockchain scanning

---

## Installation

1. As Admin user, navigate to **Settings → Extensions** and add Source:
   [Ponthief-Extensions](https://raw.githubusercontent.com/ponthief/lnbits-extensions/extensions/extensions.json)
2. Install/Enable the extension from the LNbits admin panel under **Extensions**.
3. Database migrations run automatically on first load.

---

## Configuration

### BlindBit Oracle Connection

Before scanning, an admin must configure the BlindBit Oracle connection via the **Settings** button (⚙️) in the extension UI, or via the API:

```bash
curl -X PUT https://<your-lnbits>/siLNt/api/v1/backend/config \
  -H "X-Api-Key: <admin_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "blindbit_url": "http://localhost:8001",
    "blindbit_user": "",
    "blindbit_pass": "",
    "mempool_url": "https://mempool.space"
  }'
```

### Mempool URL

The Mempool URL is configured alongside the BlindBit Oracle settings. It defaults to `https://mempool.space` but can be pointed to a local Mempool instance for added privacy. Both `http` and `https` are supported.

---

## Usage

### 1. Add a Wallet Account

Click **Silent Payments Wallet Account → New Wallet Account** and fill in:

| Field | Description |
|---|---|
| Mnemonic | 12-word BIP39 seed phrase (AES-encrypted client-side, never stored) |
| Born at Height | Block height of the wallet's first transaction — reduces scan time |
| Human Readable Address | Optional BIP353 email-format address (e.g. `alice@domain.com`) — must resolve to this wallet's SP address |

> The mnemonic is AES-encrypted using the born-at height as the key before transmission. It is never stored in the database.

### 2. Generate Labeled SP Addresses (Subaccounts)

Click **+** on a wallet row to generate a new BIP352 labeled SP address (up to 10 per wallet). Labeled addresses appear inline below the main SP address with an amber border. Click **Save** to persist to the database — unsaved addresses are marked with an `unsaved` badge.

### 3. Scan the Blockchain

Click the **Bitcoin** icon button on a wallet row to open the scan dialog. The dialog shows:
- **Scan From** — last scanned height (editable)
- **Chain Tip** — fetched live from the Oracle (editable)
- **Blocks to Scan** — calculated automatically

Click **Sync to Tip** to start scanning. A progress bar shows real-time progress. Click **Stop** to pause — progress is saved and the next scan resumes from where it left off.

### 4. Load UTXOs from DB

Click the **database** icon button on a wallet row to load previously scanned UTXOs from the local database.

### 5. Make a Payment

Click **Send** to open the Send Payment flow:
1. Select UTXOs to spend (checkbox + amount shown)
2. Enter recipient (SP address, on-chain address, or BIP353 email)
3. Set amount and fee rate
4. Click **Build Transaction** — reviews fee before broadcasting
5. Click **Broadcast** → confirm in the confirmation dialog

After broadcast, selected UTXOs are marked as spent and a Mempool link is shown in the notification.

### 6. Resolve BIP353

Click **Resolve BIP353** to look up a BIP353 email-format address and display the resolved SP address.

---

## API Reference

All endpoints are prefixed with `/siLNt/api/v1`. Authentication uses the `X-Api-Key` header.

### Wallets

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/wallet` | Invoice Key | List all wallet accounts |
| `GET` | `/wallet/{wallet_id}` | Invoice Key | Get a wallet account |
| `POST` | `/wallet` | Invoice Key | Create a wallet account |
| `PUT` | `/wallet/{wallet_id}` | Invoice Key | Update hr_address, last_height, title, balance |
| `DELETE` | `/wallet/{wallet_id}` | Invoice Key | Delete wallet, UTXOs and labeled addresses |

### Labeled SP Addresses

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/wallet/{wallet_id}/addresses` | Invoice Key | List saved labeled SP addresses |
| `POST` | `/wallet/{wallet_id}/addresses/preview` | Invoice Key | Preview a labeled SP address (not saved) |
| `POST` | `/wallet/{wallet_id}/addresses` | Invoice Key | Save a labeled SP address to DB |
| `DELETE` | `/wallet/{wallet_id}/addresses/{address_id}` | Invoice Key | Delete a labeled SP address |

### Scanning

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/wallet/{wallet_id}/scan` | Invoice Key | Scan blockchain for UTXOs |
| `POST` | `/wallet/{wallet_id}/scan/stop` | Invoice Key | Stop an in-progress scan |
| `GET` | `/wallet/{wallet_id}/scan/progress` | Invoice Key | Get real-time scan progress |

### UTXOs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/utxos?wallet_id=` | Invoice Key | Load UTXOs from DB for a wallet |

### BlindBit Oracle

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/blindbit/config` | Invoice Key | Get Oracle connection settings |
| `PUT` | `/blindbit/config` | Admin Key | Update Oracle connection settings incl. Mempool URL |
| `GET` | `/oracle/tip` | Invoice Key | Get current chain tip from Oracle |

### BIP353

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/bip353/resolve?address=` | Invoice Key | Resolve a BIP353 email-format address |

### Transactions

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/tx/build` | Admin Key | Build and sign a transaction |
| `POST` | `/tx/broadcast` | Admin Key | Broadcast a signed transaction |

### Config

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/config` | Invoice Key | Get app config including mempool endpoint |

Full interactive docs at `/docs#/siLNt` on your LNbits instance.

---

## Data Models

### WalletAccount

```json
{
  "id": "abc123xyz",
  "user": "usr_abc123",
  "title": "sp1qqw...",
  "balance": 100000,
  "hr_address": "alice@domain.com",
  "network": "mainnet",
  "last_height": 840000,
  "last_scan_height": 842000,
  "sp_address": "sp1qqw..."
}
```

### WalletAddress (Labeled SP)

```json
{
  "id": "xyz789",
  "wallet_id": "abc123xyz",
  "sp_address": "sp1qq...",
  "label_index": 1,
  "created_at": 1710000000
}
```

### BackendConfig

```json
{
  "blindbit_url": "http://localhost:8001",
  "blindbit_user": "",
  "blindbit_pass": "",
  "mempool_url": "https://mempool.space"
}
```

### UTXORecord

```json
{
  "txid": "a1b2c3...",
  "vout": 0,
  "amount": 50000,
  "priv_key_tweak": "...",
  "pub_key": "...",
  "timestamp": 1710000000,
  "utxo_state": "unspent",
  "wallet_id": "abc123xyz"
}
```

---

## Security Notes

- Mnemonics are **never stored**. AES-encrypted client-side before transmission, used only to derive keys at creation time.
- The `scan_secret` (scan private key) is encrypted at rest using a server-side Fernet key.
- The `spend_key` is encrypted at rest using the `scan_secret` as the AES key — double-layered protection.
- BIP353 `hr_address` is validated server-side on create and update — it must resolve to the wallet's SP address.
- Configure `mempool_url` to point to a local Mempool instance for transaction broadcasting privacy.
- Admin Key is required for all write operations that affect funds (tx build, broadcast, BlindBit config).

---

## Project Structure

```
siLNt/
├── __init__.py
├── views.py                    # Page routes
├── views_api.py                # REST API endpoints
├── crud.py                     # Database operations
├── models.py                   # Pydantic models
├── migrations.py               # DB schema migrations
├── helpers/
│   ├── wallet.py               # SP address derivation, key encryption, tx building
│   ├── scan.py                 # Blockchain scanner (BlindBit Oracle client)
│   ├── address_resolver.py     # BIP353 DNS resolution
│   └── curve.py                # secp256k1 EC math helpers
├── static/
│   ├── js/
│   │   ├── index.js            # Main Vue app
│   │   ├── tables.js           # Table column definitions
│   │   ├── map.js              # Data mapping functions
│   │   ├── utils.js            # Utility functions
│   │   └── bip39-word-list.js  # BIP39 word list for mnemonic validation
│   └── components/
│       ├── wallet-config.js / .html   # BlindBit Oracle settings
│       ├── wallet-list.js / .html     # Wallet table with labeled addresses
│       └── utxo-list.js / .html       # UTXO table
└── templates/
    └── silnt/
        ├── index.html
        └── _api_docs.html
```

---

## References

- [BIP352 — Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP353 — DNS Payment Instructions](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki)
- [BIP352 Light Client Specification](https://github.com/setavenger/BIP0352-light-client-specification)
- [BlindBit Oracle](https://github.com/ponthief/blindbit-oracle)

---

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

---

## Author

Created by [Ponthief](https://github.com/ponthief) at [Bitaurus](https://bitaurus.net)

---

## License

MIT
## Scanning: tuning and diagnostics

Every scan logs where its time went:

```
Scan timing: 1200 blocks, 3600 oracle requests (3.0/block), 48.2s waiting on the oracle, 1.9s matching outputs
```

Read that line before optimising anything — and note that on this workload the
answer turned out to be the opposite of the usual assumption. Measured with the
real `sync_block` over synthetic blocks:

| | µs per tweak |
|---|---|
| no labels | 92 |
| 1 label | 129 |
| 2 labels | 175 |
| 4 labels (the default scan set) | **244** |

Matching costs ~250 µs per tweak, linear in the tweak count, so a 500-tweak
block is ~0.125 s of straight computation and 160 blocks is ~20 s **before any
network time at all**. Scanning here is compute-bound, not latency-bound.

The label set is the multiplier: every tweak is combined with each label and its
negation, so the cost is O(tweaks x labels). The scan set is always four labels
(change m=0, legacy change m=1, and labeled addresses m=2,3), which is why the
default is 2.7x the no-label cost.

### Reverse matching

That multiplier exists only because `/tweaks` returns tweaks and nothing else.
Not knowing which transaction a tweak belongs to, the scanner has to enumerate
**forwards**: build every output the tweak could possibly produce — the plain
one, plus each label added and negated — and look all nine up among the block's
outputs. Nine curve operations per tweak, spent almost entirely on transactions
belonging to other people.

`/range/compute-index` pairs each tweak with its txid. Given the transaction,
the test inverts: subtract the plain candidate from that transaction's own
outputs and see whether the difference is a label. One curve operation per
output, and the label comparison becomes a set lookup.

| matcher | per block (800 tweaks, 4 labels, 2 outputs/tx) |
|---|---|
| `sync_block` (forward) | 135.7 ms |
| `sync_block_reverse` | 94.7 ms |
| | **1.43x** |

On the reported 119-block scan that is ~23.2s of matching down to ~16.2s. The
scanner uses it automatically when the oracle serves `/range/compute-index`, and
falls back to forward matching when it does not — detected once per scan.

**Both sign combinations are required.** The scanner only ever sees an output
x-only, so it reconstructs P_0 with even parity forced; where the true P_0 is
odd, the reconstruction is -P_0 and only the other sign yields the label.
Testing one sign silently misses ~40% of labeled payments — including change,
which lives at m=0. That is not hypothetical: it is precisely the defect in
`sync_block_from_compute_index`, the opt-in path behind
`SILNT_SCAN_COMPUTE_INDEX` that has never run in production.

Because this decides whether money is found, `tests/test_reverse_matching.py`
holds the two matchers to returning *identical* results — same txids, vouts,
amounts, key tweaks and labels — across a randomised corpus of plain payments,
every label, multiple outputs to us in one transaction, mixed labels, and
decoys. A separate test counts how many transactions reach extraction, because
a filter that passed everything would still be correct and would silently undo
the whole saving.

Matching runs on a **single** dedicated worker thread. This is not a limitation
to be raised: `coincurve` holds the GIL through its calls, so extra matching
threads contend rather than share. Measured on 4 cores, 8 blocks of 300 tweaks:

| | time |
|---|---|
| inline, no executor | 0.61 s |
| 1 worker | 0.64 s |
| 2 workers | 1.84 s |
| 4 workers | 2.18 s |
| default pool (`min(32, cpu+4)`) | 2.27 s |

Real parallelism needs processes, not threads. Worth doing only after the
per-tweak cost itself comes down — and the way to do that is
`SILNT_SCAN_COMPUTE_INDEX`, which moves the work to the oracle entirely.

### Range endpoints

The table above measures the matching. The other half of a scan is the requests,
and the per-block endpoints cost three of them per block — so the 1200-block
scan in that log line made 3600 requests and spent 48 s waiting on them against
1.9 s matching. Which half dominates depends entirely on the chain: a signet
block with 20 tweaks is network-bound, a mainnet block with 2000 is compute-bound.

A BlindBit oracle that reports `max_range_blocks` in `/info` serves
`/range/tweaks`, `/range/utxos` and `/range/spent-outputs`, which return a span
of blocks per request. The scanner detects this once per scan and, when it is
available, switches to batches of `SILNT_SCAN_RANGE_BATCH` blocks costing three
requests per batch instead of three per block. A 10,000-block scan goes from
~30,000 requests to ~1,200. Against an oracle without the endpoints nothing
changes: the scanner uses the per-block path exactly as before, and falls back to
it mid-scan if a range request fails.

**Fewer requests is not by itself faster.** The first version of this batched
correctly and was *slower* than the per-block path it replaced — 44s for 119
blocks where the old path managed the same work in less. Cutting requests had
worked; what broke was overlap. The per-block path gathered 24 block coroutines
at once, so while one block matched on the worker thread the others were on the
wire. Fetching a whole batch and only then matching it put the network and the
CPU in a queue behind each other, and the wall clock became their sum: 20.4s of
requests plus 23.2s of matching is the 44s exactly.

So the range path does two things beyond batching:

- The three requests for a batch go out **together**, not one after another.
  They do not depend on each other, and a batch that waits for the tweaks before
  asking for the UTXOs pays a round trip it does not need to.
- Batch N+1 is **prefetched while batch N matches**, so the network runs during
  the computation instead of before it.

Measured over that 119-block scan (~800 tweaks per block, so ~195ms of matching
each), with the request time held at the reported 20.4s:

| | wall clock |
|---|---|
| batched, sequential (the regression) | 43.4s |
| + three requests concurrently | 27.9s |
| + prefetch next batch while matching | **22.9s** |
| matching alone — the floor | 21.7s |

The batch size is the pipeline depth, which is why the default is 25 rather than
the oracle's cap: 119 blocks in batches of 100 is two stages and hides almost
nothing (27.1s), while batches of 20–40 hide essentially all of it. Bigger
batches only save requests, and at three per batch there is little left to save.

Note what the floor means. Once the network is hidden, the scan costs what the
matching costs, and nothing in the transport layer moves it. On a chain with
~800 tweaks per block this path is compute-bound, and the next lever is the
per-tweak cost or real parallelism (processes, not threads) — not requests.

Two things to know about the range responses:

- Heights the oracle never indexed are **omitted** from the response, while a
  block that genuinely holds nothing comes back present and empty. The scanner
  treats an omitted height as an error, not as an empty block.
- A range response the oracle could not finish arrives **truncated** and fails to
  parse, which the scanner reports as a failed batch. Both of these exist for the
  same reason: a block that was never read must not be recorded as scanned, or
  any payment in it stays invisible until someone rescans by hand.

When a scan cannot read a block, it stops advancing the resume point past it and
returns `gap_height`. The blocks above the gap are still scanned, but the next
scan starts from the gap and covers them again — re-scanning is slow, skipping
is wrong.

Set these in **LNbits' `.env`** (the same file as `LNBITS_ADMIN_UI` and friends),
or as real environment variables — either works. They are read with the
extension's `silnt_env` resolver, which checks the process environment first and
then parses the `.env` LNbits actually loaded, because some deployments load
that file into pydantic settings without exporting it to `os.environ`. A
restart is needed for a change to take effect; they are read once at import.

| Variable | Default | What it does |
|---|---|---|
| `SILNT_SCAN_BATCH_SIZE` | `24` | Blocks scanned concurrently on the per-block path. Lower it if the oracle starts returning timeouts or 429s; the ceiling is the HTTP pool's `max_connections` (64). |
| `SILNT_SCAN_RANGE_BATCH` | `25` | Blocks per request when the oracle supports range endpoints. This is the pipeline depth, not just a request size — raising it makes batches fewer and larger, which hides *less* of the network behind the matching, not more. Capped by the oracle's own `max_range_blocks`. |
| `SILNT_SCAN_COMPUTE_INDEX` | off | `1` uses the oracle's `compute-index` endpoint, which filters server-side instead of downloading every tweak and UTXO per block. `verify` runs both paths per block and logs any disagreement while still returning the trusted result. **Opt-in: this path has never run in production** — the branch guarding it was unreachable — and a mistake here does not raise, it silently misses outputs. Run `verify` over a range with known payments first. |
| `SILNT_ORACLE_VERIFY_TLS` | off | Verify the oracle's TLS certificate. Off by default only because that is the behaviour this has always had. Turn it on if your oracle has a valid certificate: without it, anyone on the path can serve forged tweaks and UTXOs, which shows a wrong balance and reveals which blocks a user cares about. It cannot leak keys — scanning never sees a spend key. |

### Proving the fast path before trusting it

The oracle's per-request service time is the floor on a scan: three requests per
block at ~28 ms each is ~5.7 s per hundred blocks, and no amount of client-side
concurrency gets under it if the oracle serialises. `compute-index` is the lever
that matters, because it cuts the request count rather than trying to make
requests faster.

But it decides whether your money is found, so prove it on your own data first:

```bash
SILNT_SCAN_COMPUTE_INDEX=verify   # then rescan a range whose payments you know
docker logs lnbits 2>&1 | grep "compute-index verify"
```

In `verify` mode each block is scanned **both** ways and the results compared on
(txid, vout, output key). Timestamps are excluded deliberately — the two paths
source them differently and they are display metadata, not money. The **legacy**
result is always what gets returned, so a bug in the fast path cannot cost a
payment while it is being evaluated. A silent log means they agreed; a
`MISMATCH` line names exactly which outputs differed.

Once a range with known payments comes back clean, switch to
`SILNT_SCAN_COMPUTE_INDEX=1`.

Oracle requests share one pooled, keep-alive HTTP client for the whole process.
Before that they each opened their own connection — and their own TLS handshake
— so a 10,000-block scan made roughly 30,000 connections instead of reusing a
handful.
