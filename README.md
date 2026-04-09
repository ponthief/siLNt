# SiLNt — Silent Payments Wallet Extension for LNbits

A [LNbits](https://lnbits.com) extension for managing [Silent Payment](https://silentpayments.xyz) Bitcoin wallets, with blockchain scanning powered by [BlindBit-Oracle](https://github.com/setavenger/blindbit-oracle).

---

## Features

- Generate Silent Payment addresses from a BIP39 mnemonic
- Store and manage multiple Silent Payment wallet accounts per user
- Support for Mainnet only
- Human Readable Address support ([BIP353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) email format)
- Blockchain scanning via a self-hosted BlindBit instance
- UTXO tracking with automatic balance updates (unspent only)
- Send to another SilentPayment/On-Chain or BIP-353 Address
- Admin-controlled BlindBit connection settings

---

## Requirements

- LNbits instance (self-hosted)
- Python dependencies: `embit`, `httpx`, `coincurve`
- A running [blindbit-oracle](https://github.com/setavenger/blindbit-oracle) instance for blockchain scanning

---

## Installation

1. As Admin user, navigate to Settings -> Extensions and add Source:[Ponthief-Extensions] (https://raw.githubusercontent.com/ponthief/lnbits-extensions/cardanostra/extensions.json).
2. Install/Enable the extension from the LNbits admin panel under **Extensions**.
3. Run database migrations (handled automatically on first load via LNbits migration system).

---

## Configuration

### BlindBit Connection

Before scanning, an admin must configure the BlindBit connection via the **Settings** button (⚙️) in the extension UI, or via the API:

```bash
curl -X PUT https://<your-lnbits>/silnt/api/v1/blindbit/config \
  -H "X-Api-Key: <admin_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "blindbit_url": "http://localhost:8001",    
  }'
```

---

## Usage

### 1. Add a Wallet Account

Click **Silent Payments Wallet Account** → **New Wallet Account** and fill in:

| Field | Description |
|---|---|
| Title | Display name for the wallet |
| Mnemonic | 12-word BIP39 seed phrase (encrypted client-side, never stored in plaintext) |
| Born at Height | Block height of the wallet's first transaction — reduces scan time |
| Human Readable Address | Optional BIP353 email-format address (e.g. `alice@domain.com`) |

> **Note:** The mnemonic is AES-encrypted using the born-at height as the key before being sent to the server. It is not stored in the database.

### 2. Scan the Blockchain

Click **Scan Blockchain** to proxy a scan request through LNbits to your BlindBit instance. The extension fetches:
- All UTXOs associated with the wallet's Silent Payment address
- The current block height

Wallet balance is updated automatically after each scan, counting only **unspent** UTXOs.

### 3. Make a Payment

Click **Send** to open the Send Payment flow. Select UTXOs as inputs, specify recipient, and sign the resulting transaction. Click **Broadcast** to broadcast transaction for "mining".

---

## API Reference

All endpoints are prefixed with `/silnt/api/v1`. Authentication uses the `X-Api-Key` header.

### Wallets

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/wallet` | Invoice Key | List all wallet accounts |
| `GET` | `/wallet/{wallet_id}` | Invoice Key | Get a wallet account |
| `POST` | `/wallet` | Admin Key | Create a wallet account |
| `PUT` | `/wallet/{wallet_id}` | Admin Key | Update hr_address, last_height|
| `DELETE` | `/wallet/{wallet_id}` | Admin Key | Delete wallet and all its UTXOs |

### BlindBit Config

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/blindbit/config` | Invoice Key | Get BlindBit connection settings |
| `PUT` | `/blindbit/config` | Admin Key | Update BlindBit connection settings |

### Scanning

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/scan` | Invoice Key | Proxy scan to BlindBit, returns UTXOs and height |


Full interactive docs available at `/docs#/silnt` on your LNbits instance.

---

## Data Models

### WalletAccount

```json
{
  "id": "abc123xyz",
  "user": "usr_abc123",
  "title": "My Silent Wallet",
  "balance": 100000,
  "hr_address": "alice@domain.com",
  "network": "Mainnet",
  "last_height": 840000,
  "sp_address": "sp1qqw..."
}
```

### BlindbitConfig

```json
{
  "blindbit_url": "http://localhost:8001"  
}
```

### ScanResult

```json
{
  "utxos": [
    {
      "txid": "a1b2c3...",
      "amount": 50000,
      "utxo_state": "unspent",
      "label": "",
      "timestamp": 1710000000
    }
  ],
  "height": {
    "height": 840100
  }
}
```

---

## Security Notes

- Mnemonics are **never stored in the database**. They are AES-encrypted client-side before transmission and used only to derive the Silent Payment address, scan key, and spend key at wallet creation time.
- BlindBit credentials are stored server-side and used only for proxied scan requests — they are never returned to the browser in a usable form.
- Invoice Key is required for all write operations (wallet creation, config updates, deletions).

---

## Project Structure

```
silnt/
├── __init__.py
├── views.py               # Page routes
├── views_api.py           # REST API endpoints
├── crud.py                # Database operations
├── models.py              # Pydantic models
├── migrations.py          # DB schema migrations
├── helpers/
│   └── wallet.py          # Silent Payment address derivation, mnemonic decryption
├── static/
│   ├── js/
│   │   ├── index.js       # Main Vue app
│   │   ├── tables.js      # Table definitions
│   │   ├── map.js         # Data mapping functions
│   │   └── utils.js       # Utility functions
│   └── components/
│       ├── wallet-config.js / .html
│       ├── wallet-list.js / .html
│       ├── utxo-list.js / .html
│       ├── payment.js / .html
│       └── send-to.js / .html
└── templates/
    └── silnt/
        ├── index.html
        └── _api_docs.html
```

---
## References

[BIP353 Light Client Specifications](https://github.com/setavenger/BIP0352-light-client-specification)

## Contributing

Pull requests welcome. Please open an issue first to discuss significant changes.

---

## Author

Created by [Ponthief](https://github.com/ponthief)

---

## License

MIT