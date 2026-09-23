from typing import Optional, List
from fastapi import Query
from pydantic import BaseModel, Field
from datetime import datetime
import re

USERNAME_PATTERN = re.compile(r"^[a-z0-9_\-]{3,20}$")
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "support", "help", "info", "abuse",
    "postmaster", "webmaster", "system", "anthropic", "claude", "bot",
    "moderator", "mod", "service", "noreply", "no-reply", "test", "demo",
}
REQUEST_COOLDOWN_SECONDS = 24 * 3600
RECENT_REJECT_COOLDOWN   = 24 * 3600

class CreateWallet(BaseModel):
    title:       str
    network:     str = "mainnet"
    hr_address:  Optional[str] = None    
    mnemonic:    Optional[str] = None    
    passphrase:  Optional[str] = None    
    last_height: Optional[int] = None

class BackendConfig(BaseModel):
    blindbit_url: str = ""
    # API endpoint: fee tiers, broadcast, tx status, outspend and dust checks.
    # Point this at your own instance — it is the backend asking about your
    # users' transactions, and on a public explorer that traffic identifies
    # which txids each of them cares about.
    mempool_url: str = "https://mempool.space"
    # Where a *user's browser* is sent when they tap "open in explorer". Split
    # from mempool_url because the two have opposite requirements: the API
    # endpoint wants to be private and is often LAN-only, while a link has to
    # resolve on a phone that is nowhere near the node. A link also leaks far
    # less — one txid the user chose to look up, rather than every txid the
    # wallet touches. Empty falls back to mempool_url, so an install that never
    # sets it behaves exactly as before.
    explorer_url: str = "https://mempool.space"
    min_scan_height:  int = 0   # 0 = no minimum; e.g. 840000 = no scans before block 840000
    max_wallets_per_user: int = 1   # 0 = unlimited
    dust_threshold_sats:    int = 5000
    boltz_url: str = ""
    fulcrum_host: str = ""
    fulcrum_port: int = 50001
    fulcrum_tls: bool = False
    login_scan_enabled: bool = True            # auto catch-up scan on wallet open
    login_scan_auto_threshold: int = 432       # gap < this => scan silently; >= => prompt

    def explorer_base(self) -> str:
        """Base URL for links handed to a user's browser, no trailing slash.

        Falls back to mempool_url so the field can be left blank, and to the
        public explorer so a link is never built against an empty string.
        """
        return (
            self.explorer_url or self.mempool_url or "https://mempool.space"
        ).rstrip("/")

class CreateWallet(BaseModel):
    mnemonic: str = None
    title: str = None
    network: str = "mainnet"
    passphrase: Optional[str] = ""
    hr_address: Optional[str] = None
    last_height: str = None
    balance: Optional[int] = None
    # Client-derived Silent Payments address. When present, the client generated
    # the seed and derived keys on-device (server never sees the mnemonic), so the
    # server stores this address as-is and skips server-side generation/derivation.
    sp_address: Optional[str] = None


class WalletAccount(BaseModel):
    id: str
    user: str
    title: str
    balance: int
    network: str = "mainnet"
    sp_address: str
    hr_address: str
    last_height: int
    # 0 = never scanned (matches the DB column default in migrations.py). Was 1,
    # which made a freshly-created wallet report "scanned to block 1".
    last_scan_height: int = 0


class UTXORecord(BaseModel):
    txid: str
    vout: int
    amount: int
    priv_key_tweak: str
    pub_key: str
    utxo_state: str
    timestamp: int
    wallet_id: str
    label: Optional[str] = None # individual utxo user created label
    label_index: Optional[int] = None  # None = main wallet, int = subaccount
    frozen: bool = False
    freeze_reason: Optional[str]
    suspected_dust: bool = False


class ScanWalletRequest(BaseModel):
    from_height: Optional[int] = None
    to_height: Optional[int] = None
    scan_secret: str
    # Deprecated and ignored: scanning only needs the scan key + the spend PUBLIC
    # key, which the server derives from the wallet's own sp_address. The spend
    # secret is never required to scan, so clients no longer send it. Kept
    # Optional so older clients that still include it don't 422.
    spend_key: Optional[str] = None


class UtxoForTx(BaseModel):
    txid: str
    vout: int = 0
    amount: int
    priv_key_tweak: str
    pub_key: str
    label: Optional[str] = None

class BuildTxRequest(BaseModel):
    wallet_id: str
    recipient: str
    amount: int
    fee_rate: float = 1
    memo: str = ""
    utxos: list[dict]
    spend_key: str
    scan_secret:  str


class PrepareTxRequest(BaseModel):
    """Everything /tx/build takes EXCEPT the keys.

    The client signs locally (src/services/spSign.ts) and posts the finished
    tx_hex to /tx/broadcast, so the spend key stops crossing the network. The
    server keeps the two jobs that need its data rather than a secret: refusing
    coins that are frozen, spent or somebody else's, and resolving a BitMail
    through the tampering guard.

    `utxos` is outpoints only — {txid, vout}. Amounts and keys come back from
    the database, so a client cannot build against a stale amount it cached
    before a rescan.
    """

    wallet_id: str
    recipient: str
    amount: int
    fee_rate: float = 1
    utxos: list[dict]


class SpendPlainRequest(BaseModel):
    """
    Pay out of the plain BIP-84 chain. The coins go straight from there to the
    destination without entering the Silent Payments wallet — one transaction
    rather than two, and nothing ties them to the rest of the balance.

    `keys` are the raw hex private keys for the m/84'/coin'/0'/0/i addresses
    being spent, sent transiently for signing and never stored. `amount` is in
    sats; omit it to send everything on those addresses. `change_address` is
    required when sending a specific amount and must be on the same chain — the
    server refuses anything else, so a malformed request cannot route the
    remainder elsewhere.
    """
    wallet_id: str
    keys: list[str]
    destination: str
    amount: Optional[int] = None
    change_address: Optional[str] = None
    fee_rate: float = 1


class PreparePlainRequest(BaseModel):
    """
    Everything /plain/spend needs except the keys.

    The same request with `addresses` in place of `keys`: the server still finds
    the coins, checks the destination and does every piece of the arithmetic,
    but it has nothing that can move them. The client derives the addresses from
    its own xprv, so it can match each returned coin back to the key that signs
    for it without the server ever seeing one.
    """
    wallet_id: str
    addresses: list[str]
    destination: str
    amount: Optional[int] = None
    change_address: Optional[str] = None
    fee_rate: float = 1


class BroadcastPlainRequest(BaseModel):
    wallet_id: str
    tx_hex: str
    # Set ONLY when this transaction pays the wallet's own Silent Payments
    # address, so the server can report it to the user's other devices while it
    # is in flight. Those coins are entering the wallet and will be published as
    # a receive once scanned, so recording them early reveals nothing new;
    # payments out of the plain chain are deliberately never recorded.
    incoming_amount: Optional[int] = None


class RecoverKeysRequest(BaseModel):
    mnemonic:    str          # encrypted (AES-encrypted with last_height as key)
    last_height: int          # encryption key + birth height
    passphrase:  Optional[str] = None   # NEW: BIP-39 passphrase (plaintext)
    
class Config(BaseModel):
    sats_denominated: bool = True
    network: str = "mainnet"


class WalletAddress(BaseModel):
    id: str
    wallet_id: str
    sp_address: str
    label_index: int
    hr_address: Optional[str] = None
    created_at: int = 0


class PreviewAddressRequest(BaseModel):
    scan_secret: str
    # Deprecated and ignored, same as ScanRequest.spend_key above: a labelled
    # address needs the scan secret and the spend PUBLIC key, and the server
    # reads B_spend out of the wallet's own sp_address. Kept Optional so an
    # older client that still sends it doesn't 422.
    spend_key: Optional[str] = None
    label_index: Optional[int] = None   # auto-picked if None


class SaveAddressRequest(BaseModel):
    sp_address: str
    label: Optional[str] = None
    label_index: Optional[int] = None


class CloudflareConfig(BaseModel):
    api_token: str = ""
    zone_id: str = ""
    domain: str = ""


class NtfyConfig(BaseModel):
    enabled: bool = False
    server_url: str = "https://ntfy.bitaurus.net"   # base URL of the ntfy server
    topics: List[str] = []                # one or more topics to publish to
    access_token: str = ""                # optional bearer token for protected topics
    username: str = ""                    # HTTP Basic auth username (self-hosted servers)
    password: str = ""                    # HTTP Basic auth password
    priority: str = "default"             # ntfy priority: min|low|default|high|urgent


class SetupBip353Request(BaseModel):
    username: str  # e.g. "alice" → alice@yourdomain.com
    ttl: int = 300  # DNS TTL in seconds

class ForgotPasswordRequest(BaseModel):
    email: str

class InviteRequest(BaseModel):
    email: str

class UpdateUtxoLabel(BaseModel):
    label: str = ''
    wallet_id: str
    vout: Optional[int] = None

class UpdateUtxoFrozenRequest(BaseModel):
    frozen: bool

class UpdateAddressLabelRequest(BaseModel):
    label: Optional[str] = None

class TrustedDevice(BaseModel):
    id:            str
    user_id:       str
    device_id:     str
    user_agent:    Optional[str] = None
    ip:            Optional[str] = None
    label:         Optional[str] = None
    confirmed_at:  int
    last_seen_at:  int

class DeviceVerifyCodeRequest(BaseModel):
    code: str

class DeviceCheckResponse(BaseModel):
    status:        str             # 'trusted' | 'pending'
    device_count:  int
    cap:           int


class DeviceConfirmResponse(BaseModel):
    confirmed:    bool
    device_count: int
    cap:          int
    device_id:    str | None = None

class DeviceListResponse(BaseModel):
    devices:        List[TrustedDevice]
    current_device: Optional[str] = None
    cap:            int

class WhoamiResponse(BaseModel):
    user_id:   str
    username:  Optional[str] = None
    email:     Optional[str] = None
    is_admin:  bool

class UserPrefs(BaseModel):
    user_id:             str
    dust_threshold_sats: Optional[int] = None
    updated_at:          int

class UpdateUserPrefsRequest(BaseModel):
    dust_threshold_sats: Optional[int] = None    # None = revert to admin default

class Bip353Request(BaseModel):
    id:                 str
    user_id:            str
    wallet_id:          str
    sp_address:         str
    requested_username: str
    address_id:     Optional[str] = None
    final_username:     Optional[str] = None
    message:            Optional[str] = None
    status:             str   # 'pending' | 'approved' | 'rejected' | 'cancelled'
    reject_reason:      Optional[str] = None
    created_at:         int
    processed_at:       Optional[int] = None
    processed_by:       Optional[str] = None


class CreateBip353Request(BaseModel):
    wallet_id:          str
    requested_username: str
    address_id:         Optional[str] = None   # NULL = wallet base SP address
    message:            Optional[str] = Field(default=None, max_length=500)

class ApproveBip353Request(BaseModel):
    final_username: Optional[str] = None    # admin may tweak the requested name

class RejectBip353Request(BaseModel):
    reason: str = Field(..., max_length=500)

class BroadcastOutpoint(BaseModel):
    txid: str
    vout: int

class BroadcastTxRequest(BaseModel):
    tx_hex:          str
    wallet_id:       str
    # full outpoints of the inputs this tx spends
    spent_outpoints: List[BroadcastOutpoint] = []
    # optional metadata for richer Activity display before rescan
    recipient:       Optional[str] = None
    amount:          Optional[int] = None
    fee:             Optional[int] = None
    # backward-compat: older clients may still send spent_txids
    spent_txids:     Optional[List[str]] = None

class RestoreUtxoRequest(BaseModel):
    wallet_id: str
    txid: str
    vout: int
    
# ── Models ────────────────────────────────────────────────────────────────────
class CreateSwapInRequest(BaseModel):
    wallet_id: str          # LNbits wallet to receive the Lightning payment
    amount: int             # sats to receive on Lightning
    refund_address: str                  # on-chain (non-SP) address to refund to on failure
    silnt_wallet_id: Optional[str] = None  # SP wallet funding the swap (for ownership/listing)
    network: str


class SwapInResponse(BaseModel):
    swap_id: str
    address: str            # on-chain lockup address to pay
    expected_amount: int    # exact sats to send on-chain (incl. Boltz fees)
    timeout_block_height: Optional[int] = None

class BoltzSwapRecord(BaseModel):
    id: str
    wallet_id: str                       # LNbits wallet (receives LN)
    silnt_wallet_id: Optional[str] = None
    network: Optional[str] = None
    status: str = "created"              # created|funded|failed|refunded|completed
    # refund material:
    refund_privkey: str                  # hex — SENSITIVE
    refund_public_key: str               # hex (what we sent to Boltz)
    claim_public_key: str                # hex (Boltz's key from create response)
    swap_tree: dict                      # the swapTree Boltz returned (JSON)
    timeout_block_height: Optional[int] = None
    # lockup output to refund (filled once the on-chain lockup is observed):
    lockup_txid: Optional[str] = None
    lockup_vout: Optional[int] = None
    lockup_value: Optional[int] = None
    # bookkeeping:
    address: Optional[str] = None        # Boltz lockup address
    expected_amount: Optional[int] = None
    invoice: Optional[str] = None
    payment_hash: Optional[str] = None
    refund_address: Optional[str] = None # where the refund should go (user's on-chain addr)

class RefundRequest(BaseModel):
    address: Optional[str] = None   # if omitted, use the address stored at create
    fee_sats: int = 300

class FundedRequest(BaseModel):
    lockup_txid: str         # the SP-send tx that paid the Boltz lockup address

class PayjoinDescriptor(BaseModel):
    id: str
    user_id: str
    label: Optional[str] = None
    descriptor: str            # raw output descriptor (encrypted at rest)
    xpub: str                  # parsed account xpub (encrypted at rest)
    xpub_sha256: Optional[str] = None   # non-reversible dedup tag
    master_fp: str             # 8 hex chars
    account_path: str          # e.g. "84h/1h/0h"
    script_type: str = "wpkh"
    network: str
    last_sync_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class PayjoinRequest(BaseModel):
    id: str
    status: str = "PROPOSED"
    sender_user_id: str
    sender_username: str
    receiver_user_id: Optional[str] = None
    receiver_username: str
    sender_descriptor_id: str
    receiver_descriptor_id: Optional[str] = None
    amount_sats: int
    fee_rate: float
    payment_address: str
    receiver_input_sats: Optional[int] = None
    fee_sats: Optional[int] = None
    psbt: Optional[str] = None
    unsigned_psbt: Optional[str] = None
    receiver_signed_psbt: Optional[str] = None
    sender_signed_psbt: Optional[str] = None
    memo: Optional[str] = None
    tx_hex: Optional[str] = None
    txid: Optional[str] = None
    sender_inputs: Optional[str] = None     # JSON string
    receiver_input: Optional[str] = None    # JSON string
    reject_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[int] = None


# ── request bodies (FastAPI) ──────────────────────────────────────────────────
class ImportDescriptorData(BaseModel):
    descriptor: str
    label: Optional[str] = None
    network: str = "signet"


class ProposePayjoinData(BaseModel):
    sender_descriptor_id: str
    receiver_username: str
    amount_sats: int
    fee_rate: float
    # sender's selected input outpoints to spend (from their synced UTXOs):
    sender_inputs: list[dict]   # [{txid, vout, value, chain, index}, ...]

class AcceptPayjoinData(BaseModel):
    receiver_descriptor_id: str
    # the receiver's chosen contributed input:
    receiver_input: dict 

class ContributePayjoinData(BaseModel):
    receiver_descriptor_id: str
    # the receiver's chosen contributed input:
    receiver_input: dict        # {txid, vout, value, chain, index}
    # receiver's signed copy of the final unsigned PSBT (base64):
    signed_psbt: str


class FinalizePayjoinData(BaseModel):
    # sender's signed copy of the final unsigned PSBT (base64):
    signed_psbt: str

# ── invoice model (payee-initiated, directed PayJoin) ─────────────────────────
class CreateInvoiceData(BaseModel):
    # A (payee) creates a directed invoice for a specific payer B.
    receiver_descriptor_id: str       # A's wallet that receives the payment
    receiver_input: dict              # A's ONE contributed input {txid,vout,value,chain,index}
    payer_username: str               # B, chosen from the dropdown
    amount_sats: int                  # what B owes A
    fee_rate: float
    memo: Optional[str] = None


class PayInvoiceData(BaseModel):
    # B (payer) pays an invoice: commits their wallet + inputs. siLNt then builds
    # the merged PSBT. No signature yet — both sign the returned unsigned PSBT.
    sender_descriptor_id: str         # B's wallet to spend from
    sender_inputs: list[dict]         # B's selected inputs


class SignPayjoinData(BaseModel):
    # either party submits their signed copy of the pristine unsigned PSBT;
    # siLNt combines + broadcasts once BOTH are present (order-independent).
    signed_psbt: str


# ── connections (consent-based curated payer/payee list) ──────────────────────
class PayjoinContact(BaseModel):
    id: str
    status: str
    requester_user_id: str
    target_user_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class CreateContactData(BaseModel):
    username: str


class ContactLabelData(BaseModel):
    label: str = ""   # private label for a connection (blank clears it)


class SpContact(BaseModel):
    id: str
    user_id: str
    network: str = "mainnet"       # address book is per-network
    label: str
    kind: str                      # 'bitmail' | 'sp'
    value: str                     # recipient (bitmail name or sp address); decrypted on read
    value_sha256: Optional[str] = None
    created_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class CreateSpContactData(BaseModel):
    label: str
    value: str                     # 'name@domain' or 'sp1...'/'tsp1...'


class UpdateSpContactData(BaseModel):
    label: str


class BackgroundScanData(BaseModel):
    # The wallet's scan PRIVATE key (hex). Uploaded to opt a wallet into
    # server-side background scanning. Detection-only — never the spend key.
    scan_secret: str


class FcmTokenData(BaseModel):
    token: str  # Firebase Cloud Messaging device token


class AdminDeleteAccountData(BaseModel):
    identifier: str            # username or email of the account to delete
    confirm_username: str      # must match the resolved username (typed confirmation)
    delete_bitmail: bool = True

class AdminAlert(BaseModel):
    id:           str
    kind:         str
    severity:     str = "warning"
    title:        str
    detail:       str = ""
    meta:         Optional[str] = None
    acknowledged: bool = False
    created_at:   int


# ── Silent Payments PayJoin ──────────────────────────────────────────────────
# The row, and the four request bodies that move it through its states. What is
# NOT here is the point: no field on any of these carries a scan key, a spend
# key or an input's private tweak. Each party derives its own output and signs
# its own inputs on its own device; the server only ever sees public keys,
# amounts, scriptPubKeys and witnesses. See migrations.py::m031.
class PayjoinSpRequest(BaseModel):
    id: str
    status: str = "PROPOSED"
    network: str = "signet"
    # Optional because an advertised offer has no payer until a contact
    # claims it. m032 dropped the NOT NULL to match.
    payer_user_id: Optional[str] = None
    payer_username: Optional[str] = None
    payer_wallet_id: Optional[str] = None
    payee_user_id: Optional[str] = None
    payee_username: str
    payee_wallet_id: Optional[str] = None
    amount_sats: int
    fee_rate: float
    payer_in_sats: Optional[int] = None
    payee_in_sats: Optional[int] = None
    payment_sats: Optional[int] = None
    change_sats: Optional[int] = None
    fee_sats: Optional[int] = None
    vsize: Optional[int] = None
    payer_inputs: Optional[str] = None      # JSON array
    payee_inputs: Optional[str] = None      # JSON array
    payment_spk: Optional[str] = None       # hex, derived by the payee
    change_spk: Optional[str] = None        # hex, derived by the payer
    payer_witnesses: Optional[str] = None   # JSON {input index: hex}
    payee_witnesses: Optional[str] = None   # JSON {input index: hex}
    unsigned_tx: Optional[str] = None
    tx_hex: Optional[str] = None
    txid: Optional[str] = None
    reject_reason: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    expires_at: Optional[int] = None


# NO `pattern=` OR `min_length=` ON THE MODELS BELOW, and that is not laziness.
#
# This extension loads under whichever Pydantic LNbits brings, and the two
# major versions disagree about both spellings:
#
#   list length   v1 wants min_items. v2 wants min_length, and rejects regex.
#   string regex  v1 wants regex. v2 REMOVED regex and wants pattern.
#
# No spelling satisfies both. `min_length` on a list is the loud failure: under
# v1 it is a str-only constraint, so v1 warns "the following field constraints
# are set but not enforced", and that took LNbits down at import — the whole
# extension, not just this feature. `pattern=` under v1 is the quiet one, and
# worse for it: v1 has no such keyword, so it lands in the schema extras and
# validates NOTHING. The format checks would have looked present while being
# absent, on the endpoints that decide where money goes.
#
# So the shapes are checked by helpers/payjoin_sp.py::validate_wire_input and
# ::validate_spk, called from the endpoints. Those behave the same on either
# version and are unit-tested, which no Field kwarg here ever was.
#
# `gt`/`ge` stay: both versions accept and enforce them.
class PayjoinSpInput(BaseModel):
    """One contributed UTXO, as the wire sees it — public data only.

    `pub_key` is the 32-byte x-only key exactly as it sits on chain, which is
    all that taking part in the shared input set requires: the sum of the input
    PUBLIC keys is one of the two ways to reach BIP-352's shared secret, and it
    is the way that works when the inputs have two different owners.

    The hex shapes are checked by helpers/payjoin_sp.py::validate_wire_input,
    not by a Field constraint here — see the note above this class.
    """
    txid: str
    vout: int = Field(ge=0)
    pub_key: str
    amount: int = Field(gt=0)


class ProposePayjoinSpData(BaseModel):
    payer_wallet_id: str
    payee_username: str
    amount_sats: int = Field(gt=0)
    fee_rate: float = Field(gt=0)
    inputs: List[PayjoinSpInput]
    network: str = "signet"


class ContributePayjoinSpData(BaseModel):
    """The payee's half. It can derive its payment script here and only here:
    this is the first moment the complete input set is known, and the set must
    not change afterwards."""
    payee_wallet_id: str
    inputs: List[PayjoinSpInput]
    payment_spk: str


class OfferPayjoinSpData(BaseModel):
    """The payee advertising an amount. No payment_spk: it cannot be derived
    until a claimant's inputs are in, which is what CLAIMED exists for."""
    payee_wallet_id: str
    amount_sats: int = Field(gt=0)
    fee_rate: float = Field(gt=0)
    inputs: List[PayjoinSpInput]
    memo: Optional[str] = None
    network: str = "signet"


class ClaimPayjoinSpData(BaseModel):
    """A contact taking an offer, contributing the paying side's coins."""
    payer_wallet_id: str
    inputs: List[PayjoinSpInput]


class SignPayjoinSpData(BaseModel):
    """Witnesses for the caller's own inputs, keyed by their index in the
    frozen input set. `change_spk` comes with the payer's call and is absent
    from the payee's — the payee has no output of its own to derive.

    A witness here is the hex of a BIP-341 key-path signature: 64 bytes for
    SIGHASH_DEFAULT, or 65 with an explicit sighash byte.
    """
    witnesses: dict
    change_spk: Optional[str] = None
