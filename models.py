from typing import Optional, List
from fastapi import Query
from pydantic import BaseModel, Field
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

class BlindbitConfig(BaseModel):
    blindbit_url: str = ""
    mempool_url: str = "https://mempool.space"
    min_scan_height:  int = 0   # 0 = no minimum; e.g. 840000 = no scans before block 840000
    max_wallets_per_user: int = 1   # 0 = unlimited
    dust_threshold_sats:    int = 5000
    boltz_url: str = ""

class CreateWallet(BaseModel):
    mnemonic: str = None
    title: str = None
    network: str = "mainnet"
    passphrase: Optional[str] = ""
    hr_address: Optional[str] = None
    last_height: str = None
    balance: Optional[int] = None


class WalletAccount(BaseModel):
    id: str
    user: str
    title: str
    balance: int
    network: str = "mainnet"
    sp_address: str
    hr_address: str
    last_height: int
    last_scan_height: int = 1


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
    spend_key: str


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
    created_at: int = 0


class PreviewAddressRequest(BaseModel):    
    scan_secret: str
    spend_key: str
    label_index: Optional[int] = None   # auto-picked if None


class SaveAddressRequest(BaseModel):
    sp_address: str
    label: Optional[str] = None
    label_index: Optional[int] = None


class CloudflareConfig(BaseModel):
    api_token: str = ""
    zone_id: str = ""
    domain: str = ""


class SetupBip353Request(BaseModel):
    username: str  # e.g. "alice" → alice@yourdomain.com
    ttl: int = 300  # DNS TTL in seconds

class ForgotPasswordRequest(BaseModel):
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


class DeviceCheckResponse(BaseModel):
    status:        str             # 'trusted' | 'pending'
    device_count:  int
    cap:           int


class DeviceConfirmResponse(BaseModel):
    confirmed:    bool
    device_count: int
    cap:          int

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


class SwapInResponse(BaseModel):
    swap_id: str
    address: str            # on-chain lockup address to pay
    expected_amount: int    # exact sats to send on-chain (incl. Boltz fees)
    timeout_block_height: Optional[int] = None
    not_refund_safe: bool = True

class BoltzSwapRecord(BaseModel):
    id: str
    wallet_id: str                       # LNbits wallet (receives LN)
    silnt_wallet_id: Optional[str] = None
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
    address: str          # user's on-chain destination for the refund
    fee_sats: int = 300