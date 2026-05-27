from typing import Optional, List
from fastapi import Query
from pydantic import BaseModel


class BlindbitConfig(BaseModel):
    blindbit_url: str = ""
    mempool_url: str = "https://mempool.space"
    min_scan_height:  int = 0   # 0 = no minimum; e.g. 840000 = no scans before block 840000
    max_wallets_per_user: int = 0   # 0 = unlimited
    dust_threshold_sats:    int = 5000

class CreateWallet(BaseModel):
    mnemonic: str = None
    title: str = None
    network: str = "mainnet"
    hr_address: str = None
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


class BroadcastTxRequest(BaseModel):
    tx_hex: str
    wallet_id: Optional[str] = None
    spent_txids: list[str] = []
    spent_outpoints: list[tuple[str, int]] = []   # list of [txid, vout]


class RecoverKeysRequest(BaseModel):
    mnemonic:    str          # encrypted (AES-encrypted with last_height as key)
    last_height: int          # encryption key + birth height
    
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