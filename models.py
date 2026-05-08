from typing import Optional

from fastapi import Query
from pydantic import BaseModel


class BlindbitConfig(BaseModel):
    blindbit_url: str = ""
    mempool_url: str = "https://mempool.space"


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
    label_index: Optional[int] = None  # None = main wallet, int = subaccount


class ScanWalletRequest(BaseModel):
    from_height: Optional[int] = None
    to_height: Optional[int] = None
    scan_secret:  str
    spend_key:    str


class BuildTxRequest(BaseModel):
    wallet_id: str
    recipient: str
    amount: int
    fee_rate: float = 1
    memo: str = ""
    utxos: list[dict] = []
    spend_key:  str


class BroadcastTxRequest(BaseModel):
    tx_hex: str
    wallet_id: Optional[str] = None
    spent_txids: list[str] = []


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
    label_index: int
    scan_secret:  str
    spend_key:    str

class SaveAddressRequest(BaseModel):
    sp_address: str
    label_index: int
