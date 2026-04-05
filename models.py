from typing import Optional

from fastapi import Query
from pydantic import BaseModel


class BlindbitConfig(BaseModel):
    blindbit_url: str = ""


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
    scan_secret: str
    spend_key: str
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


class ScanWalletRequest(BaseModel):
    from_height: Optional[int] = None
    to_height: Optional[int] = None


class BuildTxRequest(BaseModel):
    wallet_id: str
    recipient: str
    amount: int
    fee_rate: int = 1
    memo: str = ""
    utxos: list[dict] = []  # each: {txid, amount, vout}


class BroadcastTxRequest(BaseModel):
    tx_hex: str


class Config(BaseModel):
    mempool_endpoint: str = "https://mempool.space"
    sats_denominated: bool = True
    network: str = "mainnet"

