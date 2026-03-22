from typing import Optional

from fastapi import Query
from pydantic import BaseModel


class BlindbitConfig(BaseModel):
    blindbit_url: str = ""
    auth_user: str = ""
    auth_pass: str = ""
    
class CreateWallet(BaseModel):
    mnemonic: str = Query("")
    title: str = Query("")
    network: str = "mainnet"
    hr_address: str = Query("")
    last_height: str = Query("")     


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

class UTXORecord(BaseModel):
    txid: str
    vout: str            
    amount: int    
    priv_key_tweak: str    
    pub_key: str
    timestamp: int
    utxo_state: str
    label: str
    wallet_id: str


# class Address(BaseModel):
#     id: str
#     address: str
#     wallet: str
#     amount: int = 0
#     branch_index: int = 0
#     address_index: int
#     note: Optional[str] = None
#     has_activity: bool = False


# class TransactionInput(BaseModel):
#     tx_id: str
#     vout: int
#     amount: int
#     address: str
#     branch_index: int
#     address_index: int
#     wallet: str
#     tx_hex: str


# class TransactionOutput(BaseModel):
#     amount: int
#     address: str
#     branch_index: Optional[int] = None
#     address_index: Optional[int] = None
#     wallet: Optional[str] = None




# class ExtractTx(BaseModel):
#     tx_hex = ""
#     network = "Mainnet"


# class SignedTransaction(BaseModel):
#     tx_hex: Optional[str]
    # tx_json: Optional[str]


class Config(BaseModel):
    mempool_endpoint = "https://mempool.space"    
    sats_denominated = True
    network = "mainnet"


class ConfigDb(BaseModel):
    user: str
    json_data: Config

