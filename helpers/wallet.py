from embit import bip32
from embit import bip39
from embit.networks import NETWORKS
from binascii import hexlify
from .curve import bech32_encode, convertbits, serP, decode, Encoding
from .curve import pubkey_point_gen_from_int, int_from_bytes, Point
from loguru import logger
from lnbits.utils.crypto import AESCipher

def get_seed(mnemonic) -> bytes:
    """
    Re‑creates the BIP‑39 seed from the hard‑coded mnemonic.
    Returns the 64‑byte seed (as `bytes`).
    """    
    seed = bip39.mnemonic_to_seed(mnemonic)
    return seed

def generate_hardened_keys(seed) -> dict:    
    root = bip32.HDKey.from_seed(seed, version=NETWORKS["main"]["xprv"])    
    scan_private_key = root.derive("m/352h/0h/0h/1h/0").key.secret
    spend_private_key = root.derive("m/352h/0h/0h/0h/0").key.secret    
    scank = root.derive("m/352h/0h/0h/1h/0").key.secret    
    spendk = root.derive("m/352h/0h/0h/0h/0")    
    # Store the keys in a dictionary
    key_material = {
        'scan_priv_key': scan_private_key,
        'spend_priv_key': spend_private_key,
        'scank': hexlify(scank).decode(),
        'spendk': spendk.get_public_key()
    }
    return key_material

def encode_silent_payment_address(B_scan: Point, B_m: Point, hrp: str = 'tsp', version: int = 0) -> str:
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    ret = bech32_encode(hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M)
    if decode(hrp, ret) == (None, None):
        raise ValueError('ERROR: Invalid data.')
    return ret

def generate_silent_wallet_address(mnemonic) -> tuple:
    seed = get_seed(mnemonic)
    key_material = generate_hardened_keys(seed)       
    # Receiver's scan and spend public key 
    B_scan = pubkey_point_gen_from_int(int_from_bytes(key_material['scan_priv_key']))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(key_material['spend_priv_key']))        
    sp = encode_silent_payment_address(B_scan, B_spend, 'sp', 0)     
    return (str(sp), str(key_material['scank']), str(key_material['spendk']))

def decrypt_mnemonic(m: str | None = None, k: str | None = None, urlsafe: bool = False) -> str | None:
    """
    Decrypt message with the secret key

    Args:
        m: Message to decrypt
        k: Key used to decrypt
        urlsafe: Whether the message uses URL-safe base64 encoding
    """
    if not m:
        return None
    return AESCipher(key=k).decrypt(m, urlsafe=urlsafe)