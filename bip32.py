from embit import script
from embit import bip32
from embit import bip39, base58
from embit.networks import NETWORKS
import random
import hmac
import os
from typing import Tuple, List
import hashlib
from typing import Tuple
from binascii import unhexlify
from ecdsa import SigningKey, SECP256k1
# from mnemonic import Mnemonic

# Elliptic curve parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Points are tuples of X and Y coordinates
# the point at infinity is represented by the None keyword
Point = Tuple[int, int]

from enum import Enum
from typing import Optional, Tuple

class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""
    BECH32 = 1
    BECH32M = 2

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3

# Point addition
def point_add(P1: Optional[Point], P2: Optional[Point]) -> Optional[Point]:
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    if (x(P1) == x(P2)) and (y(P1) != y(P2)):
        return None
    if P1 == P2:
        lam = (3 * x(P1) * x(P1) * pow(2 * y(P1), p - 2, p)) % p
    else:
        lam = ((y(P2) - y(P1)) * pow(x(P2) - x(P1), p - 2, p)) % p
    x3 = (lam * lam - x(P1) - x(P2)) % p
    return x3, (lam * (x(P1) - x3) - y(P1)) % p


# Point multiplication
def point_mul(P: Optional[Point], d: int) -> Optional[Point]:
    R = None
    for i in range(256):
        if (d >> i) & 1:
            R = point_add(R, P)
        P = point_add(P, P)
    return R

# Check if a point has even y coordinate
def has_even_y(P: Point) -> bool:
    return y(P) % 2 == 0

# Get bytes from an int
def bytes_from_int(a: int) -> bytes:
    return a.to_bytes(32, byteorder="big")

# Get bytes from a point
def bytes_from_point(P: Point) -> bytes:
    return bytes_from_int(x(P))

# Get bytes from a hex
def bytes_from_hex(a: str) -> bytes:
    return unhexlify(a)

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()


def derive_hardened_key(master_key: bytes, index: int) -> bytes:
    index_bytes = index.to_bytes(4, byteorder='big')
    return hmac_sha512(master_key, b'\x00' + master_key + index_bytes)

def generate_master_key_from_seed(seed_bytes):
    # Convert the seed from hex string to bytes
    # seed_bytes = bytes.fromhex(seed_hex)
    # Use HMAC-SHA512 with "Bitcoin seed" as the key
    master_node = hmac.new(
        key=b"Bitcoin seed",
        msg=seed_bytes,
        digestmod=hashlib.sha512
    ).digest()
    # Split the 512-bit output into master private key (first 32 bytes) and chain code (last 32 bytes)
    master_private_key = master_node[:32]
    chain_code = master_node[32:]
    return master_private_key, chain_code

def generate_hardened_keys(master_key) -> dict:
    # master_key = os.urandom(32)  # 32 bytes 
    # scan_private_key = derive_hardened_key(master_key, 1)  # m/1'
    # spend_private_key = derive_hardened_key(master_key, 0)  # m/0'
    root = bip32.HDKey.from_seed(master_key, version=NETWORKS["main"]["xprv"])    
    scan_private_key = root.derive("m/352h/0h/0h/1h/0").key.secret
    spend_private_key = root.derive("m/352h/0h/0h/0h/0").key.secret
    from binascii import hexlify
    scank = root.derive("m/352h/0h/0h/1h/0").key.secret
    print(hexlify(scank).decode())
    spendk = root.derive("m/352h/0h/0h/0h/0")
    print(spendk.get_public_key())
    # Store the keys in a dictionary
    key_material = {
        'scan_priv_key': scan_private_key,
        'spend_priv_key': spend_private_key
    }
    return key_material

# Get x coordinate from a point
def x(P: Point) -> int:
    return P[0]


# Get y coordinate from a point
def y(P: Point) -> int:
    return P[1]

# ser256(p): serializes the integer p as a 32-byte sequence, most significant byte first.
def ser256(p: int) -> bytes:
    return p.to_bytes(32, 'big')

# serP(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form: 
# (0x02 or 0x03) || ser256(x), where the header byte depends on the parity of the omitted Y coordinate.
def serP(P: Point) -> bytes: 
    x_bytes = ser256(int_from_bytes(bytes_from_point(P)))
    prefix = b'\x02' if has_even_y(P) else b'\x03' # Determine the parity of y to choose the prefix
    return prefix + x_bytes 

# Get an int from bytes
def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def get_seed() -> bytes:
    """
    Re‑creates the BIP‑39 seed from the hard‑coded mnemonic.
    Returns the 64‑byte seed (as `bytes`) that the Rust code produces.
    """    
    seed = bip39.mnemonic_to_seed(mnemonic)
    return seed

def bech32_polymod(values: list[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp: str) -> list[int]:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp: str, data: list[int]) -> Optional[Encoding]:
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None

def decode(hrp: str, addr: str) -> Tuple[Optional[int], Optional[list[int]]]:
    """Decode a segwit address."""
    hrpgot, data, _ = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False) if data else None
    if decoded is None or len(decoded) < 2 or len(decoded) > 71:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 66:
        return (None, None)
    return (data[0], decoded)

def bech32_create_checksum(hrp: str, data: list[int], spec: Encoding) -> list[int]:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp: str, data: list[int], spec: Encoding) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[list[int]]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret
# Generate public key (as a point) from an int
def pubkey_point_gen_from_int(seckey: int) -> Point:
    P = point_mul(G, seckey)
    assert P is not None 
    return P

def bech32_decode(bech: str) -> Tuple[Optional[str], Optional[list[int]], Optional[Encoding]]:
    """Validate a Bech32m string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 117:
        return (None, None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)



def encode_silent_payment_address(B_scan: Point, B_m: Point, hrp: str = 'tsp', version: int = 0) -> str:
    if B_scan is None or B_m is None:
        raise ValueError('ERROR: Invalid data.')
    ret = bech32_encode(hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M)
    if decode(hrp, ret) == (None, None):
        raise ValueError('ERROR: Invalid data.')
    return ret

def main():
   # 1️⃣ Re‑create the seed.
    seed = get_seed()    
    key_material = generate_hardened_keys(seed)       
    # Receiver's scan and spend public key 
    B_scan = pubkey_point_gen_from_int(int_from_bytes(key_material['scan_priv_key']))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(key_material['spend_priv_key']))    
    sp = encode_silent_payment_address(B_scan, B_spend, 'sp', 0)        
    
if __name__ == "__main__":
    main()