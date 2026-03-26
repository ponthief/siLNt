import base64
import hashlib
from embit import bip32, bip39, ec, finalizer, script
from embit.networks import NETWORKS
from binascii import hexlify
from .curve import bech32_encode, Encoding
from .curve import pubkey_point_gen_from_int, int_from_bytes, Point
from loguru import logger
from ..crud import get_or_create_server_secret
from lnbits.utils.crypto import AESCipher
from cryptography.fernet import Fernet
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH, Witness
from embit.psbt import PSBT, InputScope
from embit.script import Script
from embit.networks import NETWORKS
from .curve import (
    decode, convertbits, pubkey_point_gen_from_int,
    int_from_bytes, point_add, point_mul, serP, ser256,
    has_even_y, G, p as CURVE_P
)


def encrypt_spend_key(spend_priv_hex: str, scan_key_hex: str) -> str:
    # Derive a 32-byte Fernet key from scan_key_hex
    key_bytes = hashlib.sha256(scan_key_hex.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    f = Fernet(fernet_key)
    return f.encrypt(spend_priv_hex.encode()).decode()

def decrypt_spend_key(encrypted: str, scan_key_hex: str) -> str:
    key_bytes = hashlib.sha256(scan_key_hex.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    f = Fernet(fernet_key)
    return f.decrypt(encrypted.encode()).decode()

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

async def generate_silent_wallet_address(mnemonic) -> tuple:    
    seed = get_seed(mnemonic)
    key_material = generate_hardened_keys(seed)       
    # Receiver's scan and spend public key 
    B_scan = pubkey_point_gen_from_int(int_from_bytes(key_material['scan_priv_key']))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(key_material['spend_priv_key']))        
    sp = encode_silent_payment_address(B_scan, B_spend, 'sp', 0)
    # Encrypt spend private key using scan key as encryption key
    spend_priv_hex = hexlify(key_material['spend_priv_key']).decode()
    scan_key_hex = key_material['scank']    
    encrypted_spend_key = encrypt_spend_key(spend_priv_hex, scan_key_hex)
     # Encrypt scan secret using server secret
    encrypted_scan_secret = await encrypt_secret(scan_key_hex)    
    return (str(sp),  encrypted_scan_secret, str(encrypted_spend_key))

def parse_sp_address(sp_address: str) -> tuple:
    """Extract B_scan and B_spend as compressed pubkey bytes from a Silent Payment address."""
    hrp = 'tsp' if sp_address.startswith('tsp') else 'sp'
    version, decoded = decode(hrp, sp_address)
    if decoded is None:
        raise ValueError(f"Invalid Silent Payment address: {sp_address}")
    b_scan_bytes = bytes(decoded[:33])
    b_spend_bytes = bytes(decoded[33:66])
    return b_scan_bytes, b_spend_bytes


def compressed_pubkey_to_point(compressed: bytes) -> tuple:
    """Parse a compressed SEC1 pubkey bytes into a curve Point."""
    prefix = compressed[0]
    x = int_from_bytes(compressed[1:33])
    y_sq = (pow(x, 3, CURVE_P) + 7) % CURVE_P
    y = pow(y_sq, (CURVE_P + 1) // 4, CURVE_P)
    if (y % 2 == 0) != (prefix == 0x02):
        y = CURVE_P - y
    return (x, y)


def derive_sp_scriptpubkey(
    sp_address: str,
    spend_key_bytes: bytes,
    utxos: list[dict]
) -> bytes:
    """
    BIP352 sender derivation.
    Returns raw P2TR scriptpubkey bytes for the derived Silent Payment output.
    """
    b_scan_bytes, b_spend_bytes = parse_sp_address(sp_address)
    B_scan = compressed_pubkey_to_point(b_scan_bytes)
    B_spend = compressed_pubkey_to_point(b_spend_bytes)

    a = int_from_bytes(spend_key_bytes)

    # Sort outpoints: txid (LE) || vout (4 bytes LE) [::-1]
    outpoints = sorted([
        bytes.fromhex(u["txid"]) + int(u.get("vout", 0)).to_bytes(4, "little")
        for u in utxos
    ])

    outpoints_hash = int_from_bytes(
        hashlib.sha256(b"".join(outpoints)).digest()
    )

    # Tweak scalar: a * outpoints_hash mod n
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    a_tweaked = (a * outpoints_hash) % n

    # ECDH: shared_secret_point = a_tweaked * B_scan
    ecdh_point = point_mul(B_scan, a_tweaked)
    if ecdh_point is None:
        raise ValueError("ECDH point is at infinity")

    # BIP352 tagged hash for shared secret
    tag = b"BIP0352/SharedSecret"
    tag_hash = hashlib.sha256(tag).digest()
    t_k_input = tag_hash + tag_hash + serP(ecdh_point) + (0).to_bytes(4, "little")
    t_k = int_from_bytes(hashlib.sha256(t_k_input).digest())

    # P = B_spend + t_k * G
    tG = pubkey_point_gen_from_int(t_k)
    P = point_add(B_spend, tG)
    if P is None:
        raise ValueError("Derived output point is at infinity")

    # x-only pubkey → P2TR scriptpubkey
    x_only = ser256(P[0])
    return bytes([0x51, 0x20]) + x_only


def build_transaction(
    spend_key_hex: str,
    recipient: str,
    amount: int,
    fee_rate: int,
    utxos: list[dict],
    network: str = "Mainnet"
) -> dict:
    """
    Build and sign a Bitcoin transaction.
    Supports Silent Payment addresses (sp1/tsp1) and standard on-chain addresses.
    Returns dict with tx_hex, fee, amount, change.
    """

    # # ── 1. Parse spend key ────────────────────────────────────────────
    spend_key = ec.PrivateKey(bytes.fromhex(spend_key_hex))
    # own_pubkey = spend_key.get_public_key()

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # ── 2. Build per-input tweaked keys and scripts ───────────────────
    input_keys = []
    input_scripts = []
    for utxo in utxos:
        tweak_hex = utxo.get("tweak") or ""
        if not tweak_hex:
            raise ValueError(f"Missing tweak for utxo {utxo['txid']}")

        tweak_int = int_from_bytes(bytes.fromhex(tweak_hex))

        # tweak IS the output private key
        tweaked_pub_point = pubkey_point_gen_from_int(tweak_int)

        # Taproot requires even y — negate if odd
        if not has_even_y(tweaked_pub_point):
            tweak_int = n - tweak_int
            tweaked_pub_point = pubkey_point_gen_from_int(tweak_int)

        tweaked_key = ec.PrivateKey(tweak_int.to_bytes(32, 'big'))
        tweaked_x_only = ser256(tweaked_pub_point[0])

        # Verify against pub_key from blindbit
        pub_key_hex = utxo.get("pub_key") or ""
        if pub_key_hex:
            expected_x = pub_key_hex[2:] if len(pub_key_hex) == 66 else pub_key_hex
            if expected_x.lower() != tweaked_x_only.hex().lower():
                logger.warning(f"Pubkey mismatch for utxo {utxo['txid']}")
            else:
                logger.debug(f"Pubkey match confirmed for utxo {utxo['txid']}")

        input_script = Script(bytes([0x51, 0x20]) + tweaked_x_only)
        input_keys.append(tweaked_key)
        input_scripts.append((input_script, tweaked_x_only))

    # ── 3. Recipient scriptpubkey ─────────────────────────────────────
    if recipient.startswith('sp1') or recipient.startswith('tsp1'):
        recipient_script = Script(
            derive_sp_scriptpubkey(recipient, spend_key.secret, utxos)
        )
    else:
        try:
            recipient_script = script.address_to_scriptpubkey(recipient)
        except Exception as e:
            raise ValueError(f"Invalid recipient address: {str(e)}")

    # ── 4. Calculate amounts ──────────────────────────────────────────
    total_input = sum(u["amount"] for u in utxos)
    # Estimate vsize: 10 base + 57.5 per taproot input + 31 per output
    estimated_vsize = int(10 + (57.5 * len(utxos)) + (31 * 2))
    fee = estimated_vsize * fee_rate
    change_amount = total_input - amount - fee

    if change_amount < 0:
        raise ValueError(
            f"Insufficient funds. Need {amount + fee} sats "
            f"(including {fee} sats fee), have {total_input} sats."
        )

    # ── 5. Build inputs ─────────────────────────────────────────────── [::-1]
    tx_inputs = [
        TransactionInput(
            bytes.fromhex(u["txid"]),
            int(u.get("vout", 0))
        )
        for u in utxos
    ]

    # ── 6. Build outputs ──────────────────────────────────────────────
    tx_outputs = [TransactionOutput(amount, recipient_script)]

    # Add change output if above dust (546 sats)
    if change_amount > 546:
        tx_outputs.append(TransactionOutput(change_amount, input_scripts[0][0]))

    # ── 7. Construct PSBT ────────────────────────────────────────────────
    tx = Transaction(vin=tx_inputs, vout=tx_outputs)
    psbt = PSBT(tx)

    for i, utxo in enumerate(utxos):
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(utxo["amount"], input_scripts[i][0])
        # inp.taproot_internal_key = input_scripts[i][1]

    # ── 8. Sign each input manually ───────────────────────────────────────
    from embit.transaction import TaprootSignatureHash

    for i in range(len(psbt.inputs)):
        # Compute sighash directly from transaction
        h = TaprootSignatureHash(
            tx,
            [inp.witness_utxo for inp in psbt.inputs],
            sighash_type=0,
            input_index=i,
            script_path=False,
        )
        logger.debug(f"TaprootSignatureHash input {i}: {h.hex()}")
        logger.debug(f"psbt.sighash_taproot input {i}: {psbt.sighash_taproot(i, script_pubkeys=all_scripts, values=all_values, sighash=0).hex()}")
    for i, inp in enumerate(psbt.inputs):
        # Compute taproot sighash for this input
        h = psbt.sighash_taproot(
            i,
            script_pubkeys=[inp.witness_utxo.script_pubkey for inp in psbt.inputs],
            values=[inp.witness_utxo.value for inp in psbt.inputs],
            sighash=0,  # SIGHASH_DEFAULT
        )
        # Sign and store as taproot key-path signature
        sig = spend_key.schnorr_sign(h)
        inp.taproot_key_sig = sig
        logger.debug(f"input {i} sighash: {h.hex()}")
        logger.debug(f"input {i} signing key pubkey: {input_keys[i].get_public_key().serialize().hex()}")
        logger.debug(f"input {i} witness_utxo script: {psbt.inputs[i].witness_utxo.script_pubkey.data.hex()}")        
        logger.debug(f"input {i} sig: {sig.serialize().hex()}")

    # ── 9. Finalize manually ──────────────────────────────────────────────
    for inp in psbt.inputs:
        if inp.taproot_key_sig is not None:            
            inp.final_scriptwitness = Witness([inp.taproot_key_sig.serialize()])
            inp.final_scriptsig = Script(b"")

    # ── 10. Extract ───────────────────────────────────────────────────────
    # Copy witnesses into the transaction
    for i, inp in enumerate(psbt.inputs):
        if inp.final_scriptwitness:
            tx.vin[i].witness = inp.final_scriptwitness

    tx_hex = tx.serialize().hex()    
    # logger.debug(f"tweak_hex: {tweak_hex}")
    # logger.debug(f"tweak_int: {hex(tweak_int)}")
    # logger.debug(f"tweaked_key_int: {hex(tweaked_key_int)}")
    # logger.debug(f"derived x_only: {tweaked_x_only.hex()}")
    # logger.debug(f"expected pub_key: {pub_key_hex}")
    return {
        "tx_hex": tx_hex,
        "fee": fee,
        "amount": amount,
        "change": change_amount if change_amount > 546 else 0,
        "total_input": total_input,
        "recipient": recipient,
    }

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

async def encrypt_secret(value: str) -> str:    
    server_secret = await get_or_create_server_secret()
    key_bytes = hashlib.sha256(server_secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    f = Fernet(fernet_key)
    return f.encrypt(value.encode()).decode()

async def decrypt_secret(encrypted: str) -> str:    
    server_secret = await get_or_create_server_secret()
    key_bytes = hashlib.sha256(server_secret.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    f = Fernet(fernet_key)
    return f.decrypt(encrypted.encode()).decode()