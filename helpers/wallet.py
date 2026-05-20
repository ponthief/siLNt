import base64
import coincurve
import hashlib
import httpx
import io
import math
import struct
from base64 import b64encode
from embit import bip32, bip39, ec, finalizer, script
from embit.networks import NETWORKS
from binascii import hexlify
from .curve import bech32_encode, Encoding
from .curve import pubkey_point_gen_from_int, int_from_bytes, Point
from loguru import logger
from lnbits.utils.crypto import AESCipher
from cryptography.fernet import Fernet
from embit.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
    SIGHASH,
    Witness,
)
from embit.psbt import PSBT, InputScope
from embit.script import Script
from embit.networks import NETWORKS
from .curve import (
    decode,
    convertbits,
    pubkey_point_gen_from_int,
    int_from_bytes,
    point_add,
    point_mul,
    serP,
    ser256,
    has_even_y,
    G,
    p as CURVE_P,
)
from embit.ec import SchnorrSig


def get_seed(mnemonic) -> bytes:
    """
    Re‑creates the BIP‑39 seed from the hard‑coded mnemonic.
    Returns the 64‑byte seed (as `bytes`).
    """
    seed = bip39.mnemonic_to_seed(mnemonic)
    return seed


def generate_hardened_keys(seed, network: str = "mainnet") -> dict:
    # BIP352: coin_type 0 = mainnet, 1 = testnet/signet
    coin_type = 0 if network == "mainnet" else 1
    xprv_version = (
        NETWORKS["main"]["xprv"] if network == "mainnet" else NETWORKS["test"]["xprv"]
    )

    root = bip32.HDKey.from_seed(seed, version=xprv_version)

    scan_path = f"m/352h/{coin_type}h/0h/1h/0"
    spend_path = f"m/352h/{coin_type}h/0h/0h/0"

    scan_private_key = root.derive(scan_path).key.secret
    spend_private_key = root.derive(spend_path).key.secret
    scank = root.derive(scan_path).key.secret
    spendk = root.derive(spend_path)

    return {
        "scan_priv_key": scan_private_key,
        "spend_priv_key": spend_private_key,
        "scank": hexlify(scank).decode(),
        "spendk": spendk.get_public_key(),
    }


def encode_silent_payment_address(
    B_scan: Point, B_m: Point, hrp: str = "tsp", version: int = 0
) -> str:
    if B_scan is None or B_m is None:
        raise ValueError("ERROR: Invalid data.")
    ret = bech32_encode(
        hrp, [version] + convertbits(serP(B_scan) + serP(B_m), 8, 5), Encoding.BECH32M
    )
    if decode(hrp, ret) == (None, None):
        raise ValueError("ERROR: Invalid data.")
    return ret


async def generate_silent_wallet_address(mnemonic, network: str = "mainnet") -> tuple:
    seed = get_seed(mnemonic)
    key_material = generate_hardened_keys(seed, network)

    B_scan = pubkey_point_gen_from_int(int_from_bytes(key_material["scan_priv_key"]))
    B_spend = pubkey_point_gen_from_int(int_from_bytes(key_material["spend_priv_key"]))

    # mainnet → 'sp', signet/testnet → 'tsp'
    hrp = "sp" if network == "mainnet" else "tsp"
    sp = encode_silent_payment_address(B_scan, B_spend, hrp, 0)

    spend_priv_hex = hexlify(key_material["spend_priv_key"]).decode()
    scan_key_hex = key_material["scank"]

    return (str(sp), scan_key_hex, spend_priv_hex)


def parse_sp_address(sp_address: str) -> tuple:
    """Extract B_scan and B_spend as compressed pubkey bytes from a Silent Payment address."""
    hrp = "tsp" if sp_address.startswith("tsp") else "sp"
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
    spend_secret: bytes,
    utxos: list[dict],
) -> bytes:
    b_scan_bytes, b_spend_bytes = parse_sp_address(sp_address)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # Step 1: sum input private keys, negating taproot keys with odd Y
    a_sum = 0
    A_points = []
    for u in utxos:
        priv = (
            int.from_bytes(bytes.fromhex(u["priv_key_tweak"]), "big")
            + int.from_bytes(spend_secret, "big")
        ) % n
        pub_point = pubkey_point_gen_from_int(priv)
        if pub_point[1] % 2 == 1:  # odd Y — negate (taproot requirement)
            priv = n - priv
            pub_point = pubkey_point_gen_from_int(priv)
        a_sum = (a_sum + priv) % n
        A_points.append(pub_point)

    # Step 2: A_sum = sum of all input pubkeys
    A_sum_point = A_points[0]
    for pt in A_points[1:]:
        A_sum_point = point_add(A_sum_point, pt)
    A_sum_bytes = bytes([0x02 + (A_sum_point[1] % 2)]) + ser256(A_sum_point[0])

    # Step 3: smallest outpoint = min(reversed_txid || vout_LE)
    outpoints = [
        bytes.fromhex(u["txid"])[::-1] + int(u.get("vout", 0)).to_bytes(4, "little")
        for u in utxos
    ]
    outpointL = min(outpoints)

    # Step 4: input_hash = TaggedHash("BIP0352/Inputs", outpointL || A_sum)
    input_hash_bytes = tagged_hash("BIP0352/Inputs", outpointL + A_sum_bytes)
    input_hash = int.from_bytes(input_hash_bytes, "big")

    # Step 5: shared_secret = (a_sum * input_hash) * B_scan
    a_tweaked = (a_sum * input_hash) % n
    B_scan = compressed_pubkey_to_point(b_scan_bytes)
    ecdh_point = point_mul(B_scan, a_tweaked)

    # Step 6: t_k = TaggedHash("BIP0352/SharedSecret", serP(ecdh) || ser32(0))
    ecdh_compressed = bytes([0x02 + (ecdh_point[1] % 2)]) + ser256(ecdh_point[0])
    t_k_bytes = tagged_hash(
        "BIP0352/SharedSecret", ecdh_compressed + (0).to_bytes(4, "big")
    )
    t_k = int.from_bytes(t_k_bytes, "big")

    # Step 7: P = B_spend + t_k*G
    B_spend = compressed_pubkey_to_point(b_spend_bytes)
    tG = pubkey_point_gen_from_int(t_k)
    P = point_add(B_spend, tG)

    return bytes([0x51, 0x20]) + ser256(P[0])


def verify_sp_output(
    recipient_script: Script,
    tx_outputs: list[TransactionOutput],
) -> bool:
    """
    Verify the derived SP scriptpubkey appears in the transaction outputs.
    Call this after building tx_outputs but before signing.
    """
    expected = bytes(recipient_script.data)
    for out in tx_outputs:
        out_script = (
            out.script_pubkey.data
            if hasattr(out.script_pubkey, "data")
            else bytes(out.script_pubkey)
        )
        if out_script == expected:
            return True
    return False


def build_transaction(
    spend_key_hex: str,
    recipient: str,
    amount: int,
    fee_rate: float,
    utxos: list[dict],
    network: str = "Mainnet",
) -> dict:
    """
    Build and sign a Bitcoin transaction.
    Supports Silent Payment addresses (sp1/tsp1) and standard on-chain addresses.
    Returns dict with tx_hex, fee, amount, change.
    """
    # # ── 1. Parse spend key ────────────────────────────────────────────
    spend_key = ec.PrivateKey(bytes.fromhex(spend_key_hex))

    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    # ── 2. Build per-input tweaked keys and scripts ───────────────────
    input_keys = []
    input_scripts = []
    for utxo in utxos:
        # BlindBit: full_signing_key = priv_key_tweak + spend_key
        priv_key_tweak_hex = utxo.get("priv_key_tweak") or ""
        if not priv_key_tweak_hex:
            raise ValueError(f"Missing priv_key_tweak for utxo {utxo['txid']}")

        pub_key_hex = utxo.get("pub_key") or ""
        if not pub_key_hex:
            raise ValueError(f"Missing pub_key for utxo {utxo['txid']}")

        # full_secret = priv_key_tweak + spend_key mod n
        priv_tweak_int = int_from_bytes(bytes.fromhex(priv_key_tweak_hex))
        spend_key_int = int_from_bytes(spend_key.secret)
        full_secret_int = (priv_tweak_int + spend_key_int) % n

        # derive pubkey and negate if odd y
        full_pub_point = pubkey_point_gen_from_int(full_secret_int)
        if not has_even_y(full_pub_point):
            full_secret_int = n - full_secret_int
            full_pub_point = pubkey_point_gen_from_int(full_secret_int)

        signing_key = ec.PrivateKey(full_secret_int.to_bytes(32, "big"))

        # ScriptPubKey uses pub_key from BlindBit directly (top level)
        actual_x_only = bytes.fromhex(pub_key_hex)  # already x-only 32 bytes
        actual_script = Script(bytes([0x51, 0x20]) + actual_x_only)

        # Verify
        derived_x = ser256(full_pub_point[0]).hex()

        input_keys.append(signing_key)
        input_scripts.append((actual_script, actual_x_only))

    # ── 3. Recipient scriptpubkey ─────────────────────────────────────
    if recipient.startswith("sp1") or recipient.startswith("tsp1"):
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
    # Round up to nearest sat — floor would underpay, ceil ensures broadcast
    fee = max(1, math.ceil(estimated_vsize * fee_rate))
    # fee = estimated_vsize * fee_rate
    change_amount = total_input - amount - fee
    if change_amount < 0:
        raise ValueError(
            f"Insufficient funds. Need {amount + fee} sats "
            f"(including {fee} sats fee), have {total_input} sats."
        )

    # If change is below dust threshold, try two strategies:
    if 0 < change_amount < 546:
        # Strategy 1: reduce amount to make change viable
        reduced_amount = amount - (546 - change_amount)
        if reduced_amount >= 546:
            change_amount = total_input - reduced_amount - fee
            amount = reduced_amount
            logger.debug(
                f"Adjusted amount to {amount} sats to avoid dust change "
                f"— change now {change_amount} sats"
            )
        else:
            # Strategy 2: add dust to fee — can't reduce amount further
            logger.debug(f"Change {change_amount} sats below dust — adding to fee")
            fee += change_amount
            change_amount = 0
    # ── 5. Build inputs ───────────────────────────────────────────────────
    tx_inputs_with_keys = [
        (
            TransactionInput(bytes.fromhex(u["txid"]), int(u.get("vout", 0))),
            input_keys[i],
            input_scripts[i],
            u["amount"],
        )
        for i, u in enumerate(utxos)
    ]

    # BIP69 sort
    tx_inputs_with_keys.sort(key=lambda x: (x[0].txid.hex(), x[0].vout))

    tx_inputs = [t[0] for t in tx_inputs_with_keys]
    input_keys_sorted = [t[1] for t in tx_inputs_with_keys]
    input_scripts_sorted = [t[2] for t in tx_inputs_with_keys]
    input_amounts_sorted = [t[3] for t in tx_inputs_with_keys]

    # ── 6. Build outputs ──────────────────────────────────────────────────
    tx_outputs = [TransactionOutput(amount, recipient_script)]

    if change_amount >= 546:
        change_script = input_scripts_sorted[0][0]
        tx_outputs.append(TransactionOutput(change_amount, change_script))

    # BIP69: sort outputs by value then scriptpubkey
    tx_outputs.sort(
        key=lambda x: (
            x.value,
            x.script_pubkey.data.hex()
            if hasattr(x.script_pubkey, "data")
            else bytes(x.script_pubkey).hex(),
        )
    )

    # ── 6b. Verify SP output is in tx before signing ──────────────────────
    if recipient.startswith("sp1") or recipient.startswith("tsp1"):
        if not verify_sp_output(recipient_script, tx_outputs):
            raise ValueError(
                f"Derived SP output not found in transaction outputs. "
                f"Funds would be unrecoverable. Aborting."
            )

    # ── 7. Construct PSBT ─────────────────────────────────────────────────
    tx = Transaction(vin=tx_inputs, vout=tx_outputs)
    psbt = PSBT(tx)

    for i in range(len(tx_inputs)):
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(
            input_amounts_sorted[i], input_scripts_sorted[i][0]
        )

    # ── 8. Collect sighash inputs ─────────────────────────────────────────
    utxo_amounts = [inp.witness_utxo.value for inp in psbt.inputs]
    utxo_scripts = [inp.witness_utxo.script_pubkey for inp in psbt.inputs]

    # ── 9. Sign each input with sorted keys ──────────────────────────────
    for i in range(len(psbt.inputs)):
        h = taproot_sighash(tx, i, utxo_scripts, utxo_amounts, sighash_type=0)
        priv_bytes = input_keys_sorted[i].secret  # ← use sorted keys
        cc_key = coincurve.PrivateKey(priv_bytes)
        sig_bytes = cc_key.sign_schnorr(h)
        sig_bytes = sig_bytes.rjust(64, b"\x00")
        psbt.inputs[i].taproot_key_sig = SchnorrSig.parse(sig_bytes)

    # ── 10. Finalize manually ──────────────────────────────────────────────
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

    return {
        "tx_hex": tx_hex,
        "fee": fee,
        "amount": amount,
        "change": change_amount,
        "total_input": total_input,
        "recipient": recipient,
        "fee_rate_used": fee_rate,
        "vsize": estimated_vsize,
    }


def decrypt_mnemonic(
    m: str | None = None, k: str | None = None, urlsafe: bool = False
) -> str | None:
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


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    tag_bytes = tag.encode()
    tag_hash = sha256(tag_bytes)
    return sha256(tag_hash + tag_hash + data)


def taproot_sighash(
    tx: Transaction,
    input_index: int,
    utxo_scripts: list,
    utxo_amounts: list,
    sighash_type: int = 0,
) -> bytes:
    """
    Compute BIP341 taproot key-path sighash manually.
    """

    # sha_prevouts
    prevouts = b""
    for vin in tx.vin:
        prevouts += vin.txid[::-1] + vin.vout.to_bytes(4, "little")
    sha_prevouts = sha256(prevouts)
    # sha_amounts
    amounts = b""
    for amt in utxo_amounts:
        amounts += amt.to_bytes(8, "little")
    sha_amounts = sha256(amounts)
    # sha_scriptpubkeys
    scripts = b""
    for s in utxo_scripts:
        script_bytes = s.data if hasattr(s, "data") else bytes(s)
        scripts += len(script_bytes).to_bytes(1, "little") + script_bytes
    sha_scriptpubkeys = sha256(scripts)
    # sha_sequences
    sequences = b""
    for vin in tx.vin:
        sequences += vin.sequence.to_bytes(4, "little")
    sha_sequences = sha256(sequences)
    # sha_outputs
    outputs = b""
    for vout in tx.vout:
        script_bytes = (
            vout.script_pubkey.data
            if hasattr(vout.script_pubkey, "data")
            else bytes(vout.script_pubkey)
        )
        outputs += vout.value.to_bytes(8, "little")
        outputs += len(script_bytes).to_bytes(1, "little") + script_bytes
    sha_outputs = sha256(outputs)
    # spend_type = 0 (key path, no annex)
    spend_type = (0).to_bytes(1, "little")

    # input data
    vin = tx.vin[input_index]
    input_data = (
        vin.txid
        + vin.vout.to_bytes(4, "little")
        + utxo_amounts[input_index].to_bytes(8, "little")
        + len(utxo_scripts[input_index].data).to_bytes(1, "little")
        + utxo_scripts[input_index].data
        + vin.sequence.to_bytes(4, "little")
    )

    # Full sighash preimage
    preimage = (
        bytes([0x00])  # epoch
        + sighash_type.to_bytes(1, "little")  # hash_type
        + tx.version.to_bytes(4, "little")  # nVersion
        + tx.locktime.to_bytes(4, "little")  # nLockTime
        + sha_prevouts
        + sha_amounts
        + sha_scriptpubkeys
        + sha_sequences
        + sha_outputs
        + spend_type
        + input_index.to_bytes(4, "little")  # input_index
    )
    return tagged_hash("TapSighash", preimage)


def generate_labeled_sp_address(
    scan_secret_hex: str, spend_pub_hex: str, m: int, hrp: str = "sp"
) -> str:
    """
    Derive a BIP352 labeled Silent Payment address.
    B_m = B_spend + TaggedHash("BIP0352/Label", b_scan || ser32(m)) * G
    m=0 is reserved for change, user labels start at m=1
    """
    scan_secret_bytes = bytes.fromhex(scan_secret_hex)
    spend_pub_bytes = bytes.fromhex(spend_pub_hex)

    # BIP352: TaggedHash("BIP0352/Label", scan_secret || ser32(m)) — big-endian
    tag_hash = hashlib.sha256("BIP0352/Label".encode()).digest()
    label_hash = hashlib.sha256(
        tag_hash + tag_hash + scan_secret_bytes + struct.pack(">I", m)
    ).digest()

    # B_m = B_spend + label_hash * G
    B_m = coincurve.PublicKey.combine_keys(
        [
            coincurve.PublicKey(spend_pub_bytes),
            coincurve.PublicKey.from_secret(label_hash),
        ]
    ).format(compressed=True)

    # B_scan pubkey
    B_scan = coincurve.PublicKey.from_secret(scan_secret_bytes).format(compressed=True)

    return bech32_encode(hrp, [0] + convertbits(B_scan + B_m, 8, 5), Encoding.BECH32M)


def get_spend_pub_from_secret(spend_secret_hex: str) -> str:
    """Derive compressed spend public key from spend private key hex."""
    pub = coincurve.PublicKey.from_secret(bytes.fromhex(spend_secret_hex))
    return pub.format(compressed=True).hex()
