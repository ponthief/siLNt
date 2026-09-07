"""
Email-verified registration for the siLNt extension.

Flow:
  1. User submits registration → validate inputs, hash password
  2. Generate a signed token containing {username, email, password_hash, ts}
     and email it as a clickable link — NO account is created yet
  3. User clicks the link → decode/validate token (incl. 1-hour TTL)
  4. Create LNbits Account with a fresh uuid4 id + the bcrypt hash from the token
  5. Enable LNBITS_USER_DEFAULT_EXTENSIONS on the new account, marking paid
     extensions as already-paid so they bypass the payment requirement

This guarantees the account is only created after email ownership is proven,
and that siLNt is fully active on first login (paid or not).

The token carries the bcrypt HASH, never the raw password. It used to carry the
raw password — contradicting step 2 above, which has described it as a hash
since the module was written — and that put a recoverable password in the user's
inbox for an hour. Encrypted with the LNbits internal secret, so not readable by
a passive observer, but reversible by anyone holding that secret: a config leak,
a database backup, or an operator. Verification links also outlive their TTL in
mail-server logs and browser history, and people reuse passwords, so what leaks
is worth more than this one account.

A bcrypt hash is safe to put there instead because LNbits hashes with a random
salt and nothing else — see Account.hash_password: gensalt() + hashpw, with no
binding to the account id. That is what lets the hash be computed at step 1 and
stored on an Account created at step 4.
"""

import base64
import json
import secrets
import time
from http import HTTPStatus
from typing import Optional
from uuid import uuid4
from fastapi import HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from lnbits.core.crud import (    
    get_account_by_username_or_email,
    create_account
)
from lnbits.core.crud.extensions import (
    create_user_extension,
    update_user_extension,
    get_user_extension,
)
from lnbits.core.models import Account
from lnbits.core.models.extensions import UserExtension, UserExtensionInfo
from lnbits.core.services.notifications import send_email_notification
from lnbits.helpers import encrypt_internal_message, decrypt_internal_message
from lnbits.settings import settings, AuthMethods


# Token lifetime — how long verification link stays valid
VERIFICATION_TOKEN_TTL_SECONDS = 60 * 60  # 1 hour


class RegistrationRequest(BaseModel):
    username: str
    email:    str
    password: str


class VerifyRegistrationRequest(BaseModel):
    token: str


class ConfirmRegistrationRequest(BaseModel):
    email: str
    code: str


# Digits, not letters: it is typed on a phone keypad, and a 6-digit field is a
# pattern users already know from the device-confirmation flow.
REGISTRATION_CODE_DIGITS = 6


def _generate_registration_code() -> str:
    """A 6-digit code, uniformly random and zero-padded.

    secrets, not random: this is the only thing standing between an email
    address and an account, for the app path where no link is involved.
    """
    upper = 10**REGISTRATION_CODE_DIGITS
    return str(secrets.randbelow(upper)).zfill(REGISTRATION_CODE_DIGITS)


# ── Token helpers ─────────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """bcrypt hash of `password`, via LNbits' own Account.hash_password.

    Routed through LNbits rather than calling bcrypt here so the salt and cost
    factor stay whatever LNbits chose, without siLNt taking a direct bcrypt
    dependency to keep in step. The throwaway Account exists only to reach that
    method: the hash it produces is independent of the id, so the id given here
    is irrelevant and never stored.
    """
    return Account(id=uuid4().hex).hash_password(password)


def _generate_verification_token(
    username: str, email: str, password_hash: str
) -> str:
    """Sign a token carrying the pending registration data.

    `password_hash` is a bcrypt hash, never the raw password — see the module
    docstring for why that distinction is the point of this token's design.
    """
    payload = {
        "kind":          "register",
        "username":      username,
        "email":         email,
        "password_hash": password_hash,
        "ts":            int(time.time()),
    }
    payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    enc = encrypt_internal_message(payload_json)
    if not enc:
        raise RuntimeError("Cannot generate verification token.")
    return "verify_" + base64.urlsafe_b64encode(enc.encode()).decode().rstrip("=")


def _decode_verification_token(token: str) -> Optional[dict]:
    """Decode and validate a verification token. Returns None if invalid/expired."""
    if not token.startswith("verify_"):
        return None
    try:
        b64 = token[7:]
        padded = b64 + "=" * (-len(b64) % 4)
        enc = base64.urlsafe_b64decode(padded).decode()
        payload_json = decrypt_internal_message(enc)
        if not payload_json:
            return None
        payload = json.loads(payload_json)
    except Exception as exc:
        logger.warning(f"Invalid verification token: {exc}")
        return None

    if payload.get("kind") != "register":
        return None

    ts = payload.get("ts", 0)
    if int(time.time()) - int(ts) > VERIFICATION_TOKEN_TTL_SECONDS:
        return None

    return payload


# ── Start registration: send email ────────────────────────────────────────────

async def start_registration(
    data: RegistrationRequest, request: Request
) -> dict:
    """
    Validate inputs, check uniqueness, hash the password, generate a
    verification token, and email the link. Does NOT create the account yet.
    """
    if not settings.is_auth_method_allowed(AuthMethods.username_and_password):
        raise HTTPException(
            HTTPStatus.FORBIDDEN, "Username/password auth disabled."
        )

    username = data.username.strip()
    email    = data.email.strip().lower()

    if len(username) < 3 or len(username) > 32:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Username must be 3–32 chars.")
    if "@" not in email:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid email.")
    if len(data.password) < 8:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Password too short (min 8).")
    # bcrypt refuses anything longer, and the hash is now computed HERE rather
    # than at verification. Without this check a long password would send a
    # verification email and then fail when the link was clicked — an account
    # that could never be created, and no way for the user to see why.
    if len(data.password.encode("utf-8")) > 72:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Password too long (max 72 bytes).",
        )

    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email already in use.",
        )

    from ..crud import pending_registration_username_taken, put_pending_registration

    # A pending registration is not an account yet, so the check above misses
    # it. Without this the second person to claim a username only finds out
    # after typing their code, which reads as the code being wrong.
    if await pending_registration_username_taken(username):
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email already in use.",
        )

    try:
        # Hashed before the token is built, so the raw password exists only for
        # the life of this request and never reaches the email.
        password_hash = _hash_password(data.password)
        token = _generate_verification_token(username, email, password_hash)
    except Exception as exc:
        # Deliberately does not log `exc` with any password context — the
        # message is enough to diagnose a signing or hashing failure.
        logger.error(f"Token generation failed: {exc}")
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not start registration.")

    # The code path, alongside the link. A deployment can have its web app
    # closed to the outside, which leaves the link with nowhere to open — the
    # code needs nothing but the API the app is already talking to. Both halves
    # of the email lead to the same account and whichever is used first spends
    # the other.
    code = _generate_registration_code()
    try:
        await put_pending_registration(email, username, password_hash, code)
    except Exception as exc:
        logger.error(f"Could not store pending registration: {exc}")
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR, "Could not start registration."
        )

    # Resolve the Thrilla web-app origin. Prefers SILNT_FRONTEND_URL so the link
    # is correct for mobile registrations too (mobile sends no Origin header, so
    # the request-derived fallback would point at the API host and 404).
    from .appenv import frontend_base_url

    origin = frontend_base_url(request)
    verify_url = f"{origin}/verify?token={token}"

    # The code comes first. Someone who registered in the mobile app is holding
    # a screen asking for it, and on a deployment whose web app is closed the
    # link below will not open at all — so the thing that always works has to
    # be the thing they see first.
    subject = "Thrilla — Verify your email"
    body = (
        f"Hi {username},\n\n"
        f"Your Thrilla verification code is:\n\n"
        f"    {code}\n\n"
        f"Enter it in the app to activate your account.\n\n"
        f"Or, if you registered in a web browser, open this link instead:\n\n"
        f"{verify_url}\n\n"
        f"The code and the link both expire in "
        f"{VERIFICATION_TOKEN_TTL_SECONDS // 60} minutes, and using either one "
        f"activates your account.\n\n"
        f"If you didn't request this, you can safely ignore this email.\n\n"
        f"— Thrilla"
    )

    if not settings.lnbits_email_notifications_enabled:
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Email notifications disabled — cannot complete registration.",
        )

    try:
        result = await send_email_notification(
            to_emails=[email],
            message=body,
            subject=subject,
        )
        if result.get("status") != "ok":
            logger.error(f"Email send failed: {result.get('message')}")
            raise HTTPException(
                HTTPStatus.BAD_GATEWAY,
                "Could not send verification email — please try again later.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Email send raised: {exc}")
        raise HTTPException(
            HTTPStatus.BAD_GATEWAY,
            "Could not send verification email — please try again later.",
        )

    logger.info(f"Verification email sent to {email} for pending username {username}")
    return {
        "success": True,
        "message": "Verification email sent. Check your inbox to complete registration.",
        "email":   email,
    }


# ── Complete registration: create account + enable extensions ─────────────────

async def complete_registration(token: str) -> dict:
    payload = _decode_verification_token(token)
    if not payload:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Verification link is invalid or has expired. Please register again.",
        )

    username = payload["username"]
    email    = payload["email"]

    password_hash = payload.get("password_hash")
    if not password_hash:
        # A token issued before this change, still inside its 1-hour TTL when
        # the new code deployed. Hash the raw password it carries so a
        # registration in flight completes instead of dead-ending on a link the
        # user has already been told to click. Removable once an hour has
        # passed since deploy — nothing can present one of these after that,
        # because _decode_verification_token rejects it on age first.
        legacy_raw = payload.get("password")
        if not legacy_raw:
            raise HTTPException(
                HTTPStatus.BAD_REQUEST,
                "Verification link is invalid or has expired. Please register again.",
            )
        logger.info(f"Verifying pre-hash-token registration for {username}")
        password_hash = _hash_password(legacy_raw)

    # The link won the race, so the code in the same email is spent. Left
    # behind, the row would sit until its TTL holding a username that now
    # exists, and rejecting that code would look like the code was wrong.
    from ..crud import drop_pending_registration

    try:
        await drop_pending_registration(email)
    except Exception as exc:
        logger.warning(f"Could not clear pending registration for {email}: {exc}")

    return await _create_verified_account(username, email, password_hash)


async def confirm_registration(data: ConfirmRegistrationRequest) -> dict:
    """Complete registration from the 6-digit code instead of the link.

    The app path. It needs nothing but this API — no browser, and no web app
    reachable from the outside — which is the whole reason the code exists.
    """
    from ..crud import take_pending_registration

    email = (data.email or "").strip().lower()
    code = (data.code or "").strip()
    if not email or not code:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, "Email and verification code are required."
        )

    row, reason = await take_pending_registration(email, code)
    if not row:
        # One message for every reason. "No such pending registration" versus
        # "wrong code" would tell a stranger which addresses are mid-signup,
        # which is exactly the enumeration this avoids; the reason is logged
        # instead.
        logger.info(f"Registration code rejected for {email}: {reason}")
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "That code is incorrect or has expired. Please register again.",
        )

    return await _create_verified_account(
        row["username"], row["email"], row["password_hash"]
    )


async def _create_verified_account(
    username: str, email: str, password_hash: str
) -> dict:
    """Create the account and switch on the default extensions.

    Shared by both halves of the verification email: the link decodes its token
    to get here, the code trades a database row for the same three values.
    Whichever arrives first creates the account, and the uniqueness check below
    is what makes the second one fail cleanly rather than duplicate anything.
    """
    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email is no longer available — please register again with a different one.",
        )

    try:
        account = Account(
            id       = uuid4().hex,
            username = username,
            email    = email,
        )
        # Assigned, not re-hashed: the hash was computed when registration
        # started. LNbits' hash_password is gensalt() + hashpw with no id
        # binding, so a hash made earlier verifies here exactly as one made now
        # would — checkpw reads the salt out of the hash itself.
        account.password_hash = password_hash
        await create_account(account)      # ← the working creation path
        account_id = account.id
        logger.info(f"Email-verified account created: {username} ({email}) id={account_id}")

        # Enable default extensions (paid bypass) — unchanged
        try:
            default_exts = settings.lnbits_user_default_extensions or []
            for ext_id in default_exts:
                user_ext = UserExtension(
                    user=account_id,
                    extension=ext_id,
                    active=True,
                    extra=UserExtensionInfo(
                        paid_to_enable=True,
                        payment_hash_to_enable="default_enabled",
                    ),
                )
                existing_ext = await get_user_extension(account_id, ext_id)
                if existing_ext:
                    await update_user_extension(user_extension=user_ext)
                else:
                    await create_user_extension(user_extension=user_ext)
                logger.info(f"Enabled default extension '{ext_id}' for {account_id} (paid bypass)")
        except Exception as exc:
            logger.warning(f"Could not enable default extensions for {account_id}: {exc}")

    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Account creation failed for {username}: {exc}")
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "Failed to create account. Please try again.",
        )

    # ── Send welcome email — non-fatal if it fails ────────────────────────────
    try:
        welcome_subject = "Welcome to Thrilla"
        welcome_body = (
            f"Hi {username},\n\n"
            f"Your Thrilla account is now active. You can sign in any time at the "
            f"URL below using your username and password.\n\n"
            f"What you can do with Thrilla:\n"
            f"  • Create Silent Payment (BIP-352) wallets — private by default\n"
            f"  • Scan the chain for incoming payments via your BlindBit oracle\n"
            f"  • Send to sp1… / bc1q… / BIP-353 (alice@domain) recipients\n"
            f"  • Register a BIP-353 human-readable address for your wallet\n\n"
            f"Wallet keys are stored ONLY on your device — never on the server. "
            f"Keep your mnemonic safe; without it your funds can't be recovered.\n\n"
            f"If you ever need to reset your password, use the 'Forgot password' "
            f"link on the sign-in screen.\n\n"
            f"— Thrilla"
        )
        if settings.lnbits_email_notifications_enabled:
            res = await send_email_notification(
                to_emails=[email],
                message=welcome_body,
                subject=welcome_subject,
            )
            if res.get("status") == "ok":
                logger.info(f"Welcome email sent to {email}")
            else:
                logger.warning(f"Welcome email send returned: {res.get('message')}")
    except Exception as exc:
        # Welcome email failure must not block account activation
        logger.warning(f"Could not send welcome email to {email}: {exc}")

    return {
        "success":  True,
        "username": username,
        "email":    email,
    }
