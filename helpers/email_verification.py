"""
Forgot-password flow for the siLNt extension.

Email-verified registration:
  1. Validate the inputs and hash the password
  2. Build a signed token containing username, email, password_hash, timestamp
  3. Email the user a link with the token
  4. When the user clicks the link, decode the token, verify it's not expired,
     and create the LNbits account at that moment
  5. Enable default extensions on the new account (since we bypass LNbits's
     native register endpoint that normally does this)
"""

import base64
import json
import time
from http import HTTPStatus
from typing import Optional
from uuid import uuid4

import bcrypt
from fastapi import HTTPException, Request
from loguru import logger
from pydantic import BaseModel

from lnbits.core.crud import (
    create_account,
    get_account_by_username_or_email,
)
from lnbits.core.crud.extensions import update_user_extension
from lnbits.core.models.extensions import UserExtension
from lnbits.core.models import Account
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


def _generate_verification_token(
    username: str, email: str, password_hash: str
) -> str:
    """Sign a token carrying the pending registration data."""
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
    """Decode and validate a verification token."""
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

    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email already in use.",
        )

    password_hash = bcrypt.hashpw(
        data.password.encode(), bcrypt.gensalt()
    ).decode()

    try:
        token = _generate_verification_token(username, email, password_hash)
    except Exception as exc:
        logger.error(f"Token generation failed: {exc}")
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, "Could not start registration.")

    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if not origin:
        origin = f"https://{request.headers.get('host', '')}"
    origin = origin.rstrip("/")
    if origin.count("/") > 2:
        parts = origin.split("/")
        origin = "/".join(parts[:3])
    verify_url = f"{origin}/verify?token={token}"

    subject = "Thrilla — Verify your email"
    body = (
        f"Hi {username},\n\n"
        f"Thanks for registering for Thrilla. Click the link below to "
        f"activate your account:\n\n"
        f"{verify_url}\n\n"
        f"This link expires in {VERIFICATION_TOKEN_TTL_SECONDS // 60} minutes.\n\n"
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


async def complete_registration(token: str) -> dict:
    """
    Decode the verification token and create the LNbits account.
    Also enables LNBITS_USER_DEFAULT_EXTENSIONS on the new account (since we
    bypass LNbits's native /register endpoint that normally does this).
    """
    payload = _decode_verification_token(token)
    if not payload:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Verification link is invalid or has expired. Please register again.",
        )

    username      = payload["username"]
    email         = payload["email"]
    password_hash = payload["password_hash"]

    existing = await get_account_by_username_or_email(username) \
            or await get_account_by_username_or_email(email)
    if existing:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Username or email is no longer available — please register again with a different one.",
        )

    try:
        # LNbits Account requires an id — generate a uuid4 hex like LNbits internals do
        account_id = uuid4().hex
        account = Account(
            id            = account_id,
            username      = username,
            email         = email,
            password_hash = password_hash,
        )
        await create_account(account=account)
        logger.info(f"Email-verified account created: {username} ({email}) id={account_id}")

        # ── Enable LNBITS_USER_DEFAULT_EXTENSIONS on the new account ──────────
        # LNbits's native register endpoint does this; we have to mirror it.
        try:
            default_exts = settings.lnbits_user_default_extensions or []
            for ext_id in default_exts:
                # Build UserExtension model — field names match LNbits internals
                user_ext = UserExtension(
                    user=account_id,
                    extension=ext_id,
                    active=True,
                )
                await update_user_extension(user_extension=user_ext)
                logger.info(f"Enabled default extension '{ext_id}' for {account_id}")
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

    return {
        "success":  True,
        "username": username,
        "email":    email,
    }
