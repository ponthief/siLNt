import base64
import hmac
import hashlib
import json
import time
import re
import os
from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Request, Response
from http import HTTPStatus
from loguru import logger
from lnbits.settings import settings as lnbits_settings
# Variant for admin-key routes:
from lnbits.decorators import require_admin_key
from lnbits.decorators import WalletTypeInfo, require_invoice_key
from ..crud import (
    get_trusted_device,
    touch_trusted_device,
    twofa_is_enabled,
    twofa_session_valid,
)
from .appenv import silnt_env
from .twofa import read_session_token, requires_twofa

MAX_TRUSTED_DEVICES_PER_USER = 5
DEVICE_COOKIE_PREFIX = "silnt_device_id_"
DEVICE_COOKIE_MAX_AGE        = 365 * 24 * 3600   # 1 year
DEVICE_CONFIRM_TOKEN_TTL     = 3600              # 1 hour
DEVICE_COOKIE_DOMAIN = silnt_env("SILNT_DEVICE_COOKIE_DOMAIN") or None
DEVICE_HEADER = "X-Silnt-Device"

def _is_thrilla_request(request: Request) -> bool:
    # WhiSPa's fetch wrapper sends this header on every call. The LNbits-native
    # extension page does not.
    return request.headers.get("X-Thrilla-Client") == "1"

def _safe_user_id_for_cookie(user_id: str) -> str:
    """Sanitize user_id for cookie name (allow only [a-zA-Z0-9_-])."""
    return re.sub(r"[^A-Za-z0-9_\-]", "", user_id or "")[:64]


def cookie_name_for_user(user_id: str) -> str:
    """Per-user cookie name. Multiple users on the same browser each get
    their own trust cookie."""
    return DEVICE_COOKIE_PREFIX + _safe_user_id_for_cookie(user_id)

def read_device_id(request: Request, user_id: str) -> str | None:
    """Device id from the per-user cookie (web) OR the X-Silnt-Device header
    (native app, where cross-site cookies aren't reliably stored)."""
    cookie_value = request.cookies.get(cookie_name_for_user(user_id))
    if cookie_value:
        return cookie_value
    hdr = request.headers.get(DEVICE_HEADER)
    return hdr.strip() if hdr else None

def set_device_cookie(response: Response, user_id: str, device_id: str) -> None:
    """Set the per-user HttpOnly device_id cookie."""
    response.set_cookie(
        key      = cookie_name_for_user(user_id),
        value    = device_id,
        max_age  = DEVICE_COOKIE_MAX_AGE,
        httponly = True,
        secure   = True,
        samesite = "lax",
        path     = "/",
        domain= DEVICE_COOKIE_DOMAIN
    )

def clear_device_cookie(response: Response, user_id: str) -> None:
    """Clear a user's device cookie (used when revoking own device)."""
    response.delete_cookie(cookie_name_for_user(user_id), path="/", domain=DEVICE_COOKIE_DOMAIN)

def _hmac_sign(payload: str) -> str:
    key = (lnbits_settings.auth_secret_key or "").encode()
    if not key:
        raise RuntimeError("LNBITS_AUTH_SECRET_KEY is not set — required for device tokens.")
    return base64.urlsafe_b64encode(
        hmac.new(key, payload.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()


def make_device_confirm_token(user_id: str, device_id: str, ua: str, ip: str) -> str:
    """Build a signed token for the email-confirmation link."""
    payload = {
        "user_id":    user_id,
        "device_id":  device_id,
        "ua":         (ua or "")[:512],
        "ip":         (ip or "")[:64],
        "exp":        int(time.time()) + DEVICE_CONFIRM_TOKEN_TTL,
    }
    body = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    sig = _hmac_sign(body)
    return f"{body}.{sig}"


def verify_device_confirm_token(token: str) -> Optional[dict]:
    try:
        body, sig = token.split(".", 1)
    except ValueError:
        return None
    expected = _hmac_sign(body)
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        # Re-pad base64
        padding = "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body + padding).decode())
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return payload


def get_client_ip(request: Request) -> str:
    """Best-effort IP extraction — checks X-Forwarded-For first (Caddy proxy)."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


TWOFA_REQUIRED_DETAIL = "twofa-required: second factor not presented for this session"


async def _require_twofa_session(request: Request, user_id: str) -> None:
    """The second factor, for a user who has turned it on.

    IT IS ITS OWN REFUSAL, and that is not cosmetic. Both clients fold a 403
    from this dependency into `untrusted` (services/deviceCheckOutcome.ts) and
    untrusted lands on the device-enrollment screen — whose only action is to
    email a DEVICE code. A bare 403 here would therefore answer "enter your
    two-factor code" with "we have emailed you a device confirmation", on a
    browser that is already trusted. The detail is prefixed so the clients can
    tell the two apart, exactly as `device-not-trusted:` already is.

    Checked AFTER the device gate on purpose: a browser that is not trusted at
    all has a more basic thing to do first, and asking for a second factor
    before the device is known would put two code prompts in a row.
    """
    if not requires_twofa(request):
        return
    if not await twofa_is_enabled(user_id):
        return
    token = read_session_token(request, user_id)
    if token and await twofa_session_valid(user_id, token):
        return
    raise HTTPException(
        status_code=HTTPStatus.FORBIDDEN,
        detail=TWOFA_REQUIRED_DETAIL,
    )


async def require_trusted_device(
    request: Request,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
) -> WalletTypeInfo:

    if not _is_thrilla_request(request):
        return key_info
    user_id = key_info.wallet.user
    # cookie_value = request.cookies.get(cookie_name_for_user(user_id))
    cookie_value = read_device_id(request, user_id)
    if not cookie_value:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: no device cookie present",
        )

    device = await get_trusted_device(user_id, cookie_value)
    if not device:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: device not in trusted list",
        )

    try:
        await touch_trusted_device(user_id, cookie_value)
    except Exception as e:
        logger.warning(f"touch_trusted_device failed: {e}")

    await _require_twofa_session(request, user_id)

    return key_info


async def require_trusted_device_admin(
    request: Request,
    key_info: WalletTypeInfo = Depends(require_admin_key),
) -> WalletTypeInfo:
    if not _is_thrilla_request(request):
        return key_info
    user_id = key_info.wallet.user
    # cookie_value = request.cookies.get(cookie_name_for_user(user_id))
    cookie_value = read_device_id(request, user_id)
    if not cookie_value:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: no device cookie present",
        )
    device = await get_trusted_device(user_id, cookie_value)
    if not device:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: device not in trusted list",
        )
    try:
        await touch_trusted_device(user_id, cookie_value)
    except Exception as e:
        logger.warning(f"touch_trusted_device failed: {e}")
    # The admin-key routes too: a second factor that the admin surface walks
    # around is a second factor on the read paths only.
    await _require_twofa_session(request, user_id)
    return key_info