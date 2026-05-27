import base64
import hmac
import hashlib
import json
import time
from typing import Optional
from fastapi import Cookie, Depends, HTTPException, Request, Response
from http import HTTPStatus
from loguru import logger
from lnbits.settings import settings as lnbits_settings
# Variant for admin-key routes:
from lnbits.decorators import require_admin_key
from lnbits.decorators import WalletTypeInfo, require_invoice_key
from ..crud import get_trusted_device, touch_trusted_device

MAX_TRUSTED_DEVICES_PER_USER = 3
DEVICE_COOKIE_NAME           = "silnt_device_id"
DEVICE_COOKIE_MAX_AGE        = 365 * 24 * 3600   # 1 year
DEVICE_CONFIRM_TOKEN_TTL     = 3600              # 1 hour

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


def set_device_cookie(response: Response, device_id: str) -> None:
    """Set the HttpOnly device_id cookie. Same-site + secure."""
    response.set_cookie(
        key      = DEVICE_COOKIE_NAME,
        value    = device_id,
        max_age  = DEVICE_COOKIE_MAX_AGE,
        httponly = True,
        secure   = True,
        samesite = "lax",   # 'strict' breaks the email-link redirect — lax is fine
        path     = "/",
    )


def get_client_ip(request: Request) -> str:
    """Best-effort IP extraction — checks X-Forwarded-For first (Caddy proxy)."""
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


async def require_trusted_device(
    request: Request,
    key_info: WalletTypeInfo = Depends(require_invoice_key),
    silnt_device_id: Optional[str] = Cookie(default=None),
) -> WalletTypeInfo:
    """
    Combined dependency: validates the API key AND the device cookie.
    Use this in place of `require_invoice_key` on every endpoint that should
    require a trusted device.
    """
    if not silnt_device_id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: no device cookie present",
        )

    device = await get_trusted_device(key_info.wallet.user, silnt_device_id)
    if not device:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: device not in trusted list",
        )

    # Track last seen (fire-and-forget; don't fail the request if this fails)
    try:
        await touch_trusted_device(key_info.wallet.user, silnt_device_id)
    except Exception as e:
        logger.warning(f"touch_trusted_device failed: {e}")

    return key_info


async def require_trusted_device_admin(
    request: Request,
    key_info: WalletTypeInfo = Depends(require_admin_key),
    silnt_device_id: Optional[str] = Cookie(default=None),
) -> WalletTypeInfo:
    if not silnt_device_id:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: no device cookie present",
        )
    device = await get_trusted_device(key_info.wallet.user, silnt_device_id)
    if not device:
        raise HTTPException(
            status_code=HTTPStatus.FORBIDDEN,
            detail="device-not-trusted: device not in trusted list",
        )
    try:
        await touch_trusted_device(key_info.wallet.user, silnt_device_id)
    except Exception as e:
        logger.warning(f"touch_trusted_device failed: {e}")
    return key_info
