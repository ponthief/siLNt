# Firebase Cloud Messaging (FCM HTTP v1) sender.
#
# Sends push notifications to users' devices — e.g. "payment received" when a
# background scan finds funds while the app is closed.
#
# SETUP (server side):
#   1. Create a Firebase project and a service account with the
#      "Firebase Cloud Messaging API" enabled; download its JSON key.
#   2. Put the JSON on the server and set:  SILNT_FCM_CREDENTIALS=/path/to/key.json
#   If the env var is unset or the file is missing, push is simply disabled
#   (sends are no-ops) — the rest of the app is unaffected.
import asyncio
import os
from typing import Optional

import httpx
from loguru import logger

_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]

_creds = None  # cached google.oauth2.service_account.Credentials


def _resolve_credentials_path() -> str:
    """Where the service-account JSON lives. Read at call-time (not import-time)
    so a restart reliably picks up a freshly-added .env value regardless of
    import order. Falls back to the LNbits settings object in case this
    deployment loads .env into pydantic settings but not os.environ."""
    p = os.environ.get("SILNT_FCM_CREDENTIALS", "").strip()
    if p:
        return p
    try:
        from lnbits.settings import settings as _s

        v = getattr(_s, "silnt_fcm_credentials", None)
        if v:
            return str(v).strip()
    except Exception:
        pass
    return ""


def _load_credentials():
    """Return (creds, reason). On failure creds is None and reason is a
    human-readable explanation of exactly which link is broken — so callers can
    tell 'env unset' from 'file missing' from 'google-auth not installed'."""
    global _creds
    if _creds is not None:
        return _creds, ""
    path = _resolve_credentials_path()
    if not path:
        return None, (
            "SILNT_FCM_CREDENTIALS is not set in the server environment "
            "(the LNbits process doesn't see it — if it's in .env, make sure "
            "that .env is actually exported into LNbits' environment, then "
            "restart)."
        )
    if not os.path.exists(path):
        return None, (
            f"SILNT_FCM_CREDENTIALS is set but no readable file exists at that "
            f"path from the LNbits process: {path} (check the path is absolute "
            f"and the file is readable by the LNbits user)."
        )
    try:
        from google.oauth2 import service_account
    except Exception as e:
        return None, (
            f"The 'google-auth' package isn't installed in the LNbits "
            f"environment ({e}). Install the extension's dependencies "
            f"(google-auth) and restart LNbits."
        )
    try:
        _creds = service_account.Credentials.from_service_account_file(
            path, scopes=_SCOPES
        )
    except Exception as e:
        return None, (
            f"Found the credentials file but couldn't load it as a service "
            f"account: {e} (is it the service-account JSON, not google-services.json?)."
        )
    return _creds, ""


def _get_credentials():
    creds, reason = _load_credentials()
    if creds is None and reason:
        logger.warning(f"FCM: {reason}")
    return creds


def push_enabled() -> bool:
    return _load_credentials()[0] is not None


def _fresh_access_token(creds) -> str:
    # Blocking refresh — call via run_in_executor.
    from google.auth.transport.requests import Request

    if not creds.valid:
        creds.refresh(Request())
    return creds.token


async def send_fcm(
    tokens: list, title: str, body: str, data: Optional[dict] = None
) -> None:
    """Send a notification to each token via FCM HTTP v1. Best-effort — never
    raises. Tokens FCM reports as unregistered/invalid are pruned from the DB."""
    creds = _get_credentials()
    if not creds or not tokens:
        return
    try:
        loop = asyncio.get_event_loop()
        access_token = await loop.run_in_executor(None, _fresh_access_token, creds)
        project_id = creds.project_id
    except Exception as e:
        logger.warning(f"FCM: token refresh failed: {e}")
        return

    from ..crud import remove_fcm_token

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload_data = {str(k): str(v) for k, v in (data or {}).items()}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for token in tokens:
            msg = {
                "message": {
                    "token": token,
                    "notification": {"title": title, "body": body},
                    "data": payload_data,
                    "android": {"priority": "high"},
                }
            }
            try:
                r = await client.post(url, headers=headers, json=msg)
                if r.status_code == 200:
                    continue
                txt = r.text.lower()
                if r.status_code in (400, 404) and (
                    "unregistered" in txt
                    or "not-registered" in txt
                    or "invalid-argument" in txt
                    or "invalid registration" in txt
                ):
                    await remove_fcm_token(token)
                else:
                    logger.warning(f"FCM send {r.status_code}: {r.text[:200]}")
            except Exception as e:
                logger.warning(f"FCM send error: {e}")


async def send_fcm_report(
    tokens: list, title: str, body: str, data: Optional[dict] = None
) -> dict:
    """Like send_fcm but returns a structured report for diagnostics, so a test
    endpoint can tell the user *why* nothing arrived (no credentials, no
    registered device, or a specific FCM rejection). Never raises. Invalid
    tokens are still pruned from the DB.

    Returns: {
        push_enabled: bool,   # server has SILNT_FCM_CREDENTIALS loaded
        tokens: int,          # how many device tokens were tried
        sent: int,            # accepted by FCM (200)
        pruned: int,          # removed because FCM said unregistered/invalid
        errors: [str],        # human-readable failure reasons
    }
    """
    report = {"push_enabled": False, "tokens": len(tokens), "sent": 0,
              "pruned": 0, "errors": []}

    creds, reason = _load_credentials()
    if not creds:
        report["errors"].append(reason or "Server has no FCM credentials.")
        return report
    report["push_enabled"] = True
    if not tokens:
        report["errors"].append("No device tokens registered for this user.")
        return report

    try:
        loop = asyncio.get_event_loop()
        access_token = await loop.run_in_executor(None, _fresh_access_token, creds)
        project_id = creds.project_id
    except Exception as e:
        report["errors"].append(f"OAuth token refresh failed: {e}")
        return report

    from ..crud import remove_fcm_token

    url = f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    payload_data = {str(k): str(v) for k, v in (data or {}).items()}

    async with httpx.AsyncClient(timeout=10.0) as client:
        for token in tokens:
            msg = {
                "message": {
                    "token": token,
                    "notification": {"title": title, "body": body},
                    "data": payload_data,
                    "android": {"priority": "high"},
                }
            }
            try:
                r = await client.post(url, headers=headers, json=msg)
                if r.status_code == 200:
                    report["sent"] += 1
                    continue
                txt = r.text.lower()
                if r.status_code in (400, 404) and (
                    "unregistered" in txt
                    or "not-registered" in txt
                    or "invalid-argument" in txt
                    or "invalid registration" in txt
                ):
                    await remove_fcm_token(token)
                    report["pruned"] += 1
                    report["errors"].append(
                        f"Token …{token[-8:]} was invalid/unregistered (pruned)."
                    )
                else:
                    report["errors"].append(
                        f"FCM {r.status_code}: {r.text[:160]}"
                    )
            except Exception as e:
                report["errors"].append(f"send error: {e}")
    return report
