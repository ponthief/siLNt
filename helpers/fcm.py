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

_CREDENTIALS_PATH = os.environ.get("SILNT_FCM_CREDENTIALS", "").strip()
_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]

_creds = None  # cached google.oauth2.service_account.Credentials


def _get_credentials():
    global _creds
    if _creds is not None:
        return _creds
    if not _CREDENTIALS_PATH or not os.path.exists(_CREDENTIALS_PATH):
        return None
    try:
        from google.oauth2 import service_account

        _creds = service_account.Credentials.from_service_account_file(
            _CREDENTIALS_PATH, scopes=_SCOPES
        )
    except Exception as e:
        logger.warning(f"FCM: could not load credentials: {e}")
        return None
    return _creds


def push_enabled() -> bool:
    return _get_credentials() is not None


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
