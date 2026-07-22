"""
KV-Store-backed per-incident lock for BCD detection fetches.

The auto-fetch modular input and the on-demand `| fetchdetections` command
both pull detections for the same incident and write to the same Splunk
index. Without coordination, a near-simultaneous run can cause the same
detection to be indexed twice (the per-incident createdTimestamp checkpoint
is only updated after the write completes).

This module provides a short-lived advisory lock per incident, stored in
the dedicated `locks` KV-store collection. The `_key` field is naturally
unique inside a KV-store collection, so an insert with an explicit `_key`
is atomic: only one acquirer succeeds, others get HTTP 409.

A lock that is leaked (process killed) is reclaimed via an `expires_at`
field checked on acquire — see ``LOCK_TTL_SECONDS`` below.
"""

import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

_bin = os.path.dirname(os.path.abspath(__file__))
if _bin not in sys.path:
    sys.path.insert(0, _bin)

import splunk.rest as rest  # type: ignore[import-not-found]

from withsecure_api import parse_iso_utc

logger = logging.getLogger("ta-withsecure-elements")

# TTL chosen to cover a realistic worst-case detection fetch (a few pages
# of pagination + a single rate-limit retry) while still self-recovering
# quickly if a holder process is killed. Strictly shorter than the
# default modular-input interval (300 s) so the next poll cycle is
# guaranteed to see a freed slot.
LOCK_TTL_SECONDS = 90

_LOCKS_PATH = (
    "/servicesNS/nobody/ta-withsecure-elements/storage/collections/data/locks"
)


def _lock_key(incident_id: str) -> str:
    return f"lock_detections_{incident_id}"


def _utc_now_iso() -> str:
    dt = datetime.now(timezone.utc)
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def _parse_iso(ts: str) -> Optional[datetime]:
    """Parse an ISO-8601 UTC timestamp, tolerating optional milliseconds.

    Uses the same helper as withsecure_api so a lock's `expires_at`
    written without milliseconds (or by any future revision that changes
    the format) is still parseable.
    """
    if not ts:
        return None
    try:
        return parse_iso_utc(ts)
    except (ValueError, TypeError):
        return None


def acquire_detection_lock(session_key: str, incident_id: str) -> Optional[str]:
    """Try to acquire the lock for an incident.

    Returns the owner UUID on success, or ``None`` if another live holder
    has the lock. A holder whose ``expires_at`` has elapsed is forcefully
    reclaimed.
    """
    owner = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    payload = {
        "_key": _lock_key(incident_id),
        "owner": owner,
        "acquired_at": _utc_now_iso(),
        "expires_at": (now + timedelta(seconds=LOCK_TTL_SECONDS)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        ),
    }
    try:
        resp, _ = rest.simpleRequest(
            _LOCKS_PATH,
            sessionKey=session_key,
            method="POST",
            jsonargs=json.dumps(payload),
            raiseAllErrors=True,
        )
        if str(getattr(resp, "status", "")) == "201":
            return owner
    except Exception as exc:  # noqa: BLE001 — broad: REST helper raises mixed types
        # 409 means a record with the same _key already exists; anything
        # else is unexpected and treated as "lock unavailable" so the
        # caller falls back to existing-only behavior.
        if "409" not in str(exc):
            logger.warning(
                "Lock acquire failed unexpectedly for %s: %s", incident_id, exc
            )
            return None

    # Conflict — inspect the existing lock; if expired we may reclaim it.
    existing = _read_lock(session_key, incident_id)
    if existing is None:
        return None
    expires = _parse_iso(existing.get("expires_at", ""))
    if expires is None or expires > now:
        # Still live
        return None

    # Expired — try to take over. DELETE may race with another waiter,
    # in which case our subsequent POST will get another 409 and we give up.
    try:
        rest.simpleRequest(
            f"{_LOCKS_PATH}/{_lock_key(incident_id)}",
            sessionKey=session_key,
            method="DELETE",
            raiseAllErrors=True,
        )
    except Exception:  # noqa: BLE001
        pass

    try:
        resp, _ = rest.simpleRequest(
            _LOCKS_PATH,
            sessionKey=session_key,
            method="POST",
            jsonargs=json.dumps(payload),
            raiseAllErrors=True,
        )
        if str(getattr(resp, "status", "")) == "201":
            return owner
    except Exception:  # noqa: BLE001
        return None
    return None


def release_detection_lock(
    session_key: str, incident_id: str, owner: str
) -> None:
    """Release the lock if we still own it.

    Owner is checked because the TTL may have expired and another process
    may now hold the slot — in that case we leave it alone.
    """
    existing = _read_lock(session_key, incident_id)
    if existing is None:
        return
    if existing.get("owner") != owner:
        return
    try:
        rest.simpleRequest(
            f"{_LOCKS_PATH}/{_lock_key(incident_id)}",
            sessionKey=session_key,
            method="DELETE",
            raiseAllErrors=True,
        )
    except Exception:  # noqa: BLE001
        # Already gone is fine; anything else is non-fatal.
        pass


def _read_lock(session_key: str, incident_id: str) -> Optional[dict]:
    try:
        _, raw = rest.simpleRequest(
            f"{_LOCKS_PATH}/{_lock_key(incident_id)}",
            sessionKey=session_key,
            method="GET",
            raiseAllErrors=True,
        )
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return None
