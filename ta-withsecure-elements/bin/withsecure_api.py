"""
Shared API client for the WithSecure Elements API.

Handles OAuth2 client_credentials authentication with automatic token refresh,
and provides methods for all three API endpoints used by this add-on:
EPP Security Events, BCD Incidents, and Incident Detections.
"""

import base64
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger("ta-withsecure-elements")

# WITHSECURE_API_BASE_URL can be overridden in test/Docker environments.
_API_BASE = os.environ.get(
    "WITHSECURE_API_BASE_URL", "https://api.connect.withsecure.com"
).rstrip("/")

_TOKEN_ENDPOINT = f"{_API_BASE}/as/token.oauth2"
_EPP_EVENTS_ENDPOINT = f"{_API_BASE}/security-events/v1/security-events"
_BCD_INCIDENTS_ENDPOINT = f"{_API_BASE}/incidents/v1/incidents"
_BCD_DETECTIONS_ENDPOINT = f"{_API_BASE}/incidents/v1/detections"
_USER_AGENT = "SplunkTA-WithSecureElements/1.0.0"

# Retry configuration
_MAX_RETRIES = 3
_RETRY_BACKOFF = 2.0


def utc_iso(dt: datetime) -> str:
    """Format a UTC datetime as ISO-8601 with millisecond precision."""
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def advance_ts(ts: str) -> str:
    """Return ts + 1 ms (used to make checkpoint comparisons exclusive)."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return utc_iso(dt + timedelta(milliseconds=1))


def flatten_detection(detection: Dict[str, Any]) -> Dict[str, Any]:
    """Expand activityContext[] items into ac_{type} fields for direct searching.

    Items with no simple 'value' (e.g. histogram objects) are skipped.
    The original activityContext field is preserved.
    """
    result = dict(detection)
    seen: Dict[str, int] = {}
    for item in detection.get("activityContext", []):
        if not isinstance(item, dict):
            continue
        item_type = item.get("type", "")
        item_value = item.get("value")
        if not item_type or item_value is None:
            continue
        key = f"ac_{item_type}"
        count = seen.get(key, 0)
        if count == 0:
            result[key] = item_value
        elif count == 1:
            result[key] = [result[key], item_value]
        else:
            result[key].append(item_value)
        seen[key] = count + 1
    return result


class WithSecureAPIError(Exception):
    """Raised when the WithSecure API returns an unrecoverable error."""

    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"WithSecure API error {status_code}: {message}")


class WithSecureClient:
    """
    Client for the WithSecure Elements API.

    Thread-safety: not thread-safe; instantiate one client per input process.
    """

    def __init__(self, client_id: str, client_secret: str, org_id: str) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._org_id = org_id
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": _USER_AGENT})

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def get_token(self) -> str:
        """Return a valid bearer token, refreshing if necessary."""
        if self._token and time.time() < self._token_expires_at - 60:
            return self._token

        logger.debug("Fetching new OAuth2 token")
        credentials = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode()
        ).decode()

        resp = self._session.post(
            _TOKEN_ENDPOINT,
            headers={
                "Authorization": f"Basic {credentials}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={
                "grant_type": "client_credentials",
                "scope": "connect.api.read",
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        expires_in = int(data["expires_in"]) if "expires_in" in data else 3600
        self._token_expires_at = time.time() + expires_in
        logger.debug("Token acquired, expires in %s seconds", expires_in)
        return self._token  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal request helper
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute an authenticated HTTP request with retry on 429."""
        for attempt in range(1, _MAX_RETRIES + 1):
            token = self.get_token()
            kwargs.setdefault("headers", {})
            kwargs["headers"]["Authorization"] = f"Bearer {token}"
            kwargs.setdefault("timeout", 30)

            logger.debug("%s %s (attempt %d)", method.upper(), url, attempt)
            resp = self._session.request(method, url, **kwargs)

            if resp.status_code == 429:
                if "Retry-After" in resp.headers:
                    retry_after = float(resp.headers["Retry-After"])
                else:
                    retry_after = _RETRY_BACKOFF * attempt
                logger.warning(
                    "Rate limited by WithSecure API; waiting %.1f seconds (attempt %d/%d)",
                    retry_after,
                    attempt,
                    _MAX_RETRIES,
                )
                time.sleep(retry_after)
                continue

            if resp.status_code >= 400:
                raise WithSecureAPIError(resp.status_code, resp.text)

            return resp

        raise WithSecureAPIError(429, "Max retries exceeded due to rate limiting")

    # ------------------------------------------------------------------
    # EPP Security Events
    # ------------------------------------------------------------------

    def get_epp_events(
        self,
        timestamp_start: str,
        timestamp_end: Optional[str] = None,
        severities: Optional[List[str]] = None,
        anchor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Fetch EPP security events via GET /security-events/v1/security-events.

        Handles pagination via the nextAnchor cursor.

        Args:
            timestamp_start: ISO-8601 UTC timestamp (inclusive lower bound).
            timestamp_end: ISO-8601 UTC timestamp (exclusive upper bound). Defaults to now.
            severities: Optional list of severity strings to filter by.
                Valid values per the API spec: info, warning, critical.
            anchor: Pagination cursor (nextAnchor from previous response).

        Returns:
            Tuple of (list of security event dicts, nextAnchor or None).
        """
        params: Dict[str, Any] = {
            "organizationId": self._org_id,
            "persistenceTimestampStart": timestamp_start,
            # asc => oldest events first. On a partial pagination failure the
            # caller's checkpoint stays at the last successfully processed page,
            # so the un-fetched (newer) events are picked up on the next poll.
            # With the API default (desc), a partial failure would silently
            # drop the older events that hadn't been paged in yet.
            "order": "asc",
        }
        if timestamp_end:
            params["persistenceTimestampEnd"] = timestamp_end
        if severities:
            # API accepts repeated severity params; requests handles list values
            params["severity"] = severities
        if anchor:
            params["anchor"] = anchor

        resp = self._request("get", _EPP_EVENTS_ENDPOINT, params=params)
        data = resp.json()
        events: List[Dict[str, Any]] = data["items"] if "items" in data else []
        next_anchor: Optional[str] = data["nextAnchor"] if "nextAnchor" in data else None
        logger.info(
            "Fetched %d EPP security events (nextAnchor=%s)",
            len(events),
            "yes" if next_anchor else "none",
        )
        return events, next_anchor

    # ------------------------------------------------------------------
    # BCD Incidents
    # ------------------------------------------------------------------

    def get_bcd_incidents(
        self,
        updated_start: str,
        risk_levels: Optional[List[str]] = None,
        anchor: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Fetch BCD incidents via GET /incidents/v1/incidents.

        Handles pagination automatically when anchor is provided.

        Args:
            updated_start: ISO-8601 UTC timestamp for updatedTimestampStart filter.
            risk_levels: Optional list of risk level strings to filter by.
                Valid values per the API spec: info, low, medium, high, severe.
            anchor: Pagination cursor (nextAnchor from previous response).

        Returns:
            Tuple of (list of incident dicts, nextAnchor or None).
        """
        params: Dict[str, Any] = {
            "organizationId": self._org_id,
            "updatedTimestampStart": updated_start,
            # asc => oldest first; see get_epp_events for the rationale.
            "order": "asc",
        }
        if risk_levels:
            # API accepts repeated riskLevel params; requests handles list values
            params["riskLevel"] = risk_levels
        if anchor:
            params["anchor"] = anchor

        resp = self._request("get", _BCD_INCIDENTS_ENDPOINT, params=params)
        data = resp.json()
        incidents: List[Dict[str, Any]] = data["items"] if "items" in data else []
        next_anchor: Optional[str] = data["nextAnchor"] if "nextAnchor" in data else None
        logger.info(
            "Fetched %d BCD incidents (nextAnchor=%s)",
            len(incidents),
            next_anchor or "none",
        )
        return incidents, next_anchor

    # ------------------------------------------------------------------
    # Incident Detections
    # ------------------------------------------------------------------

    def get_incident_detections(
        self,
        incident_id: str,
        created_timestamp_start: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch all detections for a specific BCD incident, following pagination
        via the nextAnchor cursor (API page size is up to 100).

        Args:
            incident_id: The WithSecure incident identifier.
            created_timestamp_start: Optional ISO-8601 inclusive lower bound on
                detection createdTimestamp. Detections are immutable (the spec
                exposes no updatedTimestamp for them), so this is sufficient to
                fetch only the detections added since the last successful sync.

        Returns:
            List of detection dicts (all pages aggregated).
        """
        detections: List[Dict[str, Any]] = []
        anchor: Optional[str] = None
        seen_anchors: set = set()
        while True:
            params: Dict[str, Any] = {
                "incidentId": incident_id,
                "organizationId": self._org_id,
            }
            if created_timestamp_start:
                params["createdTimestampStart"] = created_timestamp_start
            if anchor:
                params["anchor"] = anchor
            resp = self._request("get", _BCD_DETECTIONS_ENDPOINT, params=params)
            data = resp.json()
            page = data["items"] if "items" in data else []
            detections.extend(page)
            anchor = data["nextAnchor"] if "nextAnchor" in data else None
            if not anchor:
                break
            # Defensive: API misbehavior could return the same cursor twice.
            if anchor in seen_anchors:
                logger.warning(
                    "Detection pagination loop detected for incident %s "
                    "(repeated nextAnchor); aborting after %d items",
                    incident_id,
                    len(detections),
                )
                break
            seen_anchors.add(anchor)
        logger.info(
            "Fetched %d detections for incident %s", len(detections), incident_id
        )
        return detections
