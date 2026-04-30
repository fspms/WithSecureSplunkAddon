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
        expires_in = int(data.get("expires_in", 3600))
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
                retry_after = float(resp.headers.get("Retry-After", _RETRY_BACKOFF * attempt))
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
    ) -> List[Dict[str, Any]]:
        """
        Fetch EPP security events via GET /security-events/v1/security-events.

        Args:
            timestamp_start: ISO-8601 UTC timestamp (inclusive lower bound).
            timestamp_end: ISO-8601 UTC timestamp (exclusive upper bound). Defaults to now.

        Returns:
            List of security event dicts.
        """
        params: Dict[str, Any] = {
            "organizationId": self._org_id,
            "persistenceTimestampStart": timestamp_start,
        }
        if timestamp_end:
            params["persistenceTimestampEnd"] = timestamp_end

        resp = self._request("get", _EPP_EVENTS_ENDPOINT, params=params)
        data = resp.json()
        events: List[Dict[str, Any]] = data.get("items", [])
        logger.info("Fetched %d EPP security events", len(events))
        return events

    # ------------------------------------------------------------------
    # BCD Incidents
    # ------------------------------------------------------------------

    def get_bcd_incidents(
        self,
        updated_start: str,
        risk_levels: Optional[List[str]] = None,
        exclusive_start: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """
        Fetch BCD incidents via GET /incidents/v1/incidents.

        Handles pagination automatically when exclusive_start is provided.

        Args:
            updated_start: ISO-8601 UTC timestamp for updatedTimestampStart filter.
            risk_levels: Optional list of risk level strings to filter by.
            exclusive_start: Pagination cursor (nextAnchor from previous response).

        Returns:
            Tuple of (list of incident dicts, nextAnchor or None).
        """
        params: Dict[str, Any] = {
            "organizationId": self._org_id,
            "updatedTimestampStart": updated_start,
        }
        if risk_levels:
            params["riskLevel"] = ",".join(risk_levels)
        if exclusive_start:
            params["exclusiveStart"] = exclusive_start

        resp = self._request("get", _BCD_INCIDENTS_ENDPOINT, params=params)
        data = resp.json()
        incidents: List[Dict[str, Any]] = data.get("items", [])
        next_anchor: Optional[str] = data.get("nextAnchor")
        logger.info(
            "Fetched %d BCD incidents (nextAnchor=%s)",
            len(incidents),
            next_anchor or "none",
        )
        return incidents, next_anchor

    # ------------------------------------------------------------------
    # Incident Detections
    # ------------------------------------------------------------------

    def get_incident_detections(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Fetch detections for a specific BCD incident.

        Args:
            incident_id: The WithSecure incident identifier.

        Returns:
            List of detection dicts.
        """
        params = {
            "incidentId": incident_id,
            "organizationId": self._org_id,
        }
        resp = self._request("get", _BCD_DETECTIONS_ENDPOINT, params=params)
        data = resp.json()
        detections: List[Dict[str, Any]] = data.get("items", [])
        logger.info(
            "Fetched %d detections for incident %s", len(detections), incident_id
        )
        return detections
