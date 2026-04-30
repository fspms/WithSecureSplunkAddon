#!/usr/bin/env python3
"""
Custom generating search command: | fetchdetections incident_id=<id>

Returns BCD detections for a given incident. If detections are already
indexed they are returned immediately (no API call). Otherwise they are
fetched from the WithSecure API, indexed, and returned so the analyst
sees them straight away.

Usage in SPL:
    | fetchdetections incident_id="308b348b-92de-42a5-af12-2c1169e91827"
"""

import json
import os
import sys

_bin = os.path.dirname(os.path.abspath(__file__))
_app = os.path.dirname(_bin)
sys.path.insert(0, _bin)
sys.path.insert(0, os.path.join(_app, "lib"))

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)
import splunk.rest as rest

from withsecure_api import WithSecureClient, WithSecureAPIError, flatten_detection

_SOURCETYPE = "withsecure:epp:bcd_detection"


@Configuration(type="events")
class FetchDetectionsCommand(GeneratingCommand):
    """Return BCD detections from index (if present) or live from the API."""

    incident_id = Option(
        name="incident_id",
        require=True,
        validate=validators.Match("incident_id", r"^[0-9a-f-]{36}$"),
    )

    def generate(self):
        session_key = self._metadata.searchinfo.session_key

        # Return already-indexed detections immediately — no API call needed
        existing = self._search_existing(session_key)
        if existing:
            for event in existing:
                yield event
            return

        # Nothing indexed yet — read credentials and call the API
        try:
            creds = self._get_credentials(session_key)
        except Exception as exc:
            self.error_exit(exc, f"Failed to read BCD input credentials: {exc}")
            return

        if not creds:
            self.error_exit(
                RuntimeError("no BCD input"),
                "No enabled BCD input found — configure one in Data Inputs first.",
            )
            return

        try:
            api = WithSecureClient(
                creds["client_id"], creds["client_secret"], creds["org_id"]
            )
            detections = api.get_incident_detections(self.incident_id)
        except WithSecureAPIError as exc:
            self.error_exit(exc, str(exc))
            return

        if not detections:
            return

        index = creds.get("index", "main")
        uri = (
            f"/services/receivers/simple"
            f"?index={index}&sourcetype={_SOURCETYPE}&source=withsecure_elements_BCD_incidents"
        )

        for detection in detections:
            detection["incident_id"] = self.incident_id
            flat = flatten_detection(detection)
            try:
                rest.simpleRequest(
                    uri,
                    sessionKey=session_key,
                    method="POST",
                    jsonargs=json.dumps(flat),
                    raiseAllErrors=True,
                )
            except Exception:
                pass  # indexing failure is non-fatal; still yield the result
            yield flat

    def _search_existing(self, session_key: str) -> list:
        """Return indexed detections for this incident, or [] if none found.

        Uses a keyword search on the UUID so the lookup works regardless of
        whether field extraction is configured for the detection sourcetype.
        """
        try:
            _, raw = rest.simpleRequest(
                "/services/search/jobs",
                sessionKey=session_key,
                method="POST",
                postargs={
                    "search": (
                        f'search index=* sourcetype="{_SOURCETYPE}"'
                        f' "{self.incident_id}"'
                    ),
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                    "earliest_time": "0",
                    "latest_time": "now",
                    "count": "0",
                },
                raiseAllErrors=True,
            )
            data = json.loads(raw)
            return data.get("results", [])
        except Exception:
            return []

    def _get_credentials(self, session_key: str) -> dict:
        _, raw = rest.simpleRequest(
            (
                "/servicesNS/nobody/ta-withsecure-elements"
                "/data/inputs/withsecure_bcd_input"
                "?output_mode=json&count=0"
            ),
            sessionKey=session_key,
            method="GET",
            raiseAllErrors=True,
        )
        data = json.loads(raw)
        for entry in data.get("entry", []):
            conf = entry.get("content", {})
            if conf.get("disabled") in (True, "1", "true", 1):
                continue
            client_id = (conf.get("client_id") or "").strip()
            client_secret = (conf.get("client_secret") or "").strip()
            org_id = (conf.get("org_id") or "").strip()
            if client_id and client_secret and org_id:
                return {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "org_id": org_id,
                    "index": conf.get("index", "main"),
                }
        return None


if __name__ == "__main__":
    dispatch(FetchDetectionsCommand, sys.argv, sys.stdin, sys.stdout, __name__)
