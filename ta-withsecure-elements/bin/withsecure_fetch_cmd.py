#!/usr/bin/env python3
"""
Custom generating search command: | fetchdetections incident_id=<id>

Returns BCD detections for a given incident. The command:
  1. Reads any detections already indexed in Splunk for this incident.
  2. Calls the WithSecure API for *new* detections (those with a
     createdTimestamp later than the most recent one we already have).
  3. Indexes the new detections and yields existing + new to the user.

The per-incident checkpoint stored in the KV Store
(``bcd_detections_last_<incident_id>``) is shared with the BCD modular input,
so the two flows do not re-index the same detection.

Usage in SPL:
    | fetchdetections incident_id="308b348b-92de-42a5-af12-2c1169e91827"
"""

import json
import os
import sys
from urllib.parse import quote

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

from withsecure_api import (
    WithSecureClient,
    WithSecureAPIError,
    flatten_detection,
    advance_ts,
)

_SOURCETYPE = "withsecure:epp:bcd_detection"
_CHECKPOINT_COLLECTION = "checkpoints"


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
        checkpoint_key = f"bcd_detections_last_{self.incident_id}"

        # 1) Already-indexed detections (yielded back to the user)
        existing = self._search_existing(session_key)

        # 2) Decide the createdTimestampStart for the API call:
        #    use whichever is most advanced between the indexed detections'
        #    latest createdTimestamp and the KV-store checkpoint written by
        #    the modular input (or a previous run of this command).
        latest_indexed_ts = self._latest_indexed_ts(existing)
        kv_ts = self._read_kv_checkpoint(session_key, checkpoint_key)
        cursor = self._max_ts(latest_indexed_ts, kv_ts)

        # 3) Read credentials. If unavailable, fall back to yielding the
        #    already-indexed detections — the analyst still sees something.
        try:
            creds = self._get_credentials(session_key)
        except Exception:
            creds = None
        if not creds:
            if existing:
                for event in existing:
                    yield event
                return
            self.error_exit(
                RuntimeError("no BCD input"),
                "No enabled BCD input found — configure one in Data Inputs first.",
            )
            return

        # 4) Fetch potentially-new detections from the API.
        try:
            api = WithSecureClient(
                creds["client_id"], creds["client_secret"], creds["org_id"]
            )
            new_detections = api.get_incident_detections(
                self.incident_id,
                created_timestamp_start=advance_ts(cursor) if cursor else None,
            )
        except WithSecureAPIError as exc:
            # API failure: still surface what we have indexed.
            if existing:
                for event in existing:
                    yield event
                return
            self.error_exit(exc, str(exc))
            return

        # 5) Index the new detections and track the newest createdTimestamp.
        index = creds.get("index", "main")
        uri = (
            f"/services/receivers/simple"
            f"?index={index}&sourcetype={_SOURCETYPE}&source=withsecure_elements_BCD_incidents"
        )
        newest_seen = cursor
        flat_new = []
        for detection in new_detections:
            detection["incident_id"] = self.incident_id
            flat = flatten_detection(detection)
            flat_new.append(flat)
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
            det_ts = detection.get("createdTimestamp")
            if det_ts and (newest_seen is None or det_ts > newest_seen):
                newest_seen = det_ts

        # 6) Advance the shared KV checkpoint so the modular input does not
        #    re-fetch these detections on its next poll.
        if newest_seen and newest_seen != cursor:
            self._write_kv_checkpoint(
                session_key, checkpoint_key, advance_ts(newest_seen)
            )

        # 7) Yield existing first (preserves their _time), then the new ones.
        for event in existing:
            yield event
        for flat in flat_new:
            yield flat

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _latest_indexed_ts(self, events: list):
        latest = None
        for ev in events:
            ts = ev.get("createdTimestamp")
            if ts and (latest is None or ts > latest):
                latest = ts
        return latest

    @staticmethod
    def _max_ts(a, b):
        if a and b:
            return a if a > b else b
        return a or b

    def _read_kv_checkpoint(self, session_key: str, key: str):
        try:
            _, raw = rest.simpleRequest(
                (
                    "/servicesNS/nobody/ta-withsecure-elements"
                    f"/storage/collections/data/{_CHECKPOINT_COLLECTION}"
                    f"?query={quote(json.dumps({'key': key}))}&output_mode=json"
                ),
                sessionKey=session_key,
                method="GET",
                raiseAllErrors=True,
            )
            results = json.loads(raw)
            if results:
                return results[0].get("value")
        except Exception:
            pass
        return None

    def _write_kv_checkpoint(self, session_key: str, key: str, value: str) -> None:
        try:
            existing_key = None
            _, raw = rest.simpleRequest(
                (
                    "/servicesNS/nobody/ta-withsecure-elements"
                    f"/storage/collections/data/{_CHECKPOINT_COLLECTION}"
                    f"?query={quote(json.dumps({'key': key}))}&output_mode=json"
                ),
                sessionKey=session_key,
                method="GET",
                raiseAllErrors=True,
            )
            results = json.loads(raw)
            if results:
                existing_key = results[0].get("_key")
            payload = json.dumps({"key": key, "value": value})
            if existing_key:
                rest.simpleRequest(
                    (
                        "/servicesNS/nobody/ta-withsecure-elements"
                        f"/storage/collections/data/{_CHECKPOINT_COLLECTION}/{existing_key}"
                    ),
                    sessionKey=session_key,
                    method="POST",
                    jsonargs=payload,
                    raiseAllErrors=True,
                )
            else:
                rest.simpleRequest(
                    (
                        "/servicesNS/nobody/ta-withsecure-elements"
                        f"/storage/collections/data/{_CHECKPOINT_COLLECTION}"
                    ),
                    sessionKey=session_key,
                    method="POST",
                    jsonargs=payload,
                    raiseAllErrors=True,
                )
        except Exception:
            pass  # checkpoint write failure is non-fatal

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
