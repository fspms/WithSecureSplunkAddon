#!/usr/bin/env python3
"""
Splunk modular input for WithSecure Elements BCD (Broad Context Detection) Incidents.

Polls the WithSecure Elements API on a configurable interval, handles full
pagination via nextAnchor, checkpoints progress in the KV Store, and indexes
one Splunk event per BCD incident with sourcetype=withsecure:epp:bcd_incident.

When auto_fetch_detections is enabled, detections for each new incident are
fetched inline and indexed with sourcetype=withsecure:epp:bcd_detection.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import List, Optional

_bin = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _bin)
sys.path.insert(0, os.path.join(os.path.dirname(_bin), "lib"))

import splunklib.client as client
import splunklib.modularinput as smi

from withsecure_api import WithSecureClient, WithSecureAPIError, flatten_detection

logger = logging.getLogger("ta-withsecure-elements")

_CHECKPOINT_COLLECTION = "checkpoints"
_SOURCETYPE_INCIDENT = "withsecure:epp:bcd_incident"
_SOURCETYPE_DETECTION = "withsecure:epp:bcd_detection"
_VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


class BCDInput(smi.Script):
    """Modular input that polls WithSecure BCD incidents."""

    def get_scheme(self) -> smi.Scheme:
        scheme = smi.Scheme("WithSecure Elements BCD Incidents")
        scheme.description = (
            "Polls the WithSecure Elements API for Broad Context Detection incidents."
        )
        scheme.use_external_validation = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                "client_id",
                title="Client ID",
                description="OAuth2 client ID from WithSecure Elements portal.",
                data_type=smi.Argument.data_type_string,
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "client_secret",
                title="Client Secret",
                description="OAuth2 client secret (stored encrypted).",
                data_type=smi.Argument.data_type_string,
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "org_id",
                title="Organization ID",
                description="WithSecure Elements organization UUID.",
                data_type=smi.Argument.data_type_string,
                required_on_create=True,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "risk_level_filter",
                title="Risk Level Filter",
                description=(
                    "Comma-separated risk levels to collect: low,medium,high,critical. "
                    "Leave blank for all."
                ),
                data_type=smi.Argument.data_type_string,
                required_on_create=False,
            )
        )
        scheme.add_argument(
            smi.Argument(
                "auto_fetch_detections",
                title="Auto-fetch Detections",
                description=(
                    "Set to 'true' to fetch and index all individual detections "
                    "for each new BCD incident "
                    "(sourcetype=withsecure:epp:bcd_detection). "
                    "Provides granular process-level detail (processes, commands, "
                    "file accesses) but generates one additional API call per new "
                    "incident and increases the duration of each polling cycle. "
                    "Accepted values: true, false. Default: false."
                ),
                data_type=smi.Argument.data_type_string,
                required_on_create=False,
            )
        )
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition) -> None:
        org_id = (definition.parameters.get("org_id") or "").strip()
        if not org_id:
            raise ValueError("org_id must not be empty")

        raw_filter = (definition.parameters.get("risk_level_filter") or "").strip()
        if raw_filter:
            for level in _parse_risk_levels(raw_filter):
                if level not in _VALID_RISK_LEVELS:
                    raise ValueError(
                        f"Invalid risk_level_filter value '{level}'. "
                        f"Must be one of: {', '.join(sorted(_VALID_RISK_LEVELS))}"
                    )

        raw_fetch = (definition.parameters.get("auto_fetch_detections") or "").strip().lower()
        if raw_fetch and raw_fetch not in ("true", "false"):
            raise ValueError("auto_fetch_detections must be 'true' or 'false'")

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        for input_name, input_item in inputs.inputs.items():
            try:
                self._process_input(input_name, input_item, inputs, ew)
            except Exception:
                logger.exception("Unhandled error in BCD input %s", input_name)

    def _process_input(
        self,
        input_name: str,
        input_item: dict,
        inputs: smi.InputDefinition,
        ew: smi.EventWriter,
    ) -> None:
        client_id = input_item["client_id"]
        client_secret = input_item["client_secret"]
        org_id = input_item["org_id"].strip()
        index = input_item.get("index", "main")
        raw_filter = (input_item.get("risk_level_filter") or "").strip()
        risk_levels = _parse_risk_levels(raw_filter) if raw_filter else None
        auto_fetch = _parse_bool(input_item.get("auto_fetch_detections", "0"))

        service = self._get_service(inputs)
        checkpoint_key = f"bcd_last_timestamp_{org_id}"
        last_ts = self._get_checkpoint(service, checkpoint_key)

        if not last_ts:
            last_ts = _utc_iso(datetime.now(timezone.utc) - timedelta(hours=24))
            logger.info("BCD first run for org %s, starting from %s", org_id, last_ts)

        api = WithSecureClient(client_id, client_secret, org_id)

        total = 0
        newest_ts = last_ts
        next_anchor: Optional[str] = None

        while True:
            try:
                incidents, next_anchor = api.get_bcd_incidents(
                    last_ts,
                    risk_levels=risk_levels,
                    exclusive_start=next_anchor,
                )
            except WithSecureAPIError as exc:
                logger.error("Failed to fetch BCD incidents: %s", exc)
                break

            for incident in incidents:
                ev = smi.Event(
                    data=json.dumps(incident),
                    sourcetype=_SOURCETYPE_INCIDENT,
                    index=index,
                    source="withsecure_elements_BCD",
                )
                incident_ts = incident.get("updatedTimestamp")
                if incident_ts and incident_ts > newest_ts:
                    newest_ts = incident_ts
                ew.write_event(ev)
                total += 1

                if auto_fetch:
                    incident_id = incident.get("incidentId")
                    if incident_id:
                        self._fetch_and_index_detections(
                            api, incident_id, index, input_name, ew
                        )

            if not next_anchor:
                break

        if total:
            self._set_checkpoint(service, checkpoint_key, _advance_ts(newest_ts))
            logger.info(
                "Indexed %d BCD incidents for org %s; checkpoint advanced to %s",
                total,
                org_id,
                newest_ts,
            )

    # ------------------------------------------------------------------
    # Detection fetching
    # ------------------------------------------------------------------

    def _fetch_and_index_detections(
        self,
        api: WithSecureClient,
        incident_id: str,
        index: str,
        source: str,
        ew: smi.EventWriter,
    ) -> None:
        try:
            detections = api.get_incident_detections(incident_id)
        except WithSecureAPIError as exc:
            logger.error(
                "Failed to fetch detections for incident %s: %s", incident_id, exc
            )
            return

        for detection in detections:
            detection["incident_id"] = incident_id
            ew.write_event(
                smi.Event(
                    data=json.dumps(flatten_detection(detection)),
                    sourcetype=_SOURCETYPE_DETECTION,
                    index=index,
                    source="withsecure_elements_BCD",
                )
            )

        logger.info(
            "Indexed %d detections for incident %s", len(detections), incident_id
        )

    # ------------------------------------------------------------------
    # KV Store helpers
    # ------------------------------------------------------------------

    def _get_service(self, inputs: smi.InputDefinition) -> client.Service:
        return client.connect(
            token=inputs.metadata["session_key"],
            host="localhost",
            port=8089,
            scheme="https",
        )

    def _get_checkpoint(self, service: client.Service, key: str) -> Optional[str]:
        try:
            collection = service.kvstore[_CHECKPOINT_COLLECTION]
            results = collection.data.query(query=json.dumps({"key": key}))
            if results:
                return results[0].get("value")
        except Exception:
            logger.debug("No checkpoint found for key %s", key)
        return None

    def _set_checkpoint(self, service: client.Service, key: str, value: str) -> None:
        try:
            collection = service.kvstore[_CHECKPOINT_COLLECTION]
            results = collection.data.query(query=json.dumps({"key": key}))
            record = {
                "key": key,
                "value": value,
                "updated_at": _utc_iso(datetime.now(timezone.utc)),
            }
            if results:
                collection.data.update(results[0]["_key"], json.dumps(record))
            else:
                collection.data.insert(json.dumps(record))
        except Exception:
            logger.exception("Failed to save checkpoint for key %s", key)


def _parse_risk_levels(raw: str) -> List[str]:
    return [lvl.strip().lower() for lvl in raw.split(",") if lvl.strip()]


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _utc_iso(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def _advance_ts(ts: str) -> str:
    """Return ts + 1 ms so the next poll window is exclusive of the last seen event."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return _utc_iso(dt + timedelta(milliseconds=1))


if __name__ == "__main__":
    sys.exit(BCDInput().run(sys.argv))
