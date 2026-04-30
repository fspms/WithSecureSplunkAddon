#!/usr/bin/env python3
"""
Splunk modular input for WithSecure Elements EPP Security Events.

Polls the WithSecure Elements API on a configurable interval, checkpoints
progress in the KV Store, and indexes one Splunk event per security event
with sourcetype=withsecure:epp:security_event.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

# Add bin/ and lib/ to path so splunklib and withsecure_api are importable.
_bin = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _bin)
sys.path.insert(0, os.path.join(os.path.dirname(_bin), "lib"))

import splunklib.client as client
import splunklib.modularinput as smi

from withsecure_api import WithSecureClient, WithSecureAPIError

logger = logging.getLogger("ta-withsecure-elements")

_CHECKPOINT_COLLECTION = "checkpoints"
_SOURCETYPE = "withsecure:epp:security_event"


class EPPInput(smi.Script):
    """Modular input that polls WithSecure EPP security events."""

    def get_scheme(self) -> smi.Scheme:
        scheme = smi.Scheme("WithSecure Elements EPP Security Events")
        scheme.description = (
            "Polls the WithSecure Elements API for EPP security events."
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
        return scheme

    def validate_input(self, definition: smi.ValidationDefinition) -> None:
        org_id = (definition.parameters.get("org_id") or "").strip()
        if not org_id:
            raise ValueError("org_id must not be empty")

    def stream_events(self, inputs: smi.InputDefinition, ew: smi.EventWriter) -> None:
        for input_name, input_item in inputs.inputs.items():
            try:
                self._process_input(input_name, input_item, inputs, ew)
            except Exception:
                logger.exception("Unhandled error in EPP input %s", input_name)

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

        service = self._get_service(inputs)
        checkpoint_key = f"epp_last_timestamp_{org_id}"
        last_ts = self._get_checkpoint(service, checkpoint_key)

        if not last_ts:
            last_ts = _utc_iso(datetime.now(timezone.utc) - timedelta(hours=24))
            logger.info("EPP first run for org %s, starting from %s", org_id, last_ts)

        api = WithSecureClient(client_id, client_secret, org_id)

        now_ts = _utc_iso(datetime.now(timezone.utc))
        try:
            events = api.get_epp_events(last_ts, now_ts)
        except WithSecureAPIError as exc:
            logger.error("Failed to fetch EPP events: %s", exc)
            return

        newest_ts = last_ts
        for event in events:
            raw = json.dumps(event)
            ev = smi.Event(
                data=raw,
                sourcetype=_SOURCETYPE,
                index=index,
                source="withsecure_elements_security_events",
            )
            # Use the event's own persistence timestamp if available
            event_ts = event.get("persistenceTimestamp")
            if event_ts and event_ts > newest_ts:
                newest_ts = event_ts
            ew.write_event(ev)

        if events:
            self._set_checkpoint(service, checkpoint_key, _advance_ts(newest_ts))
            logger.info(
                "Indexed %d EPP events for org %s; checkpoint advanced to %s",
                len(events),
                org_id,
                newest_ts,
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


def _utc_iso(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{ms:03d}Z")


def _advance_ts(ts: str) -> str:
    """Return ts + 1 ms so the next poll window is exclusive of the last seen event."""
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    return _utc_iso(dt + timedelta(milliseconds=1))


if __name__ == "__main__":
    sys.exit(EPPInput().run(sys.argv))
