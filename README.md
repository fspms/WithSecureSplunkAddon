# WithSecure Elements Add-on

A Technology Add-on (TA) for use with Splunk® Enterprise that ingests security telemetry from the **WithSecure Elements** platform — including EPP security events and Broad Context Detection (BCD) incidents and detections.

[![Splunkbase](https://img.shields.io/badge/Splunkbase-Install-65A637.svg)](https://splunkbase.splunk.com/app/8820)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-%3E%3D9.0-green.svg)](https://www.splunk.com)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org)

---

## Features

- **EPP Security Events** — polls the WithSecure Elements API on a configurable interval (default 5 minutes) and indexes endpoint protection events (`sourcetype=withsecure:epp:security_event`)
- **BCD Incidents** — indexes Broad Context Detection incidents with configurable risk level filtering (`sourcetype=withsecure:epp:bcd_incident`)
- **BCD Detections** — optionally auto-fetches granular process/file/network detections for each incident, or on-demand via a workflow action (`sourcetype=withsecure:epp:bcd_detection`)
- **Get BCD Details** workflow action — one-click button on any BCD incident event that returns detections directly in Splunk Search
- **Windows EventLog field extraction** — for `systemEventsLog` engine events, the `<Data Name='X'>Y</Data>` pairs inside `details.eventXml` are auto-extracted as searchable fields (`TargetUserName`, `LogonType`, `ProcessName`, etc.)
- **Daemon-style polling** — modular inputs run as long-lived daemons with a configurable interval, robust against Splunk's modular-input scheduler not relaunching the script on time
- **Concurrent-fetch safe** — per-incident KV Store advisory lock prevents race conditions between auto-fetch and on-demand `| fetchdetections`
- **CIM compliant** — field mappings for the Endpoint, Malware, and Intrusion Detection data models
- **Checkpoint-based polling** — KV Store checkpoints ensure no duplicate events across restarts

---

## Requirements

| Component | Version |
|---|---|
| Splunk Enterprise | ≥ 9.0 |
| Python | 3.9+ (bundled with Splunk) |
| Splunk KV Store | Enabled (used for checkpoints and per-incident locks) |
| WithSecure Elements | API access with OAuth2 credentials (`connect.api.read` scope) |

---

## Installation

**Recommended — from Splunkbase:**

1. In Splunk, go to **Apps → Find More Apps**
2. Search for `WithSecure Elements`, or install directly from [splunkbase.splunk.com/app/8820](https://splunkbase.splunk.com/app/8820)
3. Restart Splunk if prompted

**Alternative — from a GitHub release:**

1. Download the latest `.spl` from the [Releases](https://github.com/fspms/WithSecureSplunkAddon/releases) page
2. In Splunk, go to **Apps → Manage Apps → Install app from file**
3. Select the downloaded `.spl` and click **Upload**
4. Restart Splunk if prompted

---

## Configuration

### 1. Get API credentials from WithSecure Elements

In the WithSecure Elements portal, create an API client with `connect.api.read` scope. Note the **Client ID**, **Client Secret**, and your **Organization ID**.

### 2. Configure Data Inputs in Splunk

Go to **Settings → Data Inputs** and configure one or both inputs:

#### EPP Security Events

| Parameter | Description |
|---|---|
| `client_id` | OAuth2 Client ID |
| `client_secret` | OAuth2 Client Secret |
| `org_id` | WithSecure Organization UUID |
| `severity_filter` | Comma-separated filter: `info,warning,critical` (blank = all) |
| `interval` | Poll interval in seconds (default: 300) |
| `index` | Target Splunk index (default: main) |

#### BCD Incidents

| Parameter | Description |
|---|---|
| `client_id` | OAuth2 Client ID |
| `client_secret` | OAuth2 Client Secret |
| `org_id` | WithSecure Organization UUID |
| `risk_level_filter` | Comma-separated filter: `info,low,medium,high,severe` (blank = all) |
| `auto_fetch_detections` | `true` to auto-index detections per incident (default: false) |
| `interval` | Poll interval in seconds (default: 300) |
| `index` | Target Splunk index (default: main) |

---

## Sourcetypes

| Sourcetype | Description | Source |
|---|---|---|
| `withsecure:epp:security_event` | EPP endpoint protection events | `withsecure_elements_security_events` |
| `withsecure:epp:bcd_incident` | BCD incident summaries | `withsecure_elements_BCD` |
| `withsecure:epp:bcd_detection` | Granular BCD detections (process/file/cloud) | `withsecure_elements_BCD_incidents` |

### BCD incident updates → one event per update

A BCD incident is a long-lived object that evolves over time (new detections attached, status changes, resolution, comments...). The WithSecure API exposes this via `updatedTimestamp`, which changes on every modification.

This add-on indexes **one Splunk event per update**, with `_time` set to that update's `updatedTimestamp` (via `props.conf [withsecure:epp:bcd_incident]`). This is intentional: it gives a full audit timeline of the incident's lifecycle in Splunk.

**Consequence:** the same `incidentId` appears multiple times in the index — once per server-side update. To query the *current* state of incidents, dedup by `incidentId` and keep the latest:

```spl
index=main sourcetype="withsecure:epp:bcd_incident"
| dedup incidentId sortby -_time
```

For audit/timeline analysis (who closed what when, when severity escalated, etc.), search without dedup.

---

## Windows EventLog field extraction

Events from the `systemEventsLog` engine carry the original Windows Event Log XML in `details.eventXml`. The TA ships a search-time extraction that pulls every `<Data Name='X'>Y</Data>` pair into an individual field, so they are searchable directly without parsing the XML.

Field names follow the Windows EventLog convention (PascalCase): `TargetUserName`, `LogonType`, `IpAddress`, `ProcessName`, `AuthenticationPackageName`, `WorkstationName`, `SubjectUserSid`, etc. — same naming as Splunk's own `WinEventLog` source.

```spl
# Successful RDP-style remote logons (EventID 4624, LogonType 10)
index=main sourcetype="withsecure:epp:security_event"
    engine=systemEventsLog systemDataEventId=4624 LogonType=10
| stats count earliest(_time) as first_seen latest(_time) as last_seen
    by TargetUserName SubjectUserName systemDataComputer
```

The extraction is **search-time only**: it has zero cost at ingestion, applies retroactively to events already in the index, and produces no matches for events from other engines (so it's transparent for the rest of the data).

---

## CIM Field Mappings

### `withsecure:epp:security_event`
| CIM Field | Source Field |
|---|---|
| `dest` | `deviceName` |
| `signature` | `detectionName` |
| `app` | `engine` |
| `user` | `userName` |
| `src_ip` | `clientAddress` |
| `vendor_product` | `WithSecure Elements` |

### `withsecure:epp:bcd_incident`
| CIM Field | Source Field |
|---|---|
| `dest` | `affectedDevice` |
| `signature` | `name` |
| `severity` | `riskLevel` |
| `incident_id` | `incidentId` |
| `vendor_product` | `WithSecure Elements XDR` |

### `withsecure:epp:bcd_detection`
| CIM Field | Source Field |
|---|---|
| `dest` | `deviceName` |
| `process` | `processName` |
| `process_path` | `processPath` |
| `parent_process` | `parentProcessName` |
| `src_ip` | `ac_caller_ip_address` |
| `user` | `ac_principal_name` |
| `mitre_technique_id` | `ac_mitre_id` |
| `vendor_product` | `WithSecure Elements XDR` |

---

## On-Demand Detection Fetching

The **Get BCD Details** workflow action appears on any `withsecure:epp:bcd_incident` event (visible in **Smart** search mode). Clicking it runs:

```spl
| fetchdetections incident_id="<incident-uuid>"
```

The command checks whether detections are already indexed. If found, they are returned immediately. If not, they are fetched from the WithSecure API, indexed, and returned — so the analyst sees them straight away without waiting for the next poll cycle.

> **Note:** Enable **Smart** search mode in Splunk (search bar toggle) for the workflow action button to appear.

---

## SPL Examples

```spl
# All EPP security events in the last 24 hours
index=main sourcetype="withsecure:epp:security_event" earliest=-24h

# High and severe BCD incidents (current state of each — see note on BCD incident updates above)
index=main sourcetype="withsecure:epp:bcd_incident" (riskLevel=high OR riskLevel=severe)
| dedup incidentId sortby -_time

# Fetch detections for a specific incident on-demand
| fetchdetections incident_id="308b348b-92de-42a5-af12-2c1169e91827"

# MITRE ATT&CK techniques seen in detections
index=main sourcetype="withsecure:epp:bcd_detection"
| stats count by mitre_technique_id ac_mitre_tactic
| sort -count

# Windows logons collected via the systemEventsLog engine (LogonType 10 = RDP)
index=main sourcetype="withsecure:epp:security_event"
    engine=systemEventsLog systemDataEventId=4624 LogonType=10
| stats count earliest(_time) as first_seen latest(_time) as last_seen
    by TargetUserName SubjectUserName systemDataComputer
```

---

## Architecture

```
WithSecure Elements API
        │
        ├── GET /security-events/v1/security-events  ──► withsecure_epp_input.py
        │                                                  sourcetype: withsecure:epp:security_event
        │
        ├── GET /incidents/v1/incidents               ──► withsecure_bcd_input.py
        │                                                  sourcetype: withsecure:epp:bcd_incident
        │
        └── GET /incidents/v1/incidents/{id}/detections
                    ├── auto (auto_fetch_detections=true) ── withsecure_bcd_input.py
                    └── on-demand (workflow action)       ── withsecure_fetch_cmd.py
                                                             sourcetype: withsecure:epp:bcd_detection
```

Both modular inputs run as **long-lived daemons**: each one polls, sleeps for the configured `interval`, and repeats inside its own `while True` loop. This avoids depending on Splunk's modular-input scheduler relaunching the script on time, which has proven unreliable across environments. A heartbeat INFO log is emitted every 10 cycles so operators can see the daemon is healthy even during quiet periods.

### KV Store collections

| Collection | Purpose |
|---|---|
| `checkpoints` | Per-input poll cursors (`epp_last_timestamp_<org>`, `bcd_last_timestamp_<org>`) and per-incident detection cursors (`bcd_detections_last_<incident_id>`). Each cursor advances by 1 ms after a successful poll to prevent duplicate ingestion. |
| `locks` | Per-incident advisory locks (90 s TTL) shared between the auto-fetch input and the `\| fetchdetections` command. Prevents the two flows from racing each other when both target the same incident concurrently. Expired locks are reclaimed by the next acquirer. |

---

## Support

This is a community-maintained open source project. For questions, issues, or feature requests:

- **GitHub Issues**: [Open a new issue](https://github.com/fspms/WithSecureSplunkAddon/issues)
- **Source code**: [github.com/fspms/WithSecureSplunkAddon](https://github.com/fspms/WithSecureSplunkAddon)

For WithSecure Elements API questions, contact WithSecure directly via the [Elements portal](https://elements.withsecure.com).

## License

This project is licensed under the **Apache License 2.0** — see [LICENSE](ta-withsecure-elements/LICENSE) for details.

Free to use, modify, and distribute.
