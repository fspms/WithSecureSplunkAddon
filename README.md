# WithSecure Elements Add-on

A Technology Add-on (TA) for use with Splunk® Enterprise that ingests security telemetry from the **WithSecure Elements** platform — including EPP security events and Broad Context Detection (BCD) incidents and detections.

[![Splunkbase](https://img.shields.io/badge/Splunkbase-Install-65A637.svg)](https://splunkbase.splunk.com/app/8820)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-%3E%3D10.2-green.svg)](https://www.splunk.com)
[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org)

---

## Release lines

This add-on ships in two parallel release lines. Pick the one matching your Splunk platform:

| Line | Compatible Splunk versions | Python | Status | Where to get it |
|---|---|---|---|---|
| **`1.1.x`** (main) | **Splunk Enterprise / Cloud 10.2+** | 3.13 | ✅ Active — new features and fixes land here first | [Releases](https://github.com/fspms/WithSecureSplunkAddon/releases) on `main` branch |
| **`1.0.x`** (maintenance) | Splunk Enterprise 9.0 → 10.1 | 3.9 | 🛠 Maintenance-only — critical bug fixes backported | [Releases](https://github.com/fspms/WithSecureSplunkAddon/releases) tagged `v1.0.*`, code on the [`v1.0.x`](https://github.com/fspms/WithSecureSplunkAddon/tree/v1.0.x) branch |

**Why two lines?** Splunk deprecated Python 3.9 in Splunk Enterprise 10.2, and Splunk Cloud will drop compatibility with add-ons declaring `python.required = 3.9` in the near future. To keep serving both audiences without abandoning the large installed base of Splunk 9.x, the code is preserved on the `v1.0.x` branch and new development continues on `main` with Python 3.13.

**Which one should I install?**

- Splunk Enterprise 9.x, 10.0, 10.1 → **use `1.0.x`**
- Splunk Enterprise / Cloud **10.2 or later** → **use `1.1.x`**
- Fresh install with a modern Splunk deployment → **use `1.1.x`**

Both lines produce identical events (same sourcetypes, same field extractions, same CIM mappings). Upgrading from `1.0.x` to `1.1.x` is a straightforward in-place upgrade once your Splunk instance is on 10.2 or later — KV Store checkpoints, input configuration, and existing indexed events are preserved.

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
| Splunk Enterprise / Cloud | ≥ 10.2 (for the 1.0.x line: 9.0 – 10.1) |
| Python | 3.13 (bundled with Splunk 10.2+); the 1.0.x line uses 3.9 |
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
| `proxy_url` | Optional HTTP/HTTPS proxy URL for outbound API calls (blank = direct) |
| `proxy_username` | Optional proxy authentication username |
| `proxy_password` | Optional proxy authentication password |
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
| `proxy_url` | Optional HTTP/HTTPS proxy URL for outbound API calls (blank = direct) |
| `proxy_username` | Optional proxy authentication username |
| `proxy_password` | Optional proxy authentication password |
| `interval` | Poll interval in seconds (default: 300) |
| `index` | Target Splunk index (default: main) |

### Proxy configuration

If your Splunk host must reach the internet through a corporate HTTP/HTTPS proxy, set `proxy_url` on each input. Both modular inputs (EPP + BCD) and the `| fetchdetections` command honour the setting; when `auto_fetch_detections=true`, detections are fetched through the same proxy.

Example — proxy without authentication:

```
proxy_url = http://proxy.corp.example:3128
```

Example — proxy with authentication:

```
proxy_url = http://proxy.corp.example:3128
proxy_username = svc-splunk
proxy_password = <secret>
```

Notes:
- If the URL has no scheme it is assumed to be `http://`.
- Special characters in the password are URL-encoded automatically before being embedded in the proxy URL.
- Splunk's global `server.conf [proxyConfig]` is used only by splunkd's internal services and is **not** inherited by modular input scripts — each add-on must expose its own proxy configuration, which is the industry-standard pattern used by every Splunk-published add-on that talks to a SaaS API.

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
