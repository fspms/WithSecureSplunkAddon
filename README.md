# WithSecure Elements Add-on for Splunk

A Splunk Technology Add-on (TA) that ingests security telemetry from the **WithSecure Elements** platform into Splunk — including EPP security events and Broad Context Detection (BCD) incidents and detections.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Splunk](https://img.shields.io/badge/Splunk-%3E%3D8.0-green.svg)](https://www.splunk.com)
[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org)

---

## Features

- **EPP Security Events** — polls the WithSecure Elements API every 5 minutes and indexes endpoint protection events (`sourcetype=withsecure:epp:security_event`)
- **BCD Incidents** — indexes Broad Context Detection incidents with configurable risk level filtering (`sourcetype=withsecure:epp:bcd_incident`)
- **BCD Detections** — optionally auto-fetches granular process/file/network detections for each incident, or on-demand via a workflow action (`sourcetype=withsecure:epp:bcd_detection`)
- **Get BCD Details** workflow action — one-click button on any BCD incident event that returns detections directly in Splunk Search
- **CIM compliant** — field mappings for the Endpoint, Malware, and Intrusion Detection data models
- **Checkpoint-based polling** — KV Store checkpoints ensure no duplicate events across restarts

---

## Requirements

| Component | Version |
|---|---|
| Splunk Enterprise | ≥ 8.0 |
| Python | 3.x (bundled with Splunk) |
| WithSecure Elements | API access with OAuth2 credentials |

---

## Installation

1. Download or clone this repository
2. Copy the `ta-withsecure-elements/` folder into `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk

```bash
cp -r ta-withsecure-elements/ $SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/bin/splunk restart
```

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
| `interval` | Poll interval in seconds (default: 300) |
| `index` | Target Splunk index (default: main) |

#### BCD Incidents

| Parameter | Description |
|---|---|
| `client_id` | OAuth2 Client ID |
| `client_secret` | OAuth2 Client Secret |
| `org_id` | WithSecure Organization UUID |
| `risk_level_filter` | Comma-separated filter: `low,medium,high,critical` (blank = all) |
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

# High and critical BCD incidents
index=main sourcetype="withsecure:epp:bcd_incident" riskLevel=high OR riskLevel=critical

# Fetch detections for a specific incident on-demand
| fetchdetections incident_id="308b348b-92de-42a5-af12-2c1169e91827"

# MITRE ATT&CK techniques seen in detections
index=main sourcetype="withsecure:epp:bcd_detection"
| stats count by mitre_technique_id ac_mitre_tactic
| sort -count
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

Checkpoints are stored in the Splunk KV Store (`checkpoints` collection) and advance by 1ms after each successful poll to prevent duplicate ingestion.

---

## License

This project is licensed under the **Apache License 2.0** — see [LICENSE](ta-withsecure-elements/LICENSE) for details.

Free to use, modify, and distribute.
