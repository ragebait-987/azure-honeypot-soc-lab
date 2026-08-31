# Azure Cloud Honeypot & SIEM Threat Detection Lab

A deliberately exposed Windows VM in Microsoft Azure, wired into Microsoft Sentinel to capture, enrich, and visualize real brute-force login attempts from across the internet.

**[View the live project page →](https://ragebait-987.github.io/azure-honeypot-soc-lab/)**

---

## Overview

Exposing a VM to the open internet on purpose turns it into a sensor. Every scan, credential-stuffing attempt, and brute-force login becomes a labeled data point — the same signal a SOC analyst triages in production, but generated on demand. This project builds the full detection pipeline behind that signal: exposure, capture, forwarding, enrichment, and visualization.

## Architecture

| Stage | What happens |
|---|---|
| 1. Expose the target | Windows VM in Azure, inbound NSG rule opened, host firewall disabled |
| 2. Generate signal | Failed RDP logons captured locally as Windows Event ID 4625 |
| 3. Forward logs | Azure Monitor Agent + Data Collection Rule ship Security events to a Log Analytics Workspace |
| 4. Centralize in SIEM | Microsoft Sentinel connected to the workspace for query and detection |
| 5. Enrich with geo data | ~54,000-row GeoIP CSV imported as a Sentinel Watchlist, joined via KQL |
| 6. Visualize | Custom Sentinel Workbook renders attacker origins on a live map |

## Key query

```kql
// enrich failed RDP logons with attacker geolocation
let GeoIPDB_FULL = _GetWatchlist("geoip");
SecurityEvent
| where EventID == 4625
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
```

## Result

Live geographic breakdown of real brute-force attempts against the honeypot, including top sources by volume (Hong Kong, Netherlands, Norway, and others) — see the full attack map on the [project page](https://yourusername.github.io/azure-honeypot-soc-lab/).

## Skills demonstrated

- Cloud infrastructure (Azure VM provisioning, NSG configuration)
- SIEM operation (Microsoft Sentinel)
- KQL log analysis and enrichment
- Threat intelligence application (GeoIP watchlist)
- Dashboarding (Sentinel Workbooks, JSON configuration)
- Cost-aware cloud operations

## Tech stack

`Microsoft Azure` · `Microsoft Sentinel` · `Log Analytics Workspace` · `KQL` · `Azure Monitor Agent` · `Data Collection Rules` · `Network Security Groups`
