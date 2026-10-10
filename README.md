
# Elastic Lab 21 — MITRE ATT&CK-Based Threat Hunting

## Overview

This lab demonstrates a hypothesis-driven threat-hunting workflow using Elastic Security, Elastic Agent 9.5.4, Windows 11 telemetry, and ES|QL. The investigation focuses on identifying potentially suspicious PowerShell execution, scheduled-task activity, and Windows event-log clearing while validating which evidence is actually available in the collected telemetry.

The objective is not to label every unusual event as malicious. Instead, the investigation emphasizes evidence validation, event visibility, behavioral context, MITRE ATT&CK mapping, and transparent documentation of investigative limitations.

## Environment

- **Endpoint:** Windows 11
- **Endpoint hostname:** DESKTOP-9MMM37V
- **SIEM and analytics:** Elastic Security / Kibana Discover
- **Endpoint monitoring:** Elastic Agent 9.5.4
- **Agent management:** Elastic Cloud Fleet
- **Query language:** ES|QL
- **Telemetry sources observed:** Windows Sysmon operational logs, Windows security-related data, and Elastic Agent monitoring datasets
- **Investigation window:** October 10, 2026, with screenshots showing a Last 1 hour time range for relevant queries

## Objectives

- Develop testable threat-hunting hypotheses.
- Inventory available event datasets and event IDs before investigating.
- Search endpoint telemetry using ES|QL.
- Investigate process creation and scheduled-task-related events.
- Check visibility of Windows event-log clearing indicators.
- Identify collection and query limitations.
- Map supported behaviors to MITRE ATT&CK.
- Document observations without treating missing telemetry as proof of benign activity.

## Investigation Scope

The investigation examined three primary areas:

1. **PowerShell and process execution:** Searching event IDs 4688, 4103, 4104, and 1 to identify available process and script-related telemetry.
2. **Scheduled-task activity:** Searching event IDs 4698 and 4702 for scheduled-task creation or modification events.
3. **Event-log clearing:** Searching event IDs 1102 and 104 for potential evidence of Windows event-log clearing.

The investigation also included a broader inventory of event datasets and event codes to establish telemetry coverage.

## Key Findings

- Elastic Agent was healthy and connected to Fleet, and fresh endpoint events were arriving in Discover.
- An event inventory query processed approximately 1.6K documents and returned 15 dataset/event-code combinations.
- The visible inventory results included `elastic_agent.filebeat`, `elastic_agent`, and `elastic_agent.metricbeat`.
- The process-related hunt returned 100 results, with visible events from `windows.sysmon_operational` and event code `1`, representing Sysmon process creation.
- A broader combined hunt returned 200 results from 203 processed documents.
- The scheduled-task query for event IDs 4698 and 4702 returned one document. The available screenshot does not show enough of the event details to conclusively identify which event code matched or establish its full meaning.
- The event-log clearing query for event IDs 1102 and 104 returned zero documents in the selected data view and time range.

## MITRE ATT&CK Relevance

| Behavior under investigation | ATT&CK reference |
|---|---|
| PowerShell execution | T1059.001 — PowerShell |
| Scheduled-task-based persistence or execution | T1053 — Scheduled Task/Job |
| Clearing Windows event logs | T1070.001 — Clear Windows Event Logs |

These mappings describe behaviors under investigation, not confirmed attacker activity. A technique should only be reported as observed when the available evidence supports that conclusion.

## Evidence and Limitations

The investigation confirmed that process telemetry was available and that the relevant ES|QL searches executed successfully. However, query results alone do not establish that malicious activity occurred.

The single scheduled-task query result requires inspection of its complete `event.code`, `event.dataset`, and message fields. The absence of event IDs 1102 and 104 in the selected time range does not establish that log clearing never occurred.

The availability of Security Event IDs 4688, 4698, 4702, 1102, and PowerShell logging events depends on Windows audit settings, event-channel collection, and integration configuration.


## Conclusion

This lab demonstrates how a SOC analyst can conduct a structured threat hunt using available endpoint telemetry and ES|QL. The investigation established visibility into Sysmon process-creation events and identified areas requiring further validation, particularly scheduled-task event details and Windows event-log clearing visibility. The final assessment remains evidence-driven: confirmed observations are separated from hypotheses, and missing events are documented as visibility limitations rather than proof that an activity did not occur.

**Environment:** Controlled personal SOC lab. Findings are limited to the telemetry and time ranges examined.
