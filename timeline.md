
# Timeline — Lab 21: MITRE ATT&CK-Based Threat Hunting

## Investigation Context

**Date:** October 10, 2026  
**Endpoint:** DESKTOP-9MMM37V  
**Platform:** Elastic Security / Kibana Discover  
**Agent version:** 9.5.4  
**Time zone:** The screenshots display Kibana timestamps; local Windows time and Kibana display time may differ.

This timeline records investigation actions and observed results. It does not represent a confirmed attacker timeline.

## Investigation Timeline

| Stage | Activity | Observed result | Assessment |
|---|---|---|---|
| 1 | Verified Elastic Agent status | Fleet connected; agent and configured components healthy | Endpoint telemetry collection was operational at the agent level |
| 2 | Confirmed fresh events in Discover | New endpoint events visible | Ingestion was confirmed for the observed data |
| 3 | Inventoried event datasets and codes | Approximately 1.6K documents processed; 15 dataset/code combinations returned | Established an initial telemetry inventory |
| 4 | Searched process and PowerShell-related event IDs | 101 documents processed; 100 results returned | Process-related telemetry was available |
| 5 | Inspected visible process records | `windows.sysmon_operational`, event code `1` appeared in results | Sysmon process-creation telemetry was confirmed |
| 6 | Ran a combined process, scheduled-task, and log-clearing hunt | 203 documents processed; 200 results returned | Produced records for further event-level inspection |
| 7 | Searched scheduled-task event IDs 4698 and 4702 | One matching document returned | Exact event code and message require validation |
| 8 | Searched log-clearing event IDs 1102 and 104 | Zero documents processed in the displayed query | No matching events in the selected data view and time range |
| 9 | Documented findings and limitations | Separated observed telemetry from unconfirmed hypotheses | Prevented unsupported conclusions about compromise |

## Timestamped Evidence

The following timestamps were visible in the supplied screenshots:

| Displayed timestamp | Source or context | Evidence |
|---|---|---|
| Oct 10, 2026, 06:14:56.063 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:14:56.386 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:14:56.395 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:47:48.061 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:47:51.073 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:47:53.251 | `windows.sysmon_operational` | Sysmon Event ID 1 — process creation |
| Oct 10, 2026, 06:50:18.627 | Scheduled-task query result | One document matched the query for event IDs 4698 and 4702; complete event details were not visible |

**Timestamp note:** These are the timestamps as displayed in the screenshots. Confirm Kibana's configured time zone before comparing them with timestamps from Windows Event Viewer or PowerShell.

## Event Visibility Summary

### Process creation

Sysmon Event ID 1 was visible in the results. This confirms that process-creation records were available in the examined telemetry.

### Scheduled-task activity

One document matched the event-code filter for 4698 and 4702. The complete event details were not shown, so the specific operation remains unverified.

### Event-log clearing

No documents matched event IDs 1102 and 104 in the selected time range. This is a negative search result, not proof that logs were never cleared.

## Timeline Limitations

- The screenshots do not contain every returned event.
- Several event summaries were truncated.
- The scheduled-task result requires full event inspection.
- The log-clearing query used a limited time range.
- The observed process events have not been established as malicious.
- No confirmed attack sequence or compromise was demonstrated by the available evidence.

## Final Assessment

The investigation confirmed that Elastic was receiving endpoint telemetry and that Sysmon process-creation events were visible. Scheduled-task activity requires additional validation, while log-clearing activity was not observed in the selected data and time range.

The timeline documents investigative checkpoints and telemetry observations, not a confirmed sequence of attacker actions.
