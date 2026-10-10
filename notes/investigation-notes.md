
# Investigation Notes — Lab 21: MITRE ATT&CK-Based Threat Hunting

## 1. Investigation Overview

**Investigation type:** Endpoint Threat Hunting  
**Platform:** Elastic Security  
**Endpoint:** DESKTOP-9MMM37V  
**Operating system:** Windows 11  
**Elastic Agent:** 9.5.4  
**Query language:** ES|QL  
**Investigation date:** October 10, 2026

### Objective

Investigate whether the available Windows endpoint telemetry contains evidence relevant to suspicious process execution, scheduled-task activity, or Windows event-log clearing.

The investigation follows a hypothesis-driven approach. Each hypothesis is tested against collected telemetry, and conclusions are limited to the evidence available in Discover.

## 2. Initial Telemetry Validation

The Elastic Agent status command confirmed that Fleet was healthy and connected, the agent was running, and the configured inputs and outputs were healthy.

Fresh events were subsequently visible in Kibana Discover.

This established that endpoint telemetry was reaching Elastic. It did not guarantee that every Windows audit event or operational channel was enabled and collected.

### Event Inventory Query

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY
    event.dataset,
    event.code
| SORT event_count DESC
| LIMIT 50
```

### Observations

- Approximately 1.6K documents were processed.
- The query returned 15 dataset/event-code combinations.
- Visible dataset categories included `elastic_agent.filebeat`, `elastic_agent`, and `elastic_agent.metricbeat`.
- The inventory provided an initial view of the available telemetry.

The visible dataset counts represent the rows shown in the screenshot and are not a complete breakdown of every Windows event source.

## 3. Hunt One — Process and PowerShell Activity

### Hypothesis

PowerShell or another process execution mechanism may have been used in a way that warrants investigation.

### Query

```esql
FROM logs-*
| WHERE event.code IN ("4688", "4103", "4104", "1")
| SORT @timestamp DESC
| LIMIT 100
```

### Observations

- The query processed 101 documents and returned 100 results.
- Visible records included `windows.sysmon_operational` with event code `1`.
- Sysmon Event ID 1 represents process creation.
- The results establish process-creation telemetry visibility.

The screenshot does not establish that every requested event code was present. In particular, the presence of Sysmon Event ID 1 does not confirm that Security Event ID 4688 or PowerShell logging events 4103 and 4104 were collected.

### Broader Process and Persistence Query

```esql
FROM logs-*
| WHERE event.code IN (
    "4688", "4103", "4104", "1",
    "4698", "4702", "1102", "104"
)
| KEEP @timestamp, host.name, user.name,
       event.dataset, event.code, event.action,
       message, process.name, process.command_line
| SORT @timestamp ASC
| LIMIT 200
```

### Observations

- The query processed 203 documents and returned 200 results.
- Visible records included `windows.sysmon_operational` and event code `1`.
- The results show that process-creation telemetry was available during the selected investigation period.
- A combined query is useful for building a preliminary timeline, but individual event details must be examined before linking events into an attack chain.

### Assessment

**Result:** Process-creation telemetry confirmed; malicious PowerShell activity not established by the available screenshot.

A complete investigation should inspect the process image, command line, parent process, user, host, and timestamp where those fields are available.

## 4. Hunt Two — Scheduled-Task Activity

### Hypothesis

A scheduled task may have been created or modified to enable unexpected recurring execution or persistence.

### Query

```esql
FROM logs-*
| WHERE event.code IN ("4698", "4702")
| SORT @timestamp DESC
| LIMIT 100
```

### Observations

- The query processed one document and returned one result.
- The event summary displayed a dataset beginning with `system.securit...`, consistent with a likely `system.security` dataset, although the screenshot truncates the complete value.
- The visible result did not expose the full `event.code` or message in the table.

### Assessment

**Result:** One matching document returned; exact event identity and significance require validation.

The result should not be described as confirmed scheduled-task creation or modification until its complete event code and message are inspected.

### Follow-up Query

```esql
FROM logs-*
| WHERE event.code IN ("4698", "4702")
| KEEP @timestamp, host.name, user.name,
       event.dataset, event.code, event.action,
       message, winlog.channel, winlog.provider_name
| SORT @timestamp DESC
| LIMIT 20
```

If a field is unavailable in the selected schema, remove it and rerun the query. The essential fields to verify are the timestamp, event code, dataset, channel, and message.

## 5. Hunt Three — Windows Event-Log Clearing

### Hypothesis

A Windows event log may have been cleared, potentially removing evidence of earlier activity.

### Query

```esql
FROM logs-*
| WHERE event.code IN ("1102", "104")
| SORT @timestamp DESC
```

### Observations

- Discover reported zero documents processed.
- No matching records were returned in the selected data view and time range.
- The screenshot showed a Last 1 hour time range for this query.

### Assessment

**Result:** No matching events found in the examined data and time range.

This result does not prove that log clearing never occurred. Possible explanations include:

- No such event occurred during the selected period.
- The event occurred outside the selected time range.
- The relevant Security or System event channel was not collected.
- The event was not generated because the relevant operation did not occur.
- The selected data view or query does not cover the relevant event source.

### Follow-up

Expand the time range, inspect the Windows Security and System event datasets, and verify whether events 1102 and 104 are being collected before drawing a conclusion.

## 6. MITRE ATT&CK Mapping

| Behavior | ATT&CK technique | Evidence status |
|---|---|---|
| PowerShell execution | T1059.001 — PowerShell | Investigated; malicious execution not established |
| Scheduled-task activity | T1053 — Scheduled Task/Job | One matching document; exact event requires inspection |
| Windows event-log clearing | T1070.001 — Clear Windows Event Logs | No matching events in the examined query and time range |

These are investigation mappings, not claims that an attacker performed the techniques.

## 7. Overall Findings

### Confirmed

- Elastic Agent was healthy and connected to Fleet.
- Fresh endpoint telemetry was arriving in Discover.
- The event inventory query returned multiple dataset/event-code combinations.
- Sysmon process-creation records were visible.
- The scheduled-task query returned one document requiring further inspection.
- The log-clearing query returned no matching documents in the examined time range.

### Not Established

- That PowerShell was used maliciously.
- That the scheduled-task result represents malicious persistence.
- That Windows event logs were cleared.
- That the endpoint was compromised.

## 8. Conclusion

The investigation confirmed that process-creation telemetry was available and demonstrated how to use ES|QL to test threat-hunting hypotheses. The scheduled-task result requires further event-level inspection, while the absence of log-clearing events remains a telemetry-coverage question rather than evidence that the behavior never occurred.

The investigation follows an evidence-first approach: distinguish observed events from interpretations, document limitations, and avoid claiming malicious activity without corroboration.

