
# Troubleshooting Notes — Lab 21: Elastic Threat Hunting

## 1. Purpose

This document records the telemetry and query-validation issues encountered during the MITRE ATT&CK-based threat hunt.

The main challenge was not Elastic Agent connectivity. Fleet and the agent were healthy, and fresh endpoint events were arriving in Discover. The challenge was determining which event types were actually available and interpreting empty or incomplete query results correctly.

## 2. Environment Health

The following command confirmed the agent status:

```powershell
& "C:\Program Files\Elastic\Agent\elastic-agent.exe" status --output full
```

Observed status:

- Fleet: HEALTHY / Connected
- Elastic Agent: HEALTHY / Running
- System metrics: HEALTHY
- Windows metrics: HEALTHY
- Winlog inputs and outputs: HEALTHY

Fresh events were confirmed in Discover.

**Interpretation:** Agent health and event ingestion were confirmed, but these checks did not guarantee that all Windows audit events were generated or collected.

## 3. Issue — No Results for Event IDs 1102 and 104

### Observed behavior

The following query returned zero documents in the selected time range:

```esql
FROM logs-*
| WHERE event.code IN ("1102", "104")
| SORT @timestamp DESC
```

### Meaning

The query did not find matching records in the selected data view and time range. It does not establish that Windows event-log clearing never occurred.

### Troubleshooting procedure

1. Expand the time range in Discover.
2. Confirm that the selected data view includes the Windows Security and System event datasets.
3. Inspect the available `event.dataset` and `event.code` values.
4. Verify that the relevant Windows event channels are collected.
5. Confirm that no integration filters exclude the required event IDs.
6. Repeat the query after confirming collection and time-range coverage.

### Relevant event IDs

- `1102`: Security audit log cleared.
- `104`: An event log was cleared; interpret it alongside the provider and log context.

### Important distinction

Do not enable additional audit settings merely because the query is empty. First determine whether the event should have been generated, whether the relevant channel is collected, and whether the event falls inside the search window.

## 4. Issue — Scheduled-Task Query Returned One Document

### Query

```esql
FROM logs-*
| WHERE event.code IN ("4698", "4702")
| SORT @timestamp DESC
| LIMIT 100
```

### Observed behavior

The query returned one document. The displayed event summary was truncated and did not expose the complete event code or message.

### Troubleshooting procedure

1. Open the result in Discover.
2. Expand the document's full field details.
3. Inspect `event.code`, `event.dataset`, `event.action`, `@timestamp`, and `message`.
4. Inspect `winlog.channel` and `winlog.provider_name` if available.
5. Verify whether the event is actually 4698 or 4702.
6. Correlate the timestamp with task creation or modification activity.

### Relevant event IDs

- `4698`: A scheduled task was created.
- `4702`: A scheduled task was updated.

**Do not classify the single document as confirmed persistence until the actual event and its context have been verified.**

## 5. Issue — Process Query Returned Results, but Not Every Event Type Was Verified

### Query

```esql
FROM logs-*
| WHERE event.code IN ("4688", "4103", "4104", "1")
| SORT @timestamp DESC
| LIMIT 100
```

### Observed behavior

The query processed 101 documents and returned 100 results. Visible results included `windows.sysmon_operational` and event code `1`.

### Interpretation

Sysmon process-creation telemetry was available. The screenshot does not prove that the other requested event IDs were present.

### Troubleshooting procedure

1. Inspect the complete event document.
2. Verify the dataset and event code for each relevant result.
3. Check for process image and command-line fields.
4. Determine whether Security Event ID 4688 is collected separately.
5. Determine whether PowerShell operational events 4103 and 4104 are collected.
6. Verify audit and logging configuration only if the required telemetry is missing.

### Event reference

- Sysmon Event ID `1`: Process creation.
- Security Event ID `4688`: Process creation, if process-creation auditing is enabled.
- PowerShell Event ID `4103`: Module logging, when configured and collected.
- PowerShell Event ID `4104`: Script block logging, when configured and collected.

These sources are not interchangeable. Seeing Sysmon Event ID 1 does not prove that Security 4688 or PowerShell 4104 is available.

## 6. General Telemetry Validation

### Inventory query

```esql
FROM logs-*
| STATS event_count = COUNT(*) BY
    event.dataset,
    event.code
| SORT event_count DESC
| LIMIT 50
```

This query helps identify event types present in the selected data view.

### Check the data view

If a query returns no documents:

- Confirm the data view pattern.
- Confirm the selected time range.
- Remove restrictive filters temporarily.
- Inspect the complete field values in Discover.
- Check whether the expected event source is collected.

### Check Windows event generation

For relevant Security audit events, inspect the audit policy and Windows Event Viewer. For PowerShell operational events, inspect the corresponding PowerShell operational channel. For Sysmon, inspect the Sysmon operational channel.

A healthy Elastic Agent cannot forward an event that Windows never generated or that the configured integration does not collect.

## 7. Windows Audit Policy Considerations

For scheduled-task creation auditing, inspect the current audit policy from elevated PowerShell:

```powershell
auditpol /get /subcategory:"Other Object Access Events"
```

If Success auditing is disabled and the host is authorized for configuration changes, it may be necessary to enable it:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```

Then verify the setting:

```powershell
auditpol /get /subcategory:"Other Object Access Events"
```

Use this change only when appropriate for the lab or system owner. Organizational policy may override local settings. Enabling an audit policy affects event generation; it does not automatically configure Elastic to collect the events.

## 8. Controlled Validation

If authorized, create a harmless scheduled task in the lab and check whether Windows generates Event ID 4698.

Inspect the Security log:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4698
} -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName, Message |
Format-List
```

Interpret the result:

- If Windows has the event but Discover does not, investigate Elastic collection, filters, data views, and ingestion.
- If Windows has no event, inspect the audit policy, task-creation outcome, and Security log.
- If the event is present in Discover, inspect the full event before concluding that the hunt found suspicious behavior.

Remove any test task created for this validation when it is no longer needed.

## 9. Troubleshooting Decision Table

| Observation | Next action |
|---|---|
| Fleet or agent unhealthy | Resolve agent connectivity first |
| Agent healthy, fresh events present | Validate event-specific telemetry |
| Windows event exists, Elastic event missing | Inspect integration, channel, filters, and ingestion |
| Windows event does not exist | Inspect event generation, audit policy, and time range |
| Query returns one truncated event | Open the document and inspect complete fields |
| Query returns zero log-clearing events | Expand time range and validate channel coverage |
| Sysmon Event ID 1 is present | Use process telemetry; do not assume other audit events exist |

## 10. Conclusion

The main lesson from Lab 21 is that empty query results and incomplete event summaries require validation, not assumptions. Confirm event generation, collection, time range, and field content before making a security conclusion. Preserve the distinction between a telemetry gap and evidence that an activity did not occur.
