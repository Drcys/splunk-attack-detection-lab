# Detection Searches (SPL)

Every search below was run against the lab data in Splunk with the time range set to
**All time**. Each is written to be read as a pipeline: find events, then transform,
then filter. MITRE ATT&CK technique IDs are given for each.

---

## Rule 1 — Failed-logon analysis (brute-force check)

**MITRE:** T1110 (Brute Force)

```spl
index=main source="wineventlog.log" EventCode=4625
| stats count by src_ip, user
| sort - count
```

**What it does:** finds all failed-logon events (Windows Event ID 4625), groups them
by source address and user, and sorts by count.

**Result:** 5 failed logons, each from a different source IP against a different user,
all with a count of 1. This is **not** a brute-force pattern (which would show one
source with a high count). Documented as a negative finding — a detection that
correctly returns nothing is as important as one that fires.

---

## Rule 2 — Scheduled-task persistence

**MITRE:** T1053.005 (Scheduled Task/Job)

```spl
index=main source="wineventlog.log" EventCode=4698
| table _time, host, user, TaskName, TaskContent
```

**What it does:** finds scheduled-task-creation events (Event ID 4698) and shows the
task name and the command it runs.

**Result:** one task, `SystemUpdateCheck`, created by `finuser01` at 14:07:41 — a name
chosen to look like a legitimate update.

---

## Rule 3 — Encoded / hidden PowerShell

**MITRE:** T1059.001 (PowerShell)

Surfaced by the `TaskContent` field in Rule 2:

```
powershell.exe -nop -w hidden -enc <base64>
```

**Why it is malicious:** `-nop` skips the PowerShell profile, `-w hidden` hides the
window from the user, and `-enc` runs a Base64-encoded command to conceal its intent.
A legitimate scheduled task has no reason to hide its window or encode its command.

---

## Rule 4 — Successful logon and privilege assignment

**MITRE:** T1078 (Valid Accounts)

```spl
index=main source="wineventlog.log" (EventCode=4624 OR EventCode=4672)
| table _time, host, user, src_ip, Logon_Type
| sort _time
```

**What it does:** finds successful logons (4624) and special-privilege assignments
(4672).

**Result:** `finuser01` logged on at 09:29:00 and was assigned elevated privileges at
09:29:01 — the account used throughout the rest of the incident.

---

## Rule 5 — Cross-source user activity timeline

**Purpose:** correlation across all three log sources.

```spl
index=main user=finuser01
| table _time, source, EventCode, dest_host, dest_ip, bytes_out
| sort _time
```

**What it does:** pulls every event for `finuser01` from Windows, Sysmon and proxy
logs into one time-ordered view. This is the pivot that turns isolated events into a
narrative: normal browsing until ~14:00, then repeated connections to an external
host, then the malicious scheduled task.

---

## Rule 6 — C2 beaconing (fixed-interval outbound)

**MITRE:** T1071 (Application Layer Protocol) / T1041 (Exfiltration Over C2 Channel)

```spl
index=main source="proxy.log" dest_host="cdn-static-updates.example.net"
| stats count, sum(bytes_out) as total_sent, min(_time) as first, max(_time) as last
        by src_ip, dest_host
```

**What it does:** counts connections to the suspicious host, sums the bytes sent, and
records the first and last connection times.

**Result:**
- `src_ip` = 10.14.3.51
- `count` = 39 connections
- window (`last - first`) = 2280 seconds = 38 minutes → **~58.5 seconds between
  connections**
- `total_sent` = 2,115,039 bytes (~2 MB)

A near-exact 60-second interval sustained for 38 minutes is automated beaconing, not
human browsing. The ~2 MB sent to an external host is consistent with data
exfiltration over the C2 channel.

**Tuning note:** in a real environment this rule would exclude known legitimate
periodic services (software-update agents, telemetry) before alerting, to avoid false
positives.
