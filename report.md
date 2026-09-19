# Investigation Report — Windows Host Compromise via Scheduled-Task C2

**Analyst:** Basem Zaher Al-Ammari
**Platform:** Splunk Enterprise
**Data:** synthetic SOC lab data set (Windows Event Logs, Sysmon, web proxy)
**Date of activity:** 3 September 2026

---

## 1. Executive summary

Analysis of three correlated log sources identified a compromised Windows host,
`10.14.3.51`, associated with the user account `finuser01`. Beginning at 14:02 the
host established a command-and-control (C2) channel to an external server,
`cdn-static-updates.example.net` (`198.51.100.44`), beaconing at a fixed ~60-second
interval. At 14:07 a scheduled task named `SystemUpdateCheck` was created to run
hidden, Base64-encoded PowerShell, establishing persistence. Approximately 2 MB of
data was sent to the external host over the C2 channel, consistent with data
exfiltration. The disguised naming of both the domain and the task indicates a
deliberate attempt to blend in with legitimate update traffic.

## 2. Environment and data

Three log files were ingested into Splunk under the `main` index:

| Source | Contents |
|---|---|
| `wineventlog.log` | Windows security events (logons, privileges, scheduled tasks) |
| `sysmon.log` | Sysmon endpoint telemetry |
| `proxy.log` | Web-proxy connection records (source, destination, bytes) |

796 events total. All identifiers are synthetic; external addresses fall within the
RFC 5737 documentation ranges.

## 3. Timeline of events (3 September 2026)

| Time | Event | Source | ATT&CK |
|---|---|---|---|
| 09:29:00 | Successful logon by `finuser01` | wineventlog (4624) | T1078 |
| 09:29:01 | Elevated privileges assigned | wineventlog (4672) | T1078 |
| 10:00–13:30 | Normal web browsing (Microsoft, Office 365, LinkedIn) | proxy | — |
| 14:02:19 | First connection to `cdn-static-updates.example.net` | proxy | T1071 |
| 14:02–14:40 | 39 connections at ~60s intervals, ~2 MB sent | proxy | T1071 / T1041 |
| 14:07:41 | Scheduled task `SystemUpdateCheck` created | wineventlog (4698) | T1053.005 |
| 14:07:41 | Task runs `powershell.exe -nop -w hidden -enc` | wineventlog | T1059.001 |

## 4. Findings

### 4.1 Command-and-control beaconing (Confirmed)

**Observation:** host `10.14.3.51` made 39 outbound connections to
`cdn-static-updates.example.net` between 14:02:19 and 14:40, a span of 2280 seconds —
an average of 58.5 seconds between connections.

**Interpretation:** a near-constant 60-second interval sustained over 38 minutes is
characteristic of automated C2 beaconing. Human browsing does not produce a fixed
per-minute rhythm.

**Confidence:** high. The regularity of the interval and the disguised host name
together admit no plausible benign explanation.

### 4.2 Scheduled-task persistence with encoded PowerShell (Confirmed)

**Observation:** a scheduled task `SystemUpdateCheck` was created by `finuser01` at
14:07:41 with the command `powershell.exe -nop -w hidden -enc <base64>`.

**Interpretation:** the flags conceal execution (`-nop`, `-w hidden`) and hide intent
(`-enc`). The benign-looking task name is a masquerade. This is persistence combined
with defence evasion.

**Confidence:** high.

### 4.3 Data exfiltration (Probable)

**Observation:** ~2,115,039 bytes were sent from the host to the external C2 server
over the beacon window.

**Interpretation:** 2 MB of outbound data to an external host over a covert channel is
consistent with exfiltration.

**Confidence:** probable — the volume and destination support exfiltration, though the
encrypted/opaque proxy records do not reveal the content.

### 4.4 No brute force detected (Negative finding)

**Observation:** only 5 failed logons were present, each from a distinct source and
user, with no source accumulating repeated failures.

**Interpretation:** there is no evidence of a brute-force or password-spray attack in
this data. The initial access vector is not established from these logs.

**Confidence:** high that brute force did not occur; the true initial vector remains
undetermined.

## 5. Attack narrative

The account `finuser01` logged on normally in the morning and behaved as an ordinary
user for several hours. At 14:02 the host began beaconing to an external server
disguised as a content-delivery / update service. Five minutes into the beaconing, a
scheduled task was created to run hidden, encoded PowerShell under an
update-themed name, ensuring the foothold would survive reboot. Data was steadily
sent to the external host throughout the window. How the account first came under
attacker control is not visible in the available logs.

## 6. Recommendations

- Isolate host `10.14.3.51` from the network.
- Block `cdn-static-updates.example.net` / `198.51.100.44` at the perimeter.
- Delete the `SystemUpdateCheck` scheduled task and decode the `-enc` payload for
  analysis.
- Reset credentials for `finuser01` and review its recent activity.
- Hunt for the same beacon interval and disguised domains on other hosts.
- Determine the initial access vector, which is not covered by these logs.

## 7. Limitations

- Synthetic lab data, not a live environment.
- The initial access vector is not present in the available logs.
- Proxy records show volume and destination but not payload content, so exfiltration
  is inferred rather than proven.
- Detection thresholds are tuned to this data set and would need environmental
  baselining before production use.
