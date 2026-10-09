# Response Playbook — Suspected C2 Beaconing With Scheduled-Task Persistence

Written from the finuser01 investigation in this lab. It describes what an analyst
should do when Rule 6 (beaconing) and Rule 2 (scheduled task) fire on the same host.

## 1. Triage (first 15 minutes)

| Step | Action | Evidence to capture |
|---|---|---|
| 1 | Confirm the beacon: count, average interval, jitter, bytes out | Output of the beaconing search, exported as CSV |
| 2 | Identify host and user behind `src_ip` | Asset inventory / DHCP lease, 4624 logon record |
| 3 | Check for persistence on the same host in the beacon window | 4698 events, `TaskName`, `TaskContent` |
| 4 | Look up the destination: domain age, reputation, other internal hosts contacting it | Proxy logs for `dest_host` across all `src_ip` |

**Escalate** if the destination is external and unknown, the interval is regular, and a
hidden/encoded task exists on the same host. In this case all three were true.

## 2. Containment

- Isolate the host from the network (EDR network containment or switch port).
- Block the destination domain and IP at the proxy and firewall.
- Disable the user account's interactive logon and revoke active sessions.
- Do **not** reboot or delete the task yet; volatile evidence would be lost.

## 3. Evidence collection

- Export the scheduled task XML (`schtasks /query /tn <name> /xml`).
- Record the full encoded command and decode it in an isolated analysis environment.
- Capture memory and a triage image of the host before remediation.
- Preserve the relevant Splunk results with search, time range and timestamp, and hash
  the exported files.

## 4. Eradication and recovery

- Remove the scheduled task and any payload it references.
- Reset the user's credentials; review for reuse on other systems.
- Search all hosts for the same destination, the same task name, and the same beacon
  interval before declaring the incident closed.
- Return the host to service only after a clean re-scan.

## 5. Lessons learned

- **Detection gap:** the initial access vector was not visible in the available logs.
  Add email gateway and EDR process telemetry to the SIEM.
- **Tuning:** the beaconing rule must exclude known periodic services (update agents,
  telemetry) using an allow-list lookup, otherwise it will generate false positives.
- **Time to detect:** the beacon ran ~38 minutes before the scheduled task was created;
  an hourly beaconing alert would have caught it inside that window.
