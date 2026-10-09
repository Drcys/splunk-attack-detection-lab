# Sigma rules

Vendor-neutral versions of the lab's Windows detections, written in
[Sigma](https://github.com/SigmaHQ/sigma) so they can be converted to Splunk,
Elastic, Microsoft Sentinel or other SIEMs.

| File | ATT&CK | Lab rule |
|---|---|---|
| `scheduled_task_encoded_powershell.yml` | T1053.005, T1059.001 | Rules 2–3 |
| `failed_logon_burst.yml` | T1110 | Rule 1 |
| `logon_then_special_privileges.yml` | T1078 | Rule 4 |

Beaconing (Rule 6) is a statistical, timing-based detection and is kept in SPL
(`detections/savedsearches.conf`); it does not map cleanly to a single-event Sigma rule.

Convert to SPL with [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
pip install sigma-cli
sigma plugin install splunk
sigma convert -t splunk -p splunk_windows sigma/scheduled_task_encoded_powershell.yml
```
