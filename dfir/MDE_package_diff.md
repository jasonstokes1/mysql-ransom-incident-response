# MDE Package Comparison — corp-gng-940 (DFIR Host-Artifact Analysis)

*Companion to Incident Report IR-2026-0728-GNG940. Analysis date: 2026-08-04. Two Microsoft Defender for Endpoint (MDE) live-response packages from the same host compared; no incident type assumed going in — the evidence was allowed to indicate what, if anything, occurred.*

---

## 1. Baseline Determination

**Baseline = Pre_Breach package; comparison = Post_Breach package.**

Basis: collection-summary internal timestamps — pre collected **2026-07-27T21:09:02Z**, post **2026-07-28T21:05:29Z** (`Forensics Collection Summary.csv` in each). Corroborated by (a) distinct CollectedData GUID folders and (b) System Boot Times (`SystemInformation.txt`): pre boot 7/27 14:03, post boot 7/28 14:23. Same host CORP-GNG-940, same interface 10.1.0.112. The post package was captured ~45 min before VM isolation (21:50:51Z) and ~19 h after the database destruction, so it reflects fully-compromised host state — the strongest possible test for host-level attacker traces.

## 2. Summary Verdict

**Compromise indicators (host level): NO — high confidence.** Every persistence, account, service, task, and process surface is identical between packages apart from routine OS churn. The only real deltas are external RDP brute-force noise against port 3389 — all failed. No successful public logon, no new persistence, no privilege change, no log clearing. This independently corroborates the incident report's "host was never breached" finding from a second evidence source. (The actual DB destruction occurred *inside MySQL* and is not expected to surface in host artifacts — see Gaps.)

## 3. Table of Notable Deltas

| Category | Item | Change type | Benign vs Suspicious | Evidence |
|---|---|---|---|---|
| Autoruns / Run keys | HKLM + jstokes Run/RunOnce | UNCHANGED | benign | `Autoruns.txt` — identical OneDrive, MicrosoftEdgeAutoLaunch, SecurityHealth |
| Scheduled tasks | task-name set | CHANGED (−`\Setup\SetupCleanupTask`) | benign | `ScheduledTasks.csv`; self-removing OS task; all others only trigger/last-run churn |
| Services / drivers | service-name set | UNCHANGED | benign | `Services.csv`; only per-session suffix `_122408`→`_dcfb5` and PID reassignment |
| Processes | process-name set, mysqld present ×2 | UNCHANGED | benign | `Processes.csv`; only transient app PIDs differ |
| Local users | accounts, incl. Administrators group | UNCHANGED | benign | `LocalGroups.txt` — Administrators = {administraor, jstokes} in both; `administraor` created 7/26 (pre-baseline) |
| Listening ports | 3306, 3389, 33060, 135/139/445, 5040 | UNCHANGED | benign (but exposed) | `ActiveNetConnections.txt` — identical listeners on 0.0.0.0 |
| Network — inbound 3389 | brute-force source IPs | CHANGED | suspicious (failed) | pre: 80.94.95.83, 103.117.186.132; post: 51.161.196.231, 51.11.134.246, 80.66.83.43 |
| Security event log | 4625 failures 2,543 → 15,377 | CHANGED (growth) | suspicious (failed) | `Security.evtx`; **1102 log-cleared = 0** (not tampered) |
| Installed programs | program list | UNCHANGED | benign | `InstalledPrograms.csv` — identical |
| Hosts / DNS / ARP | resolver + neighbor state | UNCHANGED | benign | `DnsCache.txt` all Microsoft; `Arp.txt` only interface-index change |
| Firewall rules | host firewall log | UNCHANGED (both empty) | benign-collection | `FirewallExecutionLog.txt` — `pfirewall.log` not found in both (logging off) |
| Loaded modules / DLLs | — | N/A | — | not included in MDE live-response package set |
| Browser / credential artifacts | — | N/A | — | not present in either package |

## 4. Prioritized Compromise Indicators → ATT&CK

All indicators are **attempted, not successful**:

1. **T1110 Brute Force (Credential Access)** — post 4625 failures = 15,377 vs pre 2,543. 51.161.196.231 = 11,389 attempts against user `CORP`; 51.11.134.246 = 2,722 username spray. Source: `Security.evtx`. Matches the incident report's two named RDP IPs exactly (independent second-source confirmation).
2. **T1190 Exploit Public-Facing Application (surface)** — 3306 (mysqld) and 3389 (RDP) listening on 0.0.0.0 in both packages. Source: `ActiveNetConnections.txt`.
3. **No successful counterpart (explicit negative)** — the only external 4624 "successes" are `ANONYMOUS LOGON` Type-3 NTLM null sessions (46.105.132.55 @07:26Z, 35.205.92.76 @16:44Z) — negotiation artifacts, not access. All credentialed logons are jstokes from 10.0.8.x. No 4720 (account created), no 4732 (group add), no 7045 (new service), no 4698 (new task), no 1102 (log cleared).

## 5. Probable Incident Type

**From host artifacts alone: failed external RDP brute-force against an internet-exposed host — no host compromise.** The host layer shows no ransomware, persistence, or data-theft tooling. Letting the evidence speak: at the OS level the story is *attempted access, unsuccessful*. This does not reveal the true incident (MySQL data destruction), which occurred entirely within the database service and is invisible to these artifacts — correctly, the packages neither manufacture nor contradict it.

## 6. IOC List and Baseline Cross-Check

IOCs derived from the post package, then checked across both:

| Indicator | Type | In post? | In baseline (pre)? | Assessment / ATT&CK |
|---|---|---|---|---|
| 51.161.196.231 | IP | Yes (11,389× 4625) | No | RDP burst, user `gng`/`CORP` — T1110 |
| 51.11.134.246 | IP | Yes (2,722× 4625) | No | RDP spray, 81 usernames — T1110 |
| 80.66.83.43 | IP | Yes (1,228× 4625) | No | RDP brute, failed — T1110 |
| 80.94.95.83 | IP | No | Yes (1,724× 4625) | Baseline-era brute (earlier wave adjacent); failed |
| 103.117.186.132 | IP | No | Yes (814× 4625) | Baseline-era brute; failed |
| 46.105.132.55 / 35.205.92.76 | IP | Yes (ANON LOGON) | No | Null-session enum, not access |
| administraor | account | Yes (Admins) | Yes (Admins) | Present in both — pre-existing lab admin, NOT attacker-added |
| RECOVER_YOUR_DATA / 64.89.163.0/24 / BTC / onionmail | DB-layer IOCs | No | No | Confirms host artifacts carry no MySQL-attack trace |

Cross-check conclusion: every suspicious IOC is a **failed external brute-force source**; none corresponds to host access, and the post-package brute IPs are cleanly **absent from baseline** (distinct from the baseline's own earlier failed-brute IPs). No attacker-added account, service, task, or persistence exists in either package.

## 7. Gaps

- **MySQL-layer activity is invisible to host artifacts** (by design — primary evidence is MySQLAudit).
- **Host firewall log absent in both** (logging disabled, so rule-diff impossible).
- **Prefetch / MFT not in the MDE package set** — recently-created-executable check relied on processes/autoruns/services, all clean.
- **Only the Security channel is present** — no System/Application evtx to cross-check the 14:24Z mysqld restart or service-control events.
