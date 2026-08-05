# Methodology

How this case was investigated and verified, end to end.

## 1. Evidence sources

- **MySQL audit logs** (`MySQLAudit_CL`, split into Auth + Query CSV extracts) — the authoritative timeline anchor, timestamped in UTC.
- **Microsoft Defender Advanced Hunting** tables — `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`.
- **Defender Incident 154333 export** — the scheduled-alert record.
- **Two MDE live-response packages** — a pre-incident and post-incident host capture, diffed for the DFIR analysis.

## 2. Timezone discipline

MySQL logs are UTC (`Z`). The Defender portal renders UTC-5. Host-side rows in the report show portal-local **and** the UTC equivalent (+5h). The offset was verified at second-level precision: an inbound 3306 connection rendering `Jul 27 8:47:14 PM` portal-local matches the MySQL auth probe logged `2026-07-28T01:47:14Z`. All hunts are scoped to the incident window `2026-07-27T21:00:21Z .. 2026-07-28T21:50:51Z` — both for reproducibility and to exclude an unrelated earlier ransom wave (DATAID 2OB23) sharing the same workspace.

## 3. Hunt design — positive AND negative evidence

Findings are backed by two kinds of query:

- **Positive** — showing the attacker's actions (destruction sequence, ransom-note INSERTs, IOC sweep).
- **Negative** — showing what did *not* happen. These are just as load-bearing:
  - `DeviceLogonEvents` bucketed by source → **no PUBLIC row** = no successful internet logon.
  - `DeviceProcessEvents` for mysqld children → **zero rows** = no SQL-to-OS pivot.
  - mysqld egress → **single loopback row** = no exfiltration path.

A claim like "the host was never breached" is only as strong as the query that would have shown otherwise returning empty. Every negative claim has such a query, captured in the screenshots.

## 4. Verification loop

The report went through a v1 → v2 revision driven entirely by cross-checking draft claims against source data:

- **Re-plant cycles corrected.** v1 listed six ransom re-plant cycles; the auth and query logs evidenced only **two** attacker write-sessions. The four unsupported timestamps were **withdrawn** rather than left in.
- **Quiet-gap resolved.** A 12-event cluster around 14:00Z was drilled down and identified as the **mysqld service restarting at 14:24:07Z** — not attacker activity.
- **Gaps marked, not guessed.** The restart *mechanism* (service-recovery vs. manual) isn't in any provided log, so it's labelled "not determined from available logs" — an explicit gap, not an assumption.

Every change is recorded in the report's **Appendix — Changes from v1**.

## 5. DFIR host comparison

The two MDE packages were compared category by category (autoruns, services, tasks, processes, users/groups, network, event logs, installed programs, DNS/ARP/firewall) using an ADDED / REMOVED / CHANGED / UNCHANGED framework, with each delta classified benign vs. suspicious and mapped to ATT&CK. No incident type was assumed — the host evidence was allowed to speak for itself, and it independently corroborated the "host never breached" conclusion reached from the MySQL side.

## 6. Reproducing this

1. Load the queries in [`../evidence/hunts/hunts.kql`](../evidence/hunts/hunts.kql) into Defender Advanced Hunting against the same workspace.
2. Compare results to the captures in [`../evidence/screenshots/`](../evidence/screenshots/).
3. For the host diff, run the two MDE packages through the category comparison in [`../dfir/MDE_package_diff.md`](../dfir/MDE_package_diff.md).
