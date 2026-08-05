# Incident Response Case Study: MySQL Database Ransom (`corp-gng-940`)

**SOC / DFIR investigation of a destructive database-ransom attack on an internet-exposed MySQL server** — reconstructed from Microsoft Defender KQL hunts, MySQL audit logs, and pre/post host forensic packages. Every finding is tied to evidence.

`Microsoft Defender` · `KQL / Advanced Hunting` · `DFIR` · `MITRE ATT&CK` · `Incident Reporting`

---

## What happened

An internet-exposed MySQL server was compromised **under 5 hours after exposure**. An automated actor logged in as `root` with **no password**, destroyed all databases, wiped the recovery logs, and left a Bitcoin ransom note. A parallel RDP brute-force campaign against the Windows host **never succeeded** — the host was never breached.

| Investigation question | Finding | Evidence |
|---|---|---|
| How did they get in? | Blank-password `root` on exposed port 3306 | Failed-auth probes → success, both sessions |
| Was data stolen? | **No** — the "we backed up your data" claim is a bluff | DB process had zero internet egress |
| Was the Windows host breached? | **No** | Zero successful public logons — confirmed by a second evidence source |
| What was the true scope? | **2** attacker sessions, not the 6 first logged | Corrected against source logs during review |

**Impact:** total database loss (Integrity + Availability critical); no exfiltration. **Recovery:** restore from backup — paying recovers nothing.

---

## Skills demonstrated

**Threat hunting** (KQL / Microsoft Defender Advanced Hunting) · **multi-source log correlation** (MySQL audit, DeviceNetworkEvents, DeviceLogonEvents, DeviceProcessEvents, Security.evtx) · **DFIR host-artifact forensics** (baseline vs. post-incident package diff) · **MITRE ATT&CK mapping** (T1485, T1486, T1110, T1190) · **incident reporting** for technical and management audiences · **evidentiary rigor** — unsupported claims withdrawn, gaps marked rather than guessed.

---

## Repository

| | |
|---|---|
| 📄 **[Full report (PDF)](report/corp-gng-940_MySQL-Ransom_IR-and-DFIR_2026-07-28.pdf)** | Incident report + DFIR host analysis |
| 🔍 **[DFIR host diff](dfir/MDE_package_diff.md)** | Pre/post package comparison, ATT&CK-mapped |
| ⌨️ **[KQL hunts](evidence/hunts/hunts.kql)** | Reproducible Defender queries |
| 🖼️ **[Screenshots](evidence/screenshots/)** | Query results, mapped to report sections |
| 📋 **[Methodology](docs/METHODOLOGY.md)** & **[IOCs](docs/IOCs.md)** | How the case was built + indicator list |

<sub>Lab / cyber-range exercise — no real victim; IOCs published as-is. Raw evidence (CSVs, host packages) excluded by design.</sub>
