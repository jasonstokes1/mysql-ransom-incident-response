# Indicators of Compromise — IR-2026-0728-GNG940

*Lab / cyber-range incident. Published as-is; no real victim. Defanged where noted.*

## Ransom-note IOCs (single consistent extortion message)

| Type | Indicator | Context |
|---|---|---|
| BTC address | `bc1qa83x6l2dlgkx7cc9rmrymscp5sa3ljepu42w2r` | Ransom payment address |
| Email | `ak+27vga@onionmail[.]org` | Attacker contact |
| URL | `hxxps://bit[.]ly/22mysql` | "More information" link |
| DATAID | `27VGA` | Victim/campaign ID |
| Malicious DB/table | `RECOVER_YOUR_DATA` | Ransom-note container created on the server |

## Network IOCs

| Type | Indicator | Context |
|---|---|---|
| Attacker IP | `64.89.163.176` | Root auth + full DB destruction (Session 1, 01:47–01:48Z) |
| Attacker IP | `64.89.163.169` | Root auth + final ransom re-plant (Session 2, 21:47Z) |
| Attacker subnet | `64.89.163.0/24` | Both attacker IPs; likely one operation |
| Probe IP | `35.233.78.91` | Single failed MySQL root auth (probe only) |
| RDP brute (spray) | `51.11.134.246` | 160 failed logons, 81-username spray — never succeeded |
| RDP brute (burst) | `51.161.196.231` | 40 failed logons in 4 s, user `gng` — never succeeded |
| RDP brute | `80.66.83.43` | 1,228 failed logons (host-package evidence) — never succeeded |

## Behavioral fingerprint

Each successful attacker session was immediately preceded by one or two
`Access denied for user 'root'@'<ip>' (using password: NO)` probes — a high-fidelity
precursor to a blank-password root login. Worth a dedicated detection analytic.

## ATT&CK techniques

| Tactic | Technique | Where |
|---|---|---|
| Credential Access (TA0006) | T1110 Brute Force | RDP (failed); MySQL root no-password (succeeded) |
| Initial Access | T1190 Exploit Public-Facing Application | Internet-exposed 3306/3389 |
| Impact | T1485 Data Destruction | DROP TABLE/DATABASE |
| Impact | T1486 Data Encrypted/Destroyed for Impact | Ransom note + destruction |
| Impact (anti-recovery) | — | RESET MASTER, PURGE BINARY LOGS, SHUTDOWN |
