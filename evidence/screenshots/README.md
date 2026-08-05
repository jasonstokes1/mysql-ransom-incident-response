# Evidence Screenshots

Each screenshot is a Microsoft Defender Advanced Hunting result (or MySQL Workbench view)
captured during the investigation. The query for each is in [`../hunts/hunts.kql`](../hunts/hunts.kql).

Upload these 10 files into this folder:

| Screenshot file | Report § | What it proves |
|------|----------|----------------|
| <img width="2240" height="672" alt="scope confirmation" src="https://github.com/user-attachments/assets/148bc4fb-faf6-4494-84d0-bd74cde7a5a2" />| §2 | Activity clusters at setup / destruction / detection; excludes the unrelated Jul-23 wave |
| <img width="2240" height="734" alt="confirm no exfil" src="https://github.com/user-attachments/assets/dae62153-0a39-45d0-a75a-85c69e95015f" />| §3 | All outbound traffic is Microsoft/Azure telemetry — no attacker infrastructure |
| <img width="2240" height="557" alt=" mysqld egress hunt expected-single loopback row" src="https://github.com/user-attachments/assets/995f1aa8-debc-4183-b1c9-e8db77e0af28" />| §3 | mysqld's only outbound connection was loopback → no exfil path (the "backed up by us" bluff) |
| <img width="2240" height="712" alt="IOC sweep, scoped to incident window" src="https://github.com/user-attachments/assets/6d285727-2daf-4d58-9bf0-64343c14e75f" />| §4 | All four note-based IOCs present in one consistent extortion message |
| <img width="2240" height="1132" alt="MySQL Workbench ransom-note screenshot" src="https://github.com/user-attachments/assets/de47a285-2c1f-4920-9b98-3d09be067b9f" />| §4 | Recovered ransom note: BTC address, bit.ly link, onionmail contact, DATAID |
| <img width="2240" height="712" alt="destruction sequence, scoped to incident window" src="https://github.com/user-attachments/assets/c2ae24ab-3cca-4a0a-80ef-8276fb5510a8" />| §5 | DROP TABLE → DROP DATABASE → RESET MASTER → PURGE BINARY LOGS → SHUTDOWN, timestamped |
| <img width="2240" height="597" alt="logon-source hunt " src="https://github.com/user-attachments/assets/7bfb1167-6891-4768-9402-9ba34efcf6fb" />| §6 | No PUBLIC logon row — affirmative proof the host was never breached |
| <img width="2240" height="538" alt="mysqld child-process hunt expected-zero rows" src="https://github.com/user-attachments/assets/5044a3e9-6922-46c1-ba38-b3f78ab15a81" />| §6 | Zero rows — no SQL-to-OS pivot (no webshell/UDF/command execution) |
| <img width="2240" height="730" alt="scoped to incident window" src="https://github.com/user-attachments/assets/3c63c7d4-e41f-41bf-bab4-be981baf9d5a" />| §8 | Ransom-note INSERTs across both attacker sessions (0.0134 → 0.0133 BTC drift) |
| <img width="2240" height="729" alt="1400Z bin drill-down-expected- monitoring SHOW queries only" src="https://github.com/user-attachments/assets/d6cd6d0e-a6a8-4b60-979f-a85fea887208" />| §6 | Identifies the 14:24:07Z mysqld startup log — resolves the post-SHUTDOWN restart timing |

**Negative-evidence screenshots** — `logon-source_hunt_`, `mysqld_child-process_hunt`, and the
`1400Z_bin` drill-down — are as important as the positive ones: the *absence* of a PUBLIC logon,
of mysqld child processes, and of attacker activity in the quiet-gap bin is what substantiates
the report's "what did NOT happen" findings.
