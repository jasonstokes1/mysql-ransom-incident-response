# Sentinel Workbook — Inbound Attack Origins (Geo Map)

A Microsoft Sentinel Workbook that plots the geographic origin of **external failed remote
logons** against the cyber-range environment (public RDP / network brute force) on a world
map, sized and colored by volume. It's the internet-wide background of credential-attack
traffic the range absorbs — the same class of activity that, against host `corp-gng-940`,
produced incident **IR-2026-0728-GNG940** (see the main report).

Built on `DeviceLogonEvents` and enriched with the native `geo_info_from_ip_address()`
function (MaxMind GeoLite2). Part of the same LAW-Cyber-Range lab as the main incident.

![Inbound Attack Origins geo map](attack-geo-map.png)

## Import

1. Microsoft Sentinel / Defender → **Workbooks** → **+ Add workbook**.
2. **Edit** → **Advanced Editor** (`</>` icon).
3. Delete the sample JSON, paste in [`attack-geo-map-workbook.json`](attack-geo-map-workbook.json), **Apply**.
4. Set the **Time range** pill to **30 days**.
5. **Save** — e.g. *Attack Source Geo Map — corp-gng-940*.

> Update the workspace resource ID (`crossComponentResources` / `context.ownerId`) to point at your own Log Analytics workspace.

## Files

| File | Purpose |
|------|---------|
| `attack-geo-map-workbook.json` | The importable workbook (map + detail table) |
| `attack-geo-map.png` | Screenshot of the rendered map |
