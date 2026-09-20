# 🛡️ Sentinel Honeypot — Live Attack Threat Intelligence

> A public-facing SSH honeypot that captured **18,648 real attacks in 24 hours**,
> analysed with **PySpark**, enriched with GeoIP, and visualised on a dashboard.

<!-- TODO: screenshot of the dashboard goes here, above the fold.
     This is the single most important thing a hiring manager sees. -->

## Results (one day of capture, 2026-07-20)

| | |
|---|---|
| **18,648** events captured | **386** unique attacker IPs |
| **2,216** login attempts | **3,775** commands run in the fake shell |
| **56** source countries | **1** live malware dropper caught |

**Captured a full kill chain:** reconnaissance (`uname`, CPU-arch probing) →
sandbox/honeypot detection → payload execution:

```bash
chmod +x ./.1988208513807693888/xinetd; nohup ./.1988208513807693888/xinetd &
```

Hidden `.`-directory (**T1564.001**), binary masquerading as the `xinetd` daemon
(**T1036**), detached for persistence (**T1059**). On a real host: game over. Here:
Cowrie faked every response, nothing executed, and the VM's egress lockdown would
have blocked the loader's C2 anyway.

**Two findings that contradict the obvious reading of the data:**
1. The 06:00 traffic spike was **~95% a single host's campaign burst** — not a
   daily rhythm, not a timezone signal.
2. The top "attacking country" was the **Netherlands (56% of all traffic)** — but
   the networks behind it are bulletproof VPS providers ("Unmanaged LTD",
   "TechTies Inc."), and **AS47890 appears under both the Netherlands and the US**.
   GeoIP tells you **where the rented server sits, not where the human is.**

## What it does
- Runs a [Cowrie](https://github.com/cowrie/cowrie) SSH honeypot on an isolated Azure VM
- Captures every login attempt, command, and credential real attackers try
- Ships logs to Azure Blob Storage
- Analyses them with **PySpark** (Databricks Free Edition)
- Aggregates a small **gold layer**, GeoIP-enriches attacker IPs
- Serves a Streamlit dashboard: world attack map, top networks, credentials, MITRE mapping

## Architecture
```
[Internet attackers]
        │  (SSH :22 → redirected to :2223)
        ▼
[Azure VM ── Cowrie honeypot]   ← isolated VNet, egress-restricted NSG
        │  cowrie.json logs                 admin SSH moved to :2222 (key-only)
        ▼
[ship_logs.py]  ──►  [Azure Blob Storage]
                              │
                              ▼
                     [PySpark / Databricks]   ← exploratory analysis
                              │
                              ▼
                     [build_gold.py] ──► gold CSVs ──► [enrich_geoip.py]
                              │
                              ▼
                     [Streamlit dashboard]  ──►  🌍 attack map
```

## Repo layout
| Path | What's inside |
|------|---------------|
| `infra/setup_cowrie.sh` | Stand up the VM + Cowrie (documented, repeatable) |
| `ingestion/ship_logs.py` | Read Cowrie JSON logs, upload to Blob Storage |
| `analysis/analyze.py` | PySpark analysis (with SQL equivalents alongside) |
| `analysis/build_gold.py` | Aggregate the raw log into the small "gold" tables |
| `analysis/enrich_geoip.py` | Attacker IPs → country / coordinates / ISP+ASN |
| `dashboard/app.py` | Streamlit dashboard (map, charts, tables) |
| `dashboard/data/` | The committed gold layer the dashboard reads |
| `docs/BUILD_LOG.md` | **The full build story** — every problem and fix |
| `docs/BUILD_LOG.el.md` | Greek version of the build log |
| `docs/SETUP.md` | Runbook: zero → first captured attack |

## Run the dashboard locally
```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on Linux/macOS)
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```
The dashboard reads only the committed gold layer, so it runs with **no Azure
resources and no honeypot required**.

To regenerate the data from a fresh capture:
```bash
python analysis/build_gold.py path/to/cowrie-YYYY-MM-DD.json
python analysis/enrich_geoip.py
```

## What I learned
<!-- Konstantinos: write this in your own words — recruiters read this section,
     and it should sound like you. Candidates worth covering:
     - Why NSG egress lockdown matters (a honeypot can become a liability)
     - Control plane vs data plane in Azure Storage RBAC (§12)
     - DataFrame API vs Spark SQL compile to the same Catalyst plan (§13)
     - Why GeoIP country ≠ attacker location (§14)
     - Batch API calls vs one-by-one (386 lookups: 9 min → seconds) -->

## Cost
Ran for ~1 week at **€3.95 total**. Torn down with a single
`az group delete` — everything lived in one dedicated resource group by design.
