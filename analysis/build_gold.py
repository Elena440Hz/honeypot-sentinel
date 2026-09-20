"""
build_gold.py
-------------
The dashboard's ETL. Read the RAW honeypot log ONCE, boil it down to a
handful of tiny "gold" tables that the dashboard reads. This is the
medallion pattern (bronze/raw -> gold/serving), right-sized for 10 MB
with pandas. At production scale this same step runs in Spark -> Blob.

Run:
    python analysis/build_gold.py
    python analysis/build_gold.py "C:\\path\\to\\cowrie-YYYY-MM-DD.json"

Output: small CSVs + a stats JSON in dashboard/data/, which app.py reads.
The raw log stays OUT of the repo; only the small gold files get committed.
"""

import json
import sys
from pathlib import Path

import pandas as pd

# --- Paths ------------------------------------------------------------
REPO = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = Path.home() / "Downloads" / "cowrie-2026-07-20.json"
DATA_DIR = REPO / "dashboard" / "data"


def load_raw(path):
    """Cowrie writes JSON-lines: one JSON object per line -> one row.

    pandas reads that natively with lines=True. Columns only some event
    types use come out mostly-NaN — the same 'wide union' shape you saw
    in Spark's printSchema().
    """
    return pd.read_json(path, lines=True)


def build(df):
    """Return {name: DataFrame} of the gold tables. Each is the pandas
    twin of a query you already ran in Spark."""
    tables = {}

    # 1) Attacks per source IP — every unique attacker (feeds the map + bet).
    #    SQL: SELECT src_ip, COUNT(*) c GROUP BY src_ip ORDER BY c DESC
    tables["ips"] = (
        df.groupby("src_ip").size()
          .reset_index(name="count")
          .rename(columns={"src_ip": "ip"})   # clean public schema: ip, count
          .sort_values("count", ascending=False)
    )

    # 2) Most-tried credentials. Login events (success + failed) both start
    #    with 'cowrie.login'  ->  WHERE eventid LIKE 'cowrie.login%'
    logins = df[df["eventid"].str.startswith("cowrie.login", na=False)]
    tables["credentials"] = (
        logins.groupby(["username", "password"]).size()
              .reset_index(name="tries")
              .sort_values("tries", ascending=False)
              .head(25)
    )

    # 3) Commands run in the fake shell.  WHERE eventid = 'cowrie.command.input'
    cmds = df[df["eventid"] == "cowrie.command.input"]
    tables["commands"] = (
        cmds.groupby("input").size()
            .reset_index(name="n")
            .sort_values("n", ascending=False)
            .head(25)
    )

    # 4) Attacks per hour (UTC). timestamp is an ISO string; parse -> floor.
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    tables["hourly"] = (
        ts.dt.floor("h").value_counts().sort_index()
          .rename_axis("hour").reset_index(name="count")
    )

    return tables


def build_stats(df):
    """Headline numbers for the dashboard's KPI tiles."""
    ts = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    logins = df[df["eventid"].str.startswith("cowrie.login", na=False)]
    ip_counts = df["src_ip"].value_counts()
    return {
        "total_events": int(len(df)),
        "unique_ips": int(df["src_ip"].nunique()),
        "login_attempts": int(len(logins)),
        "commands_run": int((df["eventid"] == "cowrie.command.input").sum()),
        "sessions": int(df["session"].nunique()) if "session" in df else None,
        "first_seen": ts.min().isoformat(),
        "last_seen": ts.max().isoformat(),
        "top_ip": ip_counts.idxmax(),
        "top_ip_count": int(ip_counts.max()),
    }


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    if not path.exists():
        sys.exit(f"Raw log not found: {path}\nPass the path as the first argument.")

    print(f"Reading {path} ...")
    df = load_raw(path)
    print(f"  {len(df):,} events loaded")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for name, table in build(df).items():
        out = DATA_DIR / f"gold_{name}.csv"
        table.to_csv(out, index=False)
        print(f"  wrote {out.relative_to(REPO)}  ({len(table)} rows)")

    (DATA_DIR / "gold_stats.json").write_text(json.dumps(build_stats(df), indent=2))
    print(f"  wrote {(DATA_DIR / 'gold_stats.json').relative_to(REPO)}")
    print("\nGold layer ready. Next: GeoIP-enrich the IPs.")


if __name__ == "__main__":
    main()
