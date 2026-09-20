"""
enrich_geoip.py
---------------
Turn attacker IPs into countries + coordinates (+ ISP/ASN) so we can draw
the world map. Reads  dashboard/data/gold_ips.csv  (ip, count) and writes
dashboard/data/gold_ips_geo.csv.

We use ip-api.com's free BATCH endpoint: up to 100 IPs per POST, results
returned in the SAME order, so ~400 distinct attackers is just a few
requests instead of one-by-one. No API key. Free tier is rate-limited
(~15 req/min) and http-only — fine for a personal project.

Production alternative: a local MaxMind GeoLite2 .mmdb (offline, no rate
limit, fully reproducible) via the geoip2 library — worth a README line.

Run:  python analysis/enrich_geoip.py
"""

import time
from pathlib import Path

import pandas as pd
import requests

REPO = Path(__file__).resolve().parents[1]
DATA_DIR = REPO / "dashboard" / "data"
IN_CSV = DATA_DIR / "gold_ips.csv"
OUT_CSV = DATA_DIR / "gold_ips_geo.csv"

# Fields ip-api returns per IP. 'query' echoes the IP so we can line responses
# up with our input; 'as' is the ASN (the network/owner behind the IP).
FIELDS = "status,message,query,country,countryCode,lat,lon,isp,as"
BATCH_URL = "http://ip-api.com/batch"


def geolocate_batch(ips):
    """Look up many IPs with as few HTTP calls as possible.

    /batch takes a JSON list of up to 100 IPs and returns a list in the same
    order. We chunk into 100s. Think of it as one big ip -> location JOIN
    rather than 400 separate lookups.
    """
    geo = {}
    for start in range(0, len(ips), 100):
        chunk = ips[start:start + 100]
        resp = requests.post(BATCH_URL, params={"fields": FIELDS},
                             json=chunk, timeout=20)
        resp.raise_for_status()
        for item in resp.json():
            ip = item.get("query")
            ok = item.get("status") == "success"
            geo[ip] = {
                "country":      item.get("country")     if ok else None,
                "country_code": item.get("countryCode") if ok else None,
                "lat":          item.get("lat")         if ok else None,
                "lon":          item.get("lon")         if ok else None,
                "isp":          item.get("isp")         if ok else None,
                "asn":          item.get("as")          if ok else None,
            }
        print(f"  looked up {min(start + 100, len(ips))}/{len(ips)} IPs")
        time.sleep(1.5)  # stay under the free rate limit
    return geo


def main():
    ips_df = pd.read_csv(IN_CSV)
    ips = ips_df["ip"].astype(str).tolist()
    print(f"Geolocating {len(ips)} unique attacker IPs via ip-api batch ...")

    geo = geolocate_batch(ips)

    # Attach geo back onto each (ip, count) row; drop failed lookups
    # (private/reserved IPs can't be placed on a map).
    geo_df = pd.DataFrame.from_dict(geo, orient="index")
    out = ips_df.merge(geo_df, left_on="ip", right_index=True, how="left")
    placed = out.dropna(subset=["lat", "lon"])

    placed.to_csv(OUT_CSV, index=False)
    failed = len(out) - len(placed)
    print(f"\nWrote {OUT_CSV.relative_to(REPO)}  "
          f"({len(placed)} IPs placed, {failed} unresolved)")

    # Quick peek — the bet settler.
    by_country = (placed.groupby("country")["count"].sum()
                        .sort_values(ascending=False).head(12))
    print("\nTop source countries by attack volume:")
    print(by_country.to_string())


if __name__ == "__main__":
    main()
