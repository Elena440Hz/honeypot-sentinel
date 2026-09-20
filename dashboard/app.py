"""
app.py — Sentinel Honeypot dashboard (Streamlit).

Reads ONLY the small gold CSVs in dashboard/data/ (produced by
analysis/build_gold.py and analysis/enrich_geoip.py). Run:

    streamlit run dashboard/app.py

Design notes (why it looks the way it does):
  * Headline numbers are STAT TILES, not charts — a number's job is to be read.
  * The map uses BUBBLES sized by attack count, not a choropleth: the top source
    is the tiny Netherlands, which a choropleth (colour by land area) would hide.
  * Every chart is a SINGLE series -> one accent hue, sorted bars, direct labels.
    No rainbow, no dual-axis. (No categorical multi-series, so no CVD palette.)
  * One accent colour (threat red-orange) + neutral ink on a dark surface.
"""

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

DATA_DIR = Path(__file__).parent / "data"
ACCENT = "#ff5a4d"          # threat red-orange — the single accent hue
INK = "#e6e6e6"

st.set_page_config(page_title="Sentinel Honeypot", page_icon="🛡️", layout="wide")


# --- Load the gold layer ---------------------------------------------------
@st.cache_data
def load():
    geo = pd.read_csv(DATA_DIR / "gold_ips_geo.csv")
    creds = pd.read_csv(DATA_DIR / "gold_credentials.csv")
    cmds = pd.read_csv(DATA_DIR / "gold_commands.csv")
    hourly = pd.read_csv(DATA_DIR / "gold_hourly.csv")
    hourly["hour"] = pd.to_datetime(hourly["hour"], utc=True)
    stats = json.loads((DATA_DIR / "gold_stats.json").read_text())
    return geo, creds, cmds, hourly, stats


geo, creds, cmds, hourly, stats = load()


def style(fig, height):
    """Shared dark, transparent-surface styling so charts sit on the page."""
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=10, b=10),
        height=height,
        font=dict(color=INK),
        coloraxis_showscale=False,
    )
    return fig


# --- Header ----------------------------------------------------------------
st.title("🛡️ Sentinel Honeypot — Attack Intelligence")
st.caption(
    f"Real SSH attacks captured by a Cowrie honeypot on Azure  ·  "
    f"{stats['first_seen'][:10]} (UTC)  ·  one day of data"
)

# --- KPI tiles -------------------------------------------------------------
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total attacks", f"{stats['total_events']:,}")
k2.metric("Unique IPs", f"{stats['unique_ips']:,}")
k3.metric("Countries", f"{geo['country'].nunique()}")
k4.metric("Login attempts", f"{stats['login_attempts']:,}")
k5.metric("Commands run", f"{stats['commands_run']:,}")

st.divider()

# --- World map (the memorable bit) -----------------------------------------
st.subheader("🌍 Where the attacks originate")
m = px.scatter_geo(
    geo, lat="lat", lon="lon", size="count", size_max=48,
    hover_name="ip",
    hover_data={"country": True, "isp": True, "count": ":,",
                "lat": False, "lon": False},
    projection="natural earth",
)
m.update_traces(marker=dict(color=ACCENT, opacity=0.72,
                            line=dict(width=0.5, color="rgba(255,255,255,0.35)")))
m.update_geos(bgcolor="rgba(0,0,0,0)", showland=True, landcolor="#1c2128",
              showocean=True, oceancolor="#0b0e14", showcountries=True,
              countrycolor="rgba(255,255,255,0.12)", coastlinecolor="rgba(255,255,255,0.12)")
st.plotly_chart(style(m, 460), use_container_width=True)
st.caption(
    "Bubble size = attack volume. Location is where the **hosting infrastructure** "
    "sits, *not* the operator — the same network (AS47890 “Unmanaged LTD”) appears "
    "under both the Netherlands and the United States."
)

# --- Countries + Networks --------------------------------------------------
left, right = st.columns(2)

with left:
    st.subheader("Top source countries")
    by_country = (geo.groupby("country")["count"].sum()
                     .sort_values().tail(12).reset_index())
    c = px.bar(by_country, x="count", y="country", orientation="h", text="count")
    c.update_traces(marker_color=ACCENT, textposition="outside", cliponaxis=False)
    c.update_layout(xaxis_title=None, yaxis_title=None, xaxis_showgrid=False)
    st.plotly_chart(style(c, 430), use_container_width=True)

with right:
    st.subheader("Top networks (ISP / hosting)")
    by_isp = (geo.groupby("isp")["count"].sum()
                 .sort_values().tail(12).reset_index())
    n = px.bar(by_isp, x="count", y="isp", orientation="h", text="count")
    n.update_traces(marker_color=ACCENT, textposition="outside", cliponaxis=False)
    n.update_layout(xaxis_title=None, yaxis_title=None, xaxis_showgrid=False)
    st.plotly_chart(style(n, 430), use_container_width=True)

# --- Hourly timeline -------------------------------------------------------
st.subheader("Attacks over time (hourly, UTC)")
h = px.area(hourly, x="hour", y="count")
h.update_traces(line_color=ACCENT, fillcolor="rgba(255,90,77,0.22)")
h.update_layout(xaxis_title=None, yaxis_title="attacks", xaxis_showgrid=False)
st.plotly_chart(style(h, 280), use_container_width=True)
st.caption(
    "The 06:00–08:00 spike is ~95% a single host (45.153.34.181) — a campaign "
    "burst, not a daily rhythm."
)

st.divider()

# --- Credentials + commands ------------------------------------------------
left2, right2 = st.columns(2)

with left2:
    st.subheader("🔑 Most-tried credentials")
    creds_view = creds.copy()
    creds_view["password"] = creds_view["password"].fillna("(empty)")
    st.dataframe(creds_view, hide_index=True, use_container_width=True, height=380)

with right2:
    st.subheader("⌨️ Commands attackers ran")
    cmds_view = cmds.copy()
    cmds_view["input"] = cmds_view["input"].str.slice(0, 90).str.replace("\n", " ")
    cmds_view = cmds_view.rename(columns={"input": "command (truncated)", "n": "count"})
    st.dataframe(cmds_view, hide_index=True, use_container_width=True, height=380)

# --- Malware highlight ------------------------------------------------------
st.subheader("🧬 Captured malware dropper")
st.markdown(
    "One session ran a full **kill chain** — reconnaissance → sandbox check → "
    "payload. The payload (executed once):"
)
st.code("chmod +x ./.1988208513807693888/xinetd; nohup ./.1988208513807693888/xinetd &",
        language="bash")
st.markdown(
    "- Hidden `.`-directory (**T1564.001**) · binary masquerading as the `xinetd` "
    "daemon (**T1036**) · detached with `nohup` for persistence (**T1059**).\n"
    "- On a real host this would be game-over. Here Cowrie faked every response — "
    "**nothing executed** — and the VM's egress lockdown would have blocked the "
    "loader's C2 callback anyway."
)

with st.expander("ℹ️ How this dashboard is built"):
    st.markdown(
        "Cowrie honeypot on an Azure VM → logs shipped to Azure Blob → analysed "
        "with **PySpark** (Databricks) → aggregated into a small **gold** layer → "
        "IPs enriched with **GeoIP** (country + ISP/ASN) → rendered here with "
        "**Streamlit + Plotly**. Attacker locations reflect hosting infrastructure, "
        "not operators."
    )

st.divider()
st.caption("Sentinel Honeypot · built by Konstantinos Parasis")
