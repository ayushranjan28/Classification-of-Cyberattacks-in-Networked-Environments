"""
Page 1: Live Dashboard — Alerts, Threat Level, Risk Gauge, Active Attacks.
"""
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from pathlib import Path
import sys
from streamlit_autorefresh import st_autorefresh

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from live_capture.database import get_recent_flows, get_database_stats

def _create_risk_gauge(score: float) -> go.Figure:
    """Create an animated risk gauge chart."""
    if pd.isna(score):
        score = 0
    if score <= 30:
        color = "#22C55E"
        label = "LOW"
    elif score <= 60:
        color = "#EAB308"
        label = "MEDIUM"
    elif score <= 80:
        color = "#F97316"
        label = "HIGH"
    else:
        color = "#EF4444"
        label = "CRITICAL"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={"suffix": "/100", "font": {"size": 36, "color": color}},
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#334155"},
            "bar": {"color": color, "thickness": 0.7},
            "bgcolor": "#1E293B",
            "borderwidth": 0,
            "steps": [
                {"range": [0, 30], "color": "rgba(34, 197, 94, 0.15)"},
                {"range": [30, 60], "color": "rgba(234, 179, 8, 0.15)"},
                {"range": [60, 80], "color": "rgba(249, 115, 22, 0.15)"},
                {"range": [80, 100], "color": "rgba(239, 68, 68, 0.15)"},
            ],
            "threshold": {
                "line": {"color": color, "width": 3},
                "thickness": 0.8,
                "value": score
            }
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font={"color": "#E0E0E0", "family": "Inter"},
        height=300,
        margin=dict(l=30, r=30, t=40, b=10),
    )
    return fig


def render():
    """Render the live dashboard page."""
    # Auto-refresh every 2000 milliseconds (2 seconds)
    st_autorefresh(interval=2000, limit=None, key="live_dashboard_refresh")
    
    st.markdown("# 🏠 Live Security Dashboard")
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Fetch real-time data from local PC
    flows = get_recent_flows(limit=1000)

    if not flows:
        st.info("📊 Waiting for live network traffic. Start the background sniffer by running `Start-AI-SOC.bat`.")
        return

    df = pd.DataFrame(flows)
    stats = get_database_stats()
    
    # Calculate live stats
    total_packets = stats["total"]
    n_attacks = stats["threats"]
    n_critical = stats["critical"]
    avg_risk = df["risk_score"].mean()
    
    # ─── Top Metrics Row ───────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Flows Sniffed (Live)", f"{total_packets:,}")
    with c2:
        st.metric("Threats Detected", f"{n_attacks:,}", delta="🔴 ACTIVE" if n_attacks > 0 else "✅ CLEAR")
    with c3:
        st.metric("Critical Blocks", f"{n_critical:,}", delta_color="inverse")
    with c4:
        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ─── Risk Gauge + Attack Distribution ──────────────────────────────
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("### Live Threat Level")
        fig = _create_risk_gauge(avg_risk)
        st.plotly_chart(fig, use_container_width=True)

        # Risk distribution
        cat_counts = df["risk_label"].value_counts()
        for cat in ["Critical", "High", "Medium", "Low"]:
            count = cat_counts.get(cat, 0)
            color_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            st.markdown(f"{color_map.get(cat, '')} **{cat}**: {count:,}")

    with col2:
        st.markdown("### Active Attack Distribution")
        
        attack_df = df[df["predicted_attack"] != "Normal"]
        if not attack_df.empty:
            label_counts = attack_df["predicted_attack"].value_counts()
            colors = ["#EF4444", "#F59E0B", "#F97316", "#8B5CF6", "#EC4899", "#3B82F6"]
            fig = go.Figure(data=[go.Pie(
                labels=label_counts.index.tolist(),
                values=label_counts.values.tolist(),
                hole=0.55,
                marker=dict(colors=colors[:len(label_counts)]),
                textinfo="label+percent",
                textfont=dict(size=13, color="#E0E0E0"),
            )])
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#E0E0E0"),
                height=400,
                showlegend=True,
                legend=dict(font=dict(color="#E0E0E0")),
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.success("✅ No attacks currently detected in the live buffer.")
            # Show empty chart
            fig = go.Figure()
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=400,
                annotations=[dict(text="No Threats Active", x=0.5, y=0.5, font_size=20, showarrow=False)]
            )
            st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ─── Recent Alerts Feed ────────────────────────────────────────────
    st.markdown("### 📋 Highest Risk Live Events")

    # Sort by risk score
    highest_risk_df = df.sort_values(by="risk_score", ascending=False).head(15)
    
    display_df = highest_risk_df[["timestamp", "src_ip", "dst_ip", "predicted_attack", "risk_label", "risk_score", "confidence"]].copy()
    display_df.rename(columns={
        "timestamp": "Time",
        "src_ip": "Source",
        "dst_ip": "Target",
        "predicted_attack": "Attack Type",
        "risk_label": "Severity",
        "risk_score": "Risk Score",
        "confidence": "Confidence"
    }, inplace=True)

    def color_severity(val):
        colors = {"Critical": "#EF4444", "High": "#F97316", "Medium": "#EAB308", "Low": "#22C55E"}
        return f"color: {colors.get(val, '#E0E0E0')}; font-weight: 600"

    styled = display_df.style.applymap(color_severity, subset=["Severity"])
    st.dataframe(styled, use_container_width=True, height=400)
