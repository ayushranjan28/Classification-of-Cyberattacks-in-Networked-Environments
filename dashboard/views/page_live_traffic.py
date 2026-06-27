import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from streamlit_autorefresh import st_autorefresh
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from live_capture.database import get_recent_flows, get_database_stats

def render():
    # Auto-refresh every 2000 milliseconds (2 seconds)
    st_autorefresh(interval=2000, limit=None, key="live_traffic_refresh")

    st.title("📡 Live Network Traffic Monitor")
    st.markdown("Real-time AI analysis of TCP/UDP flows currently traversing your network interface.")

    # Fetch latest flows
    flows = get_recent_flows(limit=100)

    if not flows:
        st.info("Waiting for network traffic... Make sure `python live_capture/sniffer.py` is running.")
    else:
        df = pd.DataFrame(flows)
        stats = get_database_stats()
        
        # Calculate live stats
        total_flows = stats["total"]
        anomalies = stats["threats"]
        highest_risk = df["risk_score"].max()
        
        col1, col2, col3 = st.columns(3)
        col1.metric("Recent Flows (Last 100)", total_flows)
        
        anomaly_delta = f"{anomalies} Attacks" if anomalies > 0 else "All Clear"
        col2.metric("Threats Detected", anomalies, delta=anomaly_delta, delta_color="inverse")
        
        risk_color = "normal" if highest_risk < 50 else "inverse"
        col3.metric("Peak Live Risk Score", f"{highest_risk:.1f}%", delta_color=risk_color)
        
        st.divider()
        
        # Format the dataframe for display
        display_df = df[["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "predicted_attack", "risk_label", "risk_score", "confidence"]].copy()
        
        # Style the dataframe based on risk
        def highlight_risk(row):
            if row["predicted_attack"] != "Normal":
                return ['background-color: rgba(239, 68, 68, 0.2)'] * len(row)
            elif row["risk_label"] == "Medium":
                return ['background-color: rgba(245, 158, 11, 0.2)'] * len(row)
            return [''] * len(row)

        st.subheader("🔴 Live Flow Stream")
        st.dataframe(
            display_df.style.apply(highlight_risk, axis=1),
            use_container_width=True,
            hide_index=True
        )
        
        # Live Attack Distribution
        st.subheader("📊 Live Threat Distribution")
        colA, colB = st.columns(2)
        
        with colA:
            if anomalies > 0:
                attack_counts = df[df["predicted_attack"] != "Normal"]["predicted_attack"].value_counts().reset_index()
                attack_counts.columns = ["Attack Type", "Count"]
                fig1 = px.pie(attack_counts, names="Attack Type", values="Count", hole=0.4, title="Detected Attack Types")
                fig1.update_traces(marker=dict(colors=["#EF4444", "#F97316", "#F59E0B"]))
                st.plotly_chart(fig1, use_container_width=True)
            else:
                st.success("No attacks detected in the recent flow buffer.")
                
        with colB:
            risk_dist = df["risk_label"].value_counts().reindex(["Low", "Medium", "High", "Critical"]).fillna(0).reset_index()
            risk_dist.columns = ["Risk Level", "Count"]
            
            colors = {"Low": "#10B981", "Medium": "#F59E0B", "High": "#F97316", "Critical": "#EF4444"}
            fig2 = px.bar(risk_dist, x="Risk Level", y="Count", title="Risk Level Distribution", color="Risk Level", color_discrete_map=colors)
            st.plotly_chart(fig2, use_container_width=True)
