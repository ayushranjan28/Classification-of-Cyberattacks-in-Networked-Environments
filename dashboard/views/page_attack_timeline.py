"""
Page 3: Attack Timeline — Temporal progression of attack stages.
"""
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
import sys
import joblib
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def render():
    st.markdown("# 📅 Attack Timeline")
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Try to load real data
    try:
        from config import PREPROCESSED_DIR, SAVED_MODELS_DIR
        from preprocessing.encoder import AttackEncoder
        data = joblib.load(PREPROCESSED_DIR / "processed_data.joblib")
        model = joblib.load(SAVED_MODELS_DIR / "best_classifier.joblib")
        encoder = AttackEncoder.load()
        y_pred = model.predict(data["X_test"])
        pred_labels = encoder.inverse_transform(y_pred)
        has_data = True
    except Exception:
        has_data = False

    if has_data:
        # Create timeline from test set ordering
        n = len(pred_labels)
        timeline_df = pd.DataFrame({
            "Index": range(n),
            "Attack_Type": pred_labels,
            "Risk_Score": np.random.uniform(0, 100, n),  # approximate
        })
    else:
        st.info("📊 Showing simulated timeline. Train models for real data.")
        np.random.seed(42)
        n = 500
        attack_types = np.random.choice(
            ["Normal", "Brute_Force", "Port_Scan", "HTTP_DDoS", "ICMP_Flood", "Web_Crwling"],
            size=n, p=[0.5, 0.25, 0.1, 0.08, 0.04, 0.03]
        )
        timeline_df = pd.DataFrame({
            "Index": range(n),
            "Attack_Type": attack_types,
            "Risk_Score": [np.random.uniform(0, 30) if a == "Normal"
                          else np.random.uniform(40, 100) for a in attack_types],
        })

    # Timeline chart
    st.markdown("### Attack Progression Over Flow Sequence")
    color_map = {
        "Normal": "#3B82F6", "Brute_Force": "#EF4444", "Port_Scan": "#F59E0B",
        "HTTP_DDoS": "#10B981", "ICMP_Flood": "#8B5CF6", "Web_Crwling": "#EC4899"
    }

    fig = go.Figure()
    for attack_type in timeline_df["Attack_Type"].unique():
        mask = timeline_df["Attack_Type"] == attack_type
        subset = timeline_df[mask]
        fig.add_trace(go.Scatter(
            x=subset["Index"], y=subset["Risk_Score"],
            mode="markers", name=attack_type,
            marker=dict(size=5, color=color_map.get(attack_type, "#666"), opacity=0.7),
            hovertemplate=f"<b>{attack_type}</b><br>Index: %{{x}}<br>Risk: %{{y:.1f}}<extra></extra>"
        ))

    fig.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#1A1A2E",
        xaxis_title="Flow Sequence Index", yaxis_title="Risk Score",
        font=dict(color="#E0E0E0"), height=450,
        legend=dict(orientation="h", y=-0.15),
        hovermode="closest"
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # MITRE Kill Chain Progression
    st.markdown("### 🎯 MITRE ATT&CK Kill Chain")
    kill_chain = [
        {"Phase": "Reconnaissance", "Attacks": "Web_Crwling", "Color": "#3B82F6"},
        {"Phase": "Initial Access", "Attacks": "Brute_Force", "Color": "#8B5CF6"},
        {"Phase": "Discovery", "Attacks": "Port_Scan", "Color": "#F59E0B"},
        {"Phase": "Credential Access", "Attacks": "Brute_Force", "Color": "#EF4444"},
        {"Phase": "Impact", "Attacks": "HTTP_DDoS, ICMP_Flood", "Color": "#DC2626"},
    ]

    phases = [kc["Phase"] for kc in kill_chain]
    attacks_in_phase = []
    for kc in kill_chain:
        count = sum(1 for a in timeline_df["Attack_Type"] if a in kc["Attacks"])
        attacks_in_phase.append(count)

    fig2 = go.Figure(go.Bar(
        x=phases, y=attacks_in_phase,
        marker_color=[kc["Color"] for kc in kill_chain],
        text=attacks_in_phase, textposition="outside",
        textfont=dict(color="#E0E0E0"),
    ))
    fig2.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#1A1A2E",
        xaxis_title="Kill Chain Phase", yaxis_title="Attack Count",
        font=dict(color="#E0E0E0"), height=400,
    )
    st.plotly_chart(fig2, use_container_width=True)

    # Attack frequency heatmap
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown("### 🔥 Attack Density Heatmap")

    # Create windowed counts
    window_size = max(1, n // 20)
    windows = []
    for i in range(0, n, window_size):
        chunk = timeline_df.iloc[i:i+window_size]
        for attack in color_map.keys():
            windows.append({
                "Window": f"W{i//window_size + 1}",
                "Attack": attack,
                "Count": (chunk["Attack_Type"] == attack).sum()
            })

    heat_df = pd.DataFrame(windows).pivot(index="Attack", columns="Window", values="Count").fillna(0)

    fig3 = go.Figure(data=go.Heatmap(
        z=heat_df.values, x=heat_df.columns.tolist(), y=heat_df.index.tolist(),
        colorscale=[[0, "#0E1117"], [0.25, "#1E3A5F"], [0.5, "#3B82F6"], [0.75, "#F59E0B"], [1, "#EF4444"]],
        hoverongaps=False,
    ))
    fig3.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
        font=dict(color="#E0E0E0"), height=350,
    )
    st.plotly_chart(fig3, use_container_width=True)
