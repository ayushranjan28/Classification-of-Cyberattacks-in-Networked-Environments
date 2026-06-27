"""
Page 1: Live Dashboard — Alerts, Threat Level, Risk Gauge, Active Attacks.
"""
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
from pathlib import Path
import sys
import joblib
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def _load_data():
    """Load preprocessed data and models."""
    try:
        from config import SAVED_MODELS_DIR, PREPROCESSED_DIR
        data = joblib.load(PREPROCESSED_DIR / "processed_data.joblib")
        model = joblib.load(SAVED_MODELS_DIR / "best_classifier.joblib")
        from preprocessing.encoder import AttackEncoder
        encoder = AttackEncoder.load()
        return data, model, encoder
    except Exception:
        return None, None, None


def _create_risk_gauge(score: float) -> go.Figure:
    """Create an animated risk gauge chart."""
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
    st.markdown("# 🏠 Live Security Dashboard")
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    data, model, encoder = _load_data()

    if data is None or model is None:
        st.warning("⚠️ No trained models found. Run `python main.py` to train the system.")
        _render_demo_dashboard()
        return

    # Run predictions
    X_test = data["X_test"]
    y_test = data["y_test"]
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    # Compute risk scores
    attack_probs = 1 - y_proba[:, 0]  # 1 - P(normal)
    risk_scores = attack_probs * 100
    avg_risk = np.mean(risk_scores)
    n_attacks = np.sum(y_pred != 0)
    n_critical = np.sum(risk_scores > 80)

    # ─── Top Metrics Row ───────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.metric("Total Alerts", f"{n_attacks:,}", delta=f"{n_attacks/len(y_test)*100:.1f}%")
    with c2:
        st.metric("Critical Threats", f"{n_critical:,}", delta="🔴 ACTIVE" if n_critical > 0 else "✅ CLEAR")
    with c3:
        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")
    with c4:
        acc = np.mean(y_pred == y_test)
        st.metric("Detection Accuracy", f"{acc:.1%}")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ─── Risk Gauge + Attack Distribution ──────────────────────────────
    col1, col2 = st.columns([1, 2])

    with col1:
        st.markdown("### Threat Level")
        fig = _create_risk_gauge(avg_risk)
        st.plotly_chart(fig, use_container_width=True)

        # Risk distribution
        categories = []
        for r in risk_scores:
            if r <= 30: categories.append("Low")
            elif r <= 60: categories.append("Medium")
            elif r <= 80: categories.append("High")
            else: categories.append("Critical")
        cat_counts = pd.Series(categories).value_counts()
        for cat in ["Critical", "High", "Medium", "Low"]:
            count = cat_counts.get(cat, 0)
            color_map = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            st.markdown(f"{color_map.get(cat, '')} **{cat}**: {count:,}")

    with col2:
        st.markdown("### Attack Distribution")
        pred_labels = encoder.inverse_transform(y_pred)
        label_counts = pd.Series(pred_labels).value_counts()

        colors = ["#3B82F6", "#EF4444", "#F59E0B", "#10B981", "#8B5CF6", "#EC4899"]
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

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ─── Recent Alerts Feed ────────────────────────────────────────────
    st.markdown("### 📋 Recent Alert Feed")

    # Show top 20 highest-risk samples
    alert_indices = np.argsort(risk_scores)[-20:][::-1]
    alerts = []
    for idx in alert_indices:
        label = encoder.inverse_transform([y_pred[idx]])[0]
        alerts.append({
            "Risk Score": f"{risk_scores[idx]:.1f}",
            "Attack Type": label,
            "Severity": categories[idx],
            "Confidence": f"{y_proba[idx].max():.1%}",
        })

    alert_df = pd.DataFrame(alerts)

    def color_severity(val):
        colors = {"Critical": "#EF4444", "High": "#F97316", "Medium": "#EAB308", "Low": "#22C55E"}
        return f"color: {colors.get(val, '#E0E0E0')}; font-weight: 600"

    styled = alert_df.style.applymap(color_severity, subset=["Severity"])
    st.dataframe(styled, use_container_width=True, height=400)


def _render_demo_dashboard():
    """Render a demo dashboard with synthetic data."""
    st.info("📊 Showing demo data. Train models to see real predictions.")

    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Total Alerts", "1,247", delta="12.3%")
    with c2: st.metric("Critical Threats", "23", delta="🔴 ACTIVE")
    with c3: st.metric("Avg Risk Score", "42.7/100")
    with c4: st.metric("Detection Accuracy", "96.8%")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.markdown("### Threat Level")
        fig = _create_risk_gauge(42.7)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.markdown("### Attack Distribution (Demo)")
        fig = go.Figure(data=[go.Pie(
            labels=["Normal", "Brute Force", "Port Scan", "HTTP DDoS", "ICMP Flood", "Web Crawling"],
            values=[28502, 88502, 11081, 641, 45, 28],
            hole=0.55,
            marker=dict(colors=["#3B82F6", "#EF4444", "#F59E0B", "#10B981", "#8B5CF6", "#EC4899"]),
            textinfo="label+percent",
            textfont=dict(size=13, color="#E0E0E0"),
        )])
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#E0E0E0"), height=400,
            legend=dict(font=dict(color="#E0E0E0")),
        )
        st.plotly_chart(fig, use_container_width=True)
