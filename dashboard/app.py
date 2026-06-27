"""
AI-Based Predictive Intrusion Detection System — SOC Dashboard
Main Streamlit application with multi-page navigation.
"""
import streamlit as st
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# ─── Page Configuration ───────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI-IDS | Predictive Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* Global */
    .stApp {
        font-family: 'Inter', sans-serif;
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0A0F1C 0%, #111827 100%);
        border-right: 1px solid rgba(59, 130, 246, 0.2);
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.6) 100%);
        border: 1px solid rgba(59, 130, 246, 0.15);
        border-radius: 12px;
        padding: 16px 20px;
        backdrop-filter: blur(10px);
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
    }

    [data-testid="stMetric"] label {
        color: #94A3B8 !important;
        font-weight: 500;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    [data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 700;
    }

    /* Headers */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif !important;
        font-weight: 700 !important;
    }

    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background: rgba(15, 23, 42, 0.5);
        border-radius: 12px;
        padding: 4px;
    }

    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 20px;
        font-weight: 500;
    }

    /* Custom alert cards */
    .alert-card {
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%);
        border-radius: 12px;
        padding: 20px;
        margin: 8px 0;
        border-left: 4px solid;
        backdrop-filter: blur(10px);
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    }

    .alert-critical { border-left-color: #EF4444; }
    .alert-high { border-left-color: #F97316; }
    .alert-medium { border-left-color: #EAB308; }
    .alert-low { border-left-color: #22C55E; }

    /* Risk gauge */
    .risk-gauge {
        text-align: center;
        padding: 20px;
        background: linear-gradient(135deg, rgba(15, 23, 42, 0.9) 0%, rgba(30, 41, 59, 0.7) 100%);
        border-radius: 16px;
        border: 1px solid rgba(59, 130, 246, 0.15);
    }

    .risk-value {
        font-size: 4rem;
        font-weight: 800;
        line-height: 1;
        margin: 10px 0;
    }

    .risk-label {
        font-size: 1.1rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 2px;
    }

    /* Divider */
    .section-divider {
        height: 1px;
        background: linear-gradient(90deg, transparent, rgba(59, 130, 246, 0.3), transparent);
        margin: 20px 0;
    }

    /* Logo area */
    .logo-container {
        text-align: center;
        padding: 20px 0 30px 0;
    }

    .logo-title {
        font-size: 1.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }

    .logo-subtitle {
        font-size: 0.75rem;
        color: #64748B;
        text-transform: uppercase;
        letter-spacing: 2px;
        margin-top: 4px;
    }

    /* Data table styling */
    .dataframe {
        font-size: 0.85rem !important;
    }

    /* Plotly chart containers */
    .js-plotly-plot {
        border-radius: 12px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# ─── Sidebar Navigation ───────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div class="logo-container">
        <p class="logo-title">🛡️ AI-IDS</p>
        <p class="logo-subtitle">Predictive Intrusion Detection</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        [
            "🏠 Live Dashboard",
            "📡 Live Traffic",
            "🕸️ Network Graph",
            "📅 Attack Timeline",
            "🎯 MITRE ATT&CK",
            "🔍 Explainable AI",
            "📊 Analytics",
        ],
        label_visibility="collapsed"
    )

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # System status
    st.markdown("### System Status")
    models_exist = (Path(__file__).parent.parent / "saved_models" / "best_classifier.joblib").exists()
    if models_exist:
        st.success("✅ Models Loaded")
    else:
        st.warning("⚠️ No trained models found")
        st.caption("Run `python main.py` to train")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.caption("IEEE DataPort Hackathon 2025")
    st.caption("v1.0 — AI-Powered SOC")


# ─── Page Routing ──────────────────────────────────────────────────────────────
if page == "🏠 Live Dashboard":
    from views import page_live_dashboard
    page_live_dashboard.render()
elif page == "📡 Live Traffic":
    from views import page_live_traffic
    page_live_traffic.render()
elif page == "🕸️ Network Graph":
    from views import page_network_graph
    page_network_graph.render()
elif page == "📅 Attack Timeline":
    from views import page_attack_timeline
    page_attack_timeline.render()
elif page == "🎯 MITRE ATT&CK":
    from views import page_mitre_mapping
    page_mitre_mapping.render()
elif page == "🔍 Explainable AI":
    from views import page_explainable_ai
    page_explainable_ai.render()
elif page == "📊 Analytics":
    from views import page_analytics
    page_analytics.render()
