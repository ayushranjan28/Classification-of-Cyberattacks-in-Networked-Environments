"""
Page 4: MITRE ATT&CK Mapping — Technique/Tactic/Mitigation drill-down.
"""
import streamlit as st
import pandas as pd
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from config import ATTACK_TO_MITRE


from live_capture.database import get_recent_flows
from streamlit_autorefresh import st_autorefresh

def render():
    st_autorefresh(interval=5000, limit=None, key="mitre_refresh")
    st.markdown("# 🎯 Live MITRE ATT&CK Mapping")
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    flows = get_recent_flows(limit=1000)
    
    # Determine default selection based on active live threats
    default_attack = None
    if flows:
        df = pd.DataFrame(flows)
        attacks = df[df["predicted_attack"] != "BENIGN"]["predicted_attack"]
        if not attacks.empty:
            default_attack = attacks.value_counts().index[0]
            st.warning(f"🔴 Auto-tracking Active Threat: **{default_attack}**")

    # Attack type selector
    attack_types = [k for k in ATTACK_TO_MITRE.keys() if k != "Normal"]
    
    default_idx = 0
    if default_attack and default_attack in attack_types:
        default_idx = attack_types.index(default_attack)
        
    selected = st.selectbox("Select Attack Type", attack_types, index=default_idx)

    info = ATTACK_TO_MITRE[selected]

    # Main info card
    st.markdown(f"""
    <div class="alert-card alert-critical">
        <h3 style="margin:0 0 10px 0; color: #EF4444;">🔴 {info['technique_name']}</h3>
        <table style="width: 100%; border-collapse: collapse;">
            <tr>
                <td style="padding: 6px 0; color: #94A3B8; width: 160px;"><strong>Technique ID</strong></td>
                <td style="padding: 6px 0; color: #E0E0E0;"><code>{info['technique_id']}</code></td>
            </tr>
            <tr>
                <td style="padding: 6px 0; color: #94A3B8;"><strong>Tactic</strong></td>
                <td style="padding: 6px 0; color: #E0E0E0;">{info['tactic']}</td>
            </tr>
            <tr>
                <td style="padding: 6px 0; color: #94A3B8;"><strong>Predicted Label</strong></td>
                <td style="padding: 6px 0; color: #E0E0E0;">{selected}</td>
            </tr>
        </table>
        <p style="margin-top: 12px; color: #CBD5E1; font-size: 0.9rem;">{info['description']}</p>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    # Attack chain
    with col1:
        st.markdown("### ⛓️ Attack Progression Chain")
        st.markdown(f"""
        <div style="padding: 15px;">
            <div style="background: rgba(59, 130, 246, 0.15); border-left: 3px solid #3B82F6;
                        padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0;">
                <strong style="color: #3B82F6;">CURRENT STAGE</strong><br>
                <span style="color: #E0E0E0; font-size: 1.1rem;">{info['technique_id']} — {info['technique_name']}</span><br>
                <span style="color: #94A3B8;">Tactic: {info['tactic']}</span>
            </div>
        """, unsafe_allow_html=True)

        for i, next_tech in enumerate(info.get("next_techniques", [])):
            st.markdown(f"""
            <div style="text-align: center; color: #64748B; font-size: 1.2rem;">↓</div>
            <div style="background: rgba(239, 68, 68, 0.1); border-left: 3px solid #F97316;
                        padding: 12px 16px; border-radius: 0 8px 8px 0; margin: 8px 0;">
                <strong style="color: #F97316;">POSSIBLE NEXT</strong><br>
                <span style="color: #E0E0E0;">{next_tech}</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("</div>", unsafe_allow_html=True)

    # Mitigations
    with col2:
        st.markdown("### 🛡️ Recommended Mitigations")
        for i, mitigation in enumerate(info.get("mitigations", []), 1):
            priority = "🔴 Critical" if i <= 2 else "🟡 Recommended" if i <= 4 else "🟢 Advisory"
            st.markdown(f"""
            <div class="alert-card" style="border-left-color: {'#EF4444' if i <= 2 else '#EAB308' if i <= 4 else '#22C55E'};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: #E0E0E0;"><strong>{i}.</strong> {mitigation}</span>
                    <span style="font-size: 0.75rem; color: #94A3B8;">{priority}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # Full mapping table
    st.markdown("### 📋 Complete Attack → MITRE Mapping")
    rows = []
    for label, info in ATTACK_TO_MITRE.items():
        if label == "Normal":
            continue
        rows.append({
            "Attack Label": label,
            "Technique ID": info["technique_id"],
            "Technique Name": info["technique_name"],
            "Tactic": info["tactic"],
            "Next Stages": ", ".join(info.get("next_techniques", [])[:2]),
            "# Mitigations": len(info.get("mitigations", [])),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, height=300)

    # Knowledge base search
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown("### 🔎 Knowledge Base Search")
    try:
        from mitre.knowledge_base import MitreKnowledgeBase
        kb = MitreKnowledgeBase().load()
        query = st.text_input("Search MITRE techniques", placeholder="e.g., brute force, lateral movement")
        if query:
            results = kb.search_techniques(query, limit=10)
            if results:
                for r in results:
                    with st.expander(f"{r['id']} — {r['name']}"):
                        st.write(r["description"][:300] + "...")
                        if r.get("mitigation"):
                            st.write(f"**Mitigation:** {r['mitigation'][:300]}...")
            else:
                st.info("No results found")
    except Exception:
        st.caption("Knowledge base not loaded. Ensure MitreEnterprise.csv exists.")
