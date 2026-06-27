"""
Page 2: Network Graph — Interactive graph visualization with risk coloring.
"""
import streamlit as st
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


from live_capture.database import get_recent_flows
from streamlit_autorefresh import st_autorefresh

def render():
    st_autorefresh(interval=2000, limit=None, key="network_refresh")
    st.markdown("# 🕸️ Live Network Communication Graph")
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        layout = st.selectbox("Graph Layout", ["Spring", "Kamada-Kawai", "Circular"], index=0)
    with col2:
        min_risk = st.slider("Minimum Risk Filter", 0, 100, 0)
    with col3:
        show_labels = st.checkbox("Show Node Labels", value=False)

    flows = get_recent_flows(limit=1000)
    
    if not flows:
        st.info("📊 Waiting for live network traffic. Start the background sniffer by running `Start-AI-SOC.bat`.")
        return
        
    # Build NetworkX graph from live flows
    G = nx.DiGraph()
    risk_scores = {}
    
    for flow in flows:
        src = flow["src_ip"]
        dst = flow["dst_ip"]
        score = flow["risk_score"]
        
        G.add_edge(src, dst)
        
        # Keep highest risk score for nodes
        if src not in risk_scores or score > risk_scores[src]:
            risk_scores[src] = score
        if dst not in risk_scores or score > risk_scores[dst]:
            risk_scores[dst] = score

    # Apply risk filter
    if min_risk > 0:
        nodes_to_keep = [n for n in G.nodes() if risk_scores.get(n, 0) >= min_risk]
        G = G.subgraph(nodes_to_keep).copy()

    # Compute layout
    if layout == "Spring":
        pos = nx.spring_layout(G, k=2.0, iterations=50, seed=42)
    elif layout == "Kamada-Kawai":
        pos = nx.kamada_kawai_layout(G)
    else:
        pos = nx.circular_layout(G)

    # Edge traces
    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.4, color="rgba(100, 116, 139, 0.3)"),
        hoverinfo="none", mode="lines"
    )

    # Node traces
    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]
    node_colors = [risk_scores.get(n, 0) for n in G.nodes()]
    node_sizes = [max(10, min(35, G.degree(n) * 3)) for n in G.nodes()]

    node_text = []
    for n in G.nodes():
        risk = risk_scores.get(n, 0)
        level = "Low" if risk <= 30 else "Medium" if risk <= 60 else "High" if risk <= 80 else "Critical"
        node_text.append(f"Node: {n}<br>Risk: {risk:.1f}/100 ({level})<br>Connections: {G.degree(n)}")

    node_trace = go.Scatter(
        x=node_x, y=node_y, mode="markers+text" if show_labels else "markers",
        text=[str(n) for n in G.nodes()] if show_labels else node_text,
        textposition="top center" if show_labels else None,
        textfont=dict(size=9, color="#94A3B8") if show_labels else None,
        hoverinfo="text" if not show_labels else "text",
        hovertext=node_text,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            colorscale=[
                [0.0, "#22C55E"], [0.3, "#22C55E"],
                [0.31, "#EAB308"], [0.6, "#EAB308"],
                [0.61, "#F97316"], [0.8, "#F97316"],
                [0.81, "#EF4444"], [1.0, "#EF4444"]
            ],
            colorbar=dict(title="Risk", thickness=15, tickfont=dict(color="#E0E0E0")),
            line=dict(width=1.5, color="#1E293B"),
            cmin=0, cmax=100
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(
        paper_bgcolor="#0E1117", plot_bgcolor="#0E1117",
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=650, margin=dict(l=10, r=10, t=10, b=10),
        font=dict(color="#E0E0E0"),
        hovermode="closest",
    )
    st.plotly_chart(fig, use_container_width=True)

    # Graph statistics
    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
    st.markdown("### 📊 Graph Statistics")
    c1, c2, c3, c4 = st.columns(4)
    with c1: st.metric("Nodes", len(G.nodes()))
    with c2: st.metric("Edges", len(G.edges()))
    with c3: st.metric("Avg Degree", f"{np.mean([G.degree(n) for n in G.nodes()]):.1f}")
    with c4:
        high_risk = sum(1 for n in G.nodes() if risk_scores.get(n, 0) > 60)
        st.metric("High Risk Nodes", high_risk)
