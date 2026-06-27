"""
Graph visualization using NetworkX and Plotly for interactive rendering.
"""
import numpy as np
import networkx as nx
import plotly.graph_objects as go
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import RISK_COLORS
from utils.logger import get_logger

log = get_logger(__name__)


def create_network_plot(
    G: nx.DiGraph,
    node_risk_scores: dict = None,
    title: str = "Network Communication Graph",
    height: int = 700
) -> go.Figure:
    """
    Create an interactive Plotly network graph visualization.

    Args:
        G: NetworkX graph
        node_risk_scores: dict mapping node_id → risk_score (0-100)
        title: plot title
        height: figure height in pixels
    """
    log.info(f"📊 Rendering network graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Layout
    pos = nx.spring_layout(G, k=1.5, iterations=50, seed=42)

    # Edge traces
    edge_x, edge_y = [], []
    for u, v in G.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color="#555555"),
        hoverinfo="none",
        mode="lines",
        opacity=0.3
    )

    # Node traces
    node_x = [pos[n][0] for n in G.nodes()]
    node_y = [pos[n][1] for n in G.nodes()]

    # Risk-based coloring
    if node_risk_scores:
        node_colors = [node_risk_scores.get(n, 0) for n in G.nodes()]
        colorscale = [
            [0.0, RISK_COLORS["low"]],
            [0.3, RISK_COLORS["low"]],
            [0.31, RISK_COLORS["medium"]],
            [0.6, RISK_COLORS["medium"]],
            [0.61, RISK_COLORS["high"]],
            [0.8, RISK_COLORS["high"]],
            [0.81, RISK_COLORS["critical"]],
            [1.0, RISK_COLORS["critical"]]
        ]
    else:
        node_colors = [G.degree(n) for n in G.nodes()]
        colorscale = "Viridis"

    node_sizes = [max(8, min(30, G.degree(n) * 2)) for n in G.nodes()]

    node_text = []
    for n in G.nodes():
        risk = node_risk_scores.get(n, 0) if node_risk_scores else 0
        text = f"Node: {n}<br>Connections: {G.degree(n)}<br>Risk: {risk:.0f}/100"
        node_text.append(text)

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers",
        hoverinfo="text",
        text=node_text,
        marker=dict(
            showscale=True,
            colorscale=colorscale,
            color=node_colors,
            size=node_sizes,
            colorbar=dict(
                thickness=15,
                title="Risk Score",
                xanchor="left",
            ),
            line=dict(width=1, color="#333")
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(text=title, font=dict(size=18, color="#E0E0E0")),
            showlegend=False,
            hovermode="closest",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#0E1117",
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            height=height,
            margin=dict(l=20, r=20, t=50, b=20),
            font=dict(color="#E0E0E0")
        )
    )

    return fig
