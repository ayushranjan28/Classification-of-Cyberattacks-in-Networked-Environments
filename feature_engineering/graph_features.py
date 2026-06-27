"""
Graph-based feature engineering: centrality, clustering coefficients.
"""
import pandas as pd
import numpy as np
import networkx as nx
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def compute_graph_centrality(df: pd.DataFrame, G: nx.DiGraph = None) -> pd.DataFrame:
    """
    Compute graph centrality features for IP nodes.
    If no graph provided, builds one from Source_IP / Destination_IP columns.
    Adds features per source IP.
    """
    log.info("🕸  Computing graph centrality features...")

    if G is None:
        src_col = next((c for c in df.columns if "Source_IP" in c or "Src_IP" in c), None)
        dst_col = next((c for c in df.columns if "Destination_IP" in c or "Dst_IP" in c), None)

        if src_col is None or dst_col is None:
            log.warning("  No IP columns found — skipping graph centrality features")
            return df

        # Build graph from flows
        edges = df[[src_col, dst_col]].drop_duplicates()
        G = nx.from_pandas_edgelist(edges, src_col, dst_col, create_using=nx.DiGraph())
        log.info(f"  Built graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Compute centralities (on undirected version for some metrics)
    G_undirected = G.to_undirected()

    degree_cent = nx.degree_centrality(G)
    betweenness = nx.betweenness_centrality(G, k=min(100, G.number_of_nodes()))
    clustering = nx.clustering(G_undirected)

    try:
        pagerank = nx.pagerank(G, max_iter=100)
    except Exception:
        pagerank = {n: 1.0 / G.number_of_nodes() for n in G.nodes()}

    # Map to source IPs
    src_col = next((c for c in df.columns if "Source_IP" in c or "Src_IP" in c), None)
    if src_col:
        df["Degree_Centrality"] = df[src_col].map(degree_cent).fillna(0)
        df["Betweenness_Centrality"] = df[src_col].map(betweenness).fillna(0)
        df["Clustering_Coeff"] = df[src_col].map(clustering).fillna(0)
        df["PageRank"] = df[src_col].map(pagerank).fillna(0)
        log.info("  Added: Degree_Centrality, Betweenness_Centrality, Clustering_Coeff, PageRank")

    return df
