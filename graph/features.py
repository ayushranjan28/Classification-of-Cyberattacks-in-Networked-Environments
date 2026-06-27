"""
Node and edge feature vector construction for graph neural networks.
"""
import numpy as np
import pandas as pd
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def compute_node_features(df: pd.DataFrame, ip_col: str, agg_cols: list) -> pd.DataFrame:
    """
    Aggregate flow-level features to node-level features for a given IP column.

    Args:
        df: DataFrame with flow data
        ip_col: column name with IP addresses
        agg_cols: list of numeric columns to aggregate

    Returns:
        DataFrame with one row per IP, columns = aggregated stats
    """
    agg_funcs = {}
    for col in agg_cols:
        if col in df.columns:
            agg_funcs[col] = ["mean", "std", "max", "sum"]

    if not agg_funcs:
        log.warning("  No columns to aggregate for node features")
        return pd.DataFrame()

    node_features = df.groupby(ip_col).agg(agg_funcs)
    node_features.columns = ["_".join(col).strip() for col in node_features.columns]
    node_features = node_features.fillna(0)

    # Add connection count
    node_features["connection_count"] = df.groupby(ip_col).size()

    log.info(f"  Node features: {node_features.shape} ({len(agg_cols)} base cols × 4 aggs)")
    return node_features


def compute_edge_features(df: pd.DataFrame, src_col: str, dst_col: str, feature_cols: list) -> pd.DataFrame:
    """
    Compute edge-level features between IP pairs.
    """
    if src_col not in df.columns or dst_col not in df.columns:
        return pd.DataFrame()

    # Create edge key
    df["_edge_key"] = df[src_col].astype(str) + "->" + df[dst_col].astype(str)

    valid_cols = [c for c in feature_cols if c in df.columns]
    edge_features = df.groupby("_edge_key")[valid_cols].agg(["mean", "count"])
    edge_features.columns = ["_".join(col).strip() for col in edge_features.columns]
    edge_features = edge_features.fillna(0)

    df.drop(columns=["_edge_key"], inplace=True)

    log.info(f"  Edge features: {edge_features.shape}")
    return edge_features
