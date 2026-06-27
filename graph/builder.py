"""
Graph construction: converts network flows into dynamic communication graphs.
Nodes = IPs, Edges = flows, with rich node/edge features.
"""
import pandas as pd
import numpy as np
import networkx as nx
import torch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import GRAPH_TIME_WINDOW, MAX_NODES_PER_GRAPH, CICIDS_LABEL_MAP
from utils.logger import get_logger

log = get_logger(__name__)


def build_static_graph(df: pd.DataFrame) -> tuple:
    """
    Build a static directed graph from network flow data.

    Returns:
        (G, node_features_df, edge_features_df)
    """
    log.info("🕸  Building static network graph...")

    src_col = next((c for c in df.columns if "Source_IP" in c), None)
    dst_col = next((c for c in df.columns if "Destination_IP" in c), None)

    if not src_col or not dst_col:
        log.error("  Cannot find Source/Destination IP columns")
        return None, None, None

    # Build graph
    G = nx.DiGraph()

    # Aggregate node features from flows
    all_ips = pd.concat([df[src_col], df[dst_col]]).unique()
    log.info(f"  Unique IPs: {len(all_ips)}")

    # Limit graph size for tractability
    if len(all_ips) > MAX_NODES_PER_GRAPH:
        # Keep top nodes by frequency
        ip_counts = pd.concat([df[src_col], df[dst_col]]).value_counts()
        top_ips = set(ip_counts.head(MAX_NODES_PER_GRAPH).index)
        df = df[df[src_col].isin(top_ips) & df[dst_col].isin(top_ips)]
        all_ips = pd.concat([df[src_col], df[dst_col]]).unique()
        log.info(f"  Trimmed to {len(all_ips)} nodes")

    # Node ID mapping
    ip_to_idx = {ip: idx for idx, ip in enumerate(all_ips)}

    # Compute node features (aggregated stats per IP)
    node_features = {}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    # Select meaningful aggregate columns
    agg_cols = [c for c in numeric_cols if any(k in c.lower() for k in
        ["pkt", "byt", "len", "flag", "duration", "iat"])][:10]

    for ip in all_ips:
        # Stats for flows where this IP is source
        src_flows = df[df[src_col] == ip]
        # Stats for flows where this IP is destination
        dst_flows = df[df[dst_col] == ip]

        features = [
            len(src_flows),                    # outgoing flow count
            len(dst_flows),                    # incoming flow count
            len(src_flows) + len(dst_flows),   # total connections
        ]
        for col in agg_cols[:5]:
            features.append(src_flows[col].mean() if len(src_flows) > 0 else 0)
            features.append(dst_flows[col].mean() if len(dst_flows) > 0 else 0)

        node_features[ip] = features

    # Feature names
    feat_names = ["out_flows", "in_flows", "total_connections"]
    for col in agg_cols[:5]:
        feat_names.extend([f"src_{col}_mean", f"dst_{col}_mean"])

    node_df = pd.DataFrame.from_dict(node_features, orient="index", columns=feat_names)
    node_df = node_df.fillna(0)

    # Build edge list with features
    edge_list = []
    label_col = "Label"
    for _, row in df.iterrows():
        src_idx = ip_to_idx[row[src_col]]
        dst_idx = ip_to_idx[row[dst_col]]
        edge_features = []
        for col in agg_cols[:6]:
            edge_features.append(float(row[col]) if pd.notna(row[col]) else 0.0)
        edge_list.append((src_idx, dst_idx, edge_features))
        G.add_edge(src_idx, dst_idx)

    log.info(f"  Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    return G, node_df, ip_to_idx


def build_pyg_data(df: pd.DataFrame, label_col: str = "Label"):
    """
    Build PyTorch Geometric Data objects from network flows.

    Returns:
        torch_geometric.data.Data or dict with tensors if PyG not available
    """
    log.info("🔥 Building PyTorch Geometric data...")

    src_col = next((c for c in df.columns if "Source_IP" in c), None)
    dst_col = next((c for c in df.columns if "Destination_IP" in c), None)

    if not src_col or not dst_col:
        log.warning("  No IP columns — building from flow features only")
        return _build_flow_graph(df, label_col)

    # Build IP-based graph
    all_ips = pd.concat([df[src_col], df[dst_col]]).unique()
    if len(all_ips) > MAX_NODES_PER_GRAPH:
        ip_counts = pd.concat([df[src_col], df[dst_col]]).value_counts()
        top_ips = set(ip_counts.head(MAX_NODES_PER_GRAPH).index)
        df = df[df[src_col].isin(top_ips) & df[dst_col].isin(top_ips)]
        all_ips = pd.concat([df[src_col], df[dst_col]]).unique()

    ip_to_idx = {ip: idx for idx, ip in enumerate(all_ips)}
    n_nodes = len(all_ips)

    # Compute node features
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    feature_cols = [c for c in numeric_cols if c != label_col][:15]

    node_features = np.zeros((n_nodes, len(feature_cols) + 2))
    node_labels = np.zeros(n_nodes, dtype=np.int64)
    node_label_counts = {}

    for _, row in df.iterrows():
        src_idx = ip_to_idx[row[src_col]]
        dst_idx = ip_to_idx[row[dst_col]]
        feats = [float(row[c]) if pd.notna(row[c]) else 0.0 for c in feature_cols]
        node_features[src_idx, :len(feats)] += np.array(feats)
        node_features[src_idx, -2] += 1  # out-degree
        node_features[dst_idx, -1] += 1  # in-degree

        # Assign label to src node (majority vote)
        lbl = row.get(label_col, 0)
        if src_idx not in node_label_counts:
            node_label_counts[src_idx] = {}
        node_label_counts[src_idx][lbl] = node_label_counts[src_idx].get(lbl, 0) + 1

    # Normalize node features by connection count
    conn_counts = node_features[:, -2] + node_features[:, -1]
    conn_counts[conn_counts == 0] = 1
    node_features[:, :-2] /= conn_counts[:, np.newaxis]

    # Majority vote labels
    for node_idx, counts in node_label_counts.items():
        node_labels[node_idx] = max(counts, key=counts.get)

    # Build edge index
    edge_src = []
    edge_dst = []
    for _, row in df.iterrows():
        edge_src.append(ip_to_idx[row[src_col]])
        edge_dst.append(ip_to_idx[row[dst_col]])

    # Replace NaN/inf
    node_features = np.nan_to_num(node_features, nan=0.0, posinf=1e6, neginf=-1e6)

    data_dict = {
        "x": torch.tensor(node_features, dtype=torch.float32),
        "edge_index": torch.tensor([edge_src, edge_dst], dtype=torch.long),
        "y": torch.tensor(node_labels, dtype=torch.long),
        "num_nodes": n_nodes,
        "ip_to_idx": ip_to_idx,
    }

    try:
        from torch_geometric.data import Data
        data = Data(
            x=data_dict["x"],
            edge_index=data_dict["edge_index"],
            y=data_dict["y"],
            num_nodes=n_nodes
        )
        log.info(f"  PyG Data: {data}")
        return data
    except ImportError:
        log.warning("  torch_geometric not available, returning dict")
        return data_dict


def _build_flow_graph(df: pd.DataFrame, label_col: str = "Label"):
    """Build a simple KNN graph from flow features when no IPs are available."""
    log.info("  Building flow-based KNN graph (no IPs available)...")
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    feature_cols = [c for c in numeric_cols if c != label_col]

    X = df[feature_cols].values
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
    y = df[label_col].values if label_col in df.columns else np.zeros(len(df))

    # Build KNN graph (k=5)
    from sklearn.neighbors import kneighbors_graph
    n_samples = min(len(X), 10000)  # limit for memory
    X_sub = X[:n_samples]
    y_sub = y[:n_samples]

    knn = kneighbors_graph(X_sub, n_neighbors=5, mode="connectivity", include_self=False)
    edge_index = np.array(knn.nonzero())

    data_dict = {
        "x": torch.tensor(X_sub, dtype=torch.float32),
        "edge_index": torch.tensor(edge_index, dtype=torch.long),
        "y": torch.tensor(y_sub, dtype=torch.long),
        "num_nodes": n_samples,
    }

    try:
        from torch_geometric.data import Data
        return Data(**{k: v for k, v in data_dict.items() if k != "num_nodes"})
    except ImportError:
        return data_dict


def build_dynamic_graphs(df: pd.DataFrame, window_seconds: int = None) -> list:
    """
    Build a sequence of graph snapshots over sliding time windows.

    Returns:
        List of PyG Data objects (or dicts)
    """
    window_seconds = window_seconds or GRAPH_TIME_WINDOW
    log.info(f"  Building dynamic graphs (window={window_seconds}s)...")

    if "Timestamp" not in df.columns:
        log.warning("  No Timestamp column — returning single static graph")
        return [build_pyg_data(df)]

    df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
    df = df.dropna(subset=["Timestamp"]).sort_values("Timestamp")

    min_time = df["Timestamp"].min()
    max_time = df["Timestamp"].max()
    total_seconds = (max_time - min_time).total_seconds()

    graphs = []
    current_start = min_time
    window = pd.Timedelta(seconds=window_seconds)

    while current_start < max_time:
        window_df = df[(df["Timestamp"] >= current_start) &
                       (df["Timestamp"] < current_start + window)]
        if len(window_df) > 10:
            g = build_pyg_data(window_df)
            graphs.append(g)
        current_start += window

    log.info(f"  Created {len(graphs)} graph snapshots")
    return graphs
