"""
Model 2: Graph Neural Networks — GraphSAGE, GAT, GCN
Node-level attack classification on communication graphs.
"""
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import GNN_PARAMS, SAVED_MODELS_DIR
from utils.logger import get_logger
from utils.timer import Timer

log = get_logger(__name__)

# ─── Check for torch_geometric ─────────────────────────────────────────────
HAS_PYG = False
try:
    from torch_geometric.nn import SAGEConv, GATConv, GCNConv
    from torch_geometric.data import Data
    HAS_PYG = True
except ImportError:
    log.warning("torch_geometric not installed — using fallback GNN with torch only")


# ─── PyG-based Models ─────────────────────────────────────────────────────────
if HAS_PYG:
    class GraphSAGEModel(nn.Module):
        def __init__(self, in_channels, hidden_channels, out_channels, num_layers=2, dropout=0.3):
            super().__init__()
            self.convs = nn.ModuleList()
            self.convs.append(SAGEConv(in_channels, hidden_channels))
            for _ in range(num_layers - 2):
                self.convs.append(SAGEConv(hidden_channels, hidden_channels))
            self.convs.append(SAGEConv(hidden_channels, out_channels))
            self.dropout = dropout

        def forward(self, x, edge_index):
            for i, conv in enumerate(self.convs[:-1]):
                x = conv(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
            x = self.convs[-1](x, edge_index)
            return x

    class GATModel(nn.Module):
        def __init__(self, in_channels, hidden_channels, out_channels, num_layers=2, heads=4, dropout=0.3):
            super().__init__()
            self.convs = nn.ModuleList()
            self.convs.append(GATConv(in_channels, hidden_channels, heads=heads, dropout=dropout))
            for _ in range(num_layers - 2):
                self.convs.append(GATConv(hidden_channels * heads, hidden_channels, heads=heads, dropout=dropout))
            self.convs.append(GATConv(hidden_channels * heads, out_channels, heads=1, concat=False, dropout=dropout))
            self.dropout = dropout

        def forward(self, x, edge_index):
            for i, conv in enumerate(self.convs[:-1]):
                x = conv(x, edge_index)
                x = F.elu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
            x = self.convs[-1](x, edge_index)
            return x

    class GCNModel(nn.Module):
        def __init__(self, in_channels, hidden_channels, out_channels, num_layers=2, dropout=0.3):
            super().__init__()
            self.convs = nn.ModuleList()
            self.convs.append(GCNConv(in_channels, hidden_channels))
            for _ in range(num_layers - 2):
                self.convs.append(GCNConv(hidden_channels, hidden_channels))
            self.convs.append(GCNConv(hidden_channels, out_channels))
            self.dropout = dropout

        def forward(self, x, edge_index):
            for i, conv in enumerate(self.convs[:-1]):
                x = conv(x, edge_index)
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
            x = self.convs[-1](x, edge_index)
            return x


# ─── Fallback MLP-based "GNN" ─────────────────────────────────────────────────
class FallbackGNN(nn.Module):
    """Simple MLP used when PyG is not available."""
    def __init__(self, in_channels, hidden_channels, out_channels, dropout=0.3):
        super().__init__()
        self.fc1 = nn.Linear(in_channels, hidden_channels)
        self.fc2 = nn.Linear(hidden_channels, hidden_channels)
        self.fc3 = nn.Linear(hidden_channels, out_channels)
        self.dropout = dropout

    def forward(self, x, edge_index=None):
        x = F.relu(self.fc1(x))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = F.relu(self.fc2(x))
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.fc3(x)
        return x


def train_gnn(data, num_classes: int, model_type: str = "graphsage") -> dict:
    """
    Train a GNN model on graph data.

    Args:
        data: PyG Data object or dict with x, edge_index, y
        num_classes: number of attack classes
        model_type: 'graphsage', 'gat', or 'gcn'

    Returns:
        dict with model, metrics, losses
    """
    params = GNN_PARAMS
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info(f"🔥 Training GNN ({model_type}) on {device}...")

    # Extract tensors
    if isinstance(data, dict):
        x = data["x"].to(device)
        edge_index = data["edge_index"].to(device)
        y = data["y"].to(device)
    else:
        x = data.x.to(device)
        edge_index = data.edge_index.to(device)
        y = data.y.to(device)

    in_channels = x.shape[1]
    n_nodes = x.shape[0]

    # Train/val/test masks (60/20/20)
    perm = torch.randperm(n_nodes)
    n_train = int(0.6 * n_nodes)
    n_val = int(0.2 * n_nodes)
    train_mask = torch.zeros(n_nodes, dtype=torch.bool)
    val_mask = torch.zeros(n_nodes, dtype=torch.bool)
    test_mask = torch.zeros(n_nodes, dtype=torch.bool)
    train_mask[perm[:n_train]] = True
    val_mask[perm[n_train:n_train + n_val]] = True
    test_mask[perm[n_train + n_val:]] = True

    # Build model
    if HAS_PYG:
        if model_type == "graphsage":
            model = GraphSAGEModel(in_channels, params["hidden_channels"], num_classes,
                                   params["num_layers"], params["dropout"])
        elif model_type == "gat":
            model = GATModel(in_channels, params["hidden_channels"], num_classes,
                            params["num_layers"], dropout=params["dropout"])
        else:
            model = GCNModel(in_channels, params["hidden_channels"], num_classes,
                            params["num_layers"], params["dropout"])
    else:
        model = FallbackGNN(in_channels, params["hidden_channels"], num_classes, params["dropout"])

    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=params["lr"], weight_decay=5e-4)

    # Training loop
    best_val_acc = 0
    patience_counter = 0
    train_losses = []
    val_accs = []

    for epoch in range(params["epochs"]):
        model.train()
        optimizer.zero_grad()
        out = model(x, edge_index)
        loss = F.cross_entropy(out[train_mask], y[train_mask])
        loss.backward()
        optimizer.step()
        train_losses.append(loss.item())

        # Validation
        model.eval()
        with torch.no_grad():
            out = model(x, edge_index)
            pred = out[val_mask].argmax(dim=1)
            val_acc = (pred == y[val_mask]).float().mean().item()
            val_accs.append(val_acc)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1

        if patience_counter >= params["patience"]:
            log.info(f"  Early stopping at epoch {epoch+1}")
            break

        if (epoch + 1) % 20 == 0:
            log.info(f"  Epoch {epoch+1}: loss={loss.item():.4f}, val_acc={val_acc:.4f}")

    # Load best model and evaluate on test
    model.load_state_dict(best_state)
    model.eval()
    with torch.no_grad():
        out = model(x, edge_index)
        test_pred = out[test_mask].argmax(dim=1)
        test_acc = (test_pred == y[test_mask]).float().mean().item()

        # Node risk scores (probability of being attack)
        probs = F.softmax(out, dim=1)
        # Risk = 1 - P(normal), scaled to 0-100
        normal_idx = 0  # assuming Normal is class 0
        risk_scores = (1 - probs[:, normal_idx]) * 100
        risk_scores = risk_scores.cpu().numpy()

    log.info(f"  Test accuracy: {test_acc:.4f}")
    log.info(f"  Best val accuracy: {best_val_acc:.4f}")

    # Save
    model_path = SAVED_MODELS_DIR / f"gnn_{model_type}.pt"
    torch.save(model.state_dict(), model_path)
    log.info(f"  Saved to {model_path}")

    return {
        "model": model,
        "test_acc": test_acc,
        "best_val_acc": best_val_acc,
        "risk_scores": risk_scores,
        "train_losses": train_losses,
        "val_accs": val_accs,
        "model_type": model_type,
    }


def train_all_gnns(data, num_classes: int) -> dict:
    """Train all 3 GNN architectures and compare."""
    results = {}
    for model_type in ["graphsage", "gat", "gcn"]:
        log.info(f"\n{'='*50}")
        with Timer(f"GNN-{model_type}"):
            try:
                res = train_gnn(data, num_classes, model_type)
                results[model_type] = res
            except Exception as e:
                log.error(f"  {model_type} failed: {e}")

    if results:
        best = max(results, key=lambda k: results[k]["test_acc"])
        log.info(f"\n🏆 Best GNN: {best} (acc={results[best]['test_acc']:.4f})")
        return {"results": results, "best": best}
    return {"results": {}, "best": None}
