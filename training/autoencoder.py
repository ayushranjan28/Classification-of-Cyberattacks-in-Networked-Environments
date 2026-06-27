"""
Model 4: Autoencoder for unknown/zero-day attack detection.
Trained only on benign traffic; high reconstruction error = anomaly.
"""
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import AUTOENCODER_PARAMS, SAVED_MODELS_DIR
from utils.logger import get_logger
from utils.timer import Timer

log = get_logger(__name__)


class Autoencoder(nn.Module):
    """Symmetric deep autoencoder for anomaly detection."""
    def __init__(self, input_dim, hidden_dims=None, encoding_dim=32):
        super().__init__()
        hidden_dims = hidden_dims or [128, 64]

        # Encoder
        encoder_layers = []
        prev_dim = input_dim
        for h_dim in hidden_dims:
            encoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
            ])
            prev_dim = h_dim
        encoder_layers.append(nn.Linear(prev_dim, encoding_dim))
        self.encoder = nn.Sequential(*encoder_layers)

        # Decoder (mirror)
        decoder_layers = []
        prev_dim = encoding_dim
        for h_dim in reversed(hidden_dims):
            decoder_layers.extend([
                nn.Linear(prev_dim, h_dim),
                nn.BatchNorm1d(h_dim),
                nn.ReLU(),
                nn.Dropout(0.2),
            ])
            prev_dim = h_dim
        decoder_layers.append(nn.Linear(prev_dim, input_dim))
        self.decoder = nn.Sequential(*decoder_layers)

    def forward(self, x):
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded

    def encode(self, x):
        return self.encoder(x)


def train_autoencoder(X_benign_train, X_benign_val, input_dim: int) -> dict:
    """
    Train autoencoder only on benign traffic.

    Args:
        X_benign_train: benign training features (numpy)
        X_benign_val: benign validation features (numpy)
        input_dim: number of features
    """
    params = AUTOENCODER_PARAMS
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info(f"🔍 Training Autoencoder on {device} (benign samples: {len(X_benign_train)})...")

    train_ds = TensorDataset(torch.tensor(X_benign_train, dtype=torch.float32))
    val_ds = TensorDataset(torch.tensor(X_benign_val, dtype=torch.float32))
    train_loader = DataLoader(train_ds, batch_size=params["batch_size"], shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=params["batch_size"])

    model = Autoencoder(input_dim, params["hidden_dims"], params["encoding_dim"]).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=params["lr"])

    best_val_loss = float("inf")
    patience_counter = 0
    train_losses, val_losses = [], []

    for epoch in range(params["epochs"]):
        model.train()
        epoch_loss = 0
        for (X_batch,) in train_loader:
            X_batch = X_batch.to(device)
            optimizer.zero_grad()
            reconstructed = model(X_batch)
            loss = F.mse_loss(reconstructed, X_batch)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()

        avg_train = epoch_loss / len(train_loader)
        train_losses.append(avg_train)

        # Validation
        model.eval()
        val_loss = 0
        with torch.no_grad():
            for (X_batch,) in val_loader:
                X_batch = X_batch.to(device)
                out = model(X_batch)
                val_loss += F.mse_loss(out, X_batch).item()
        avg_val = val_loss / len(val_loader)
        val_losses.append(avg_val)

        if avg_val < best_val_loss:
            best_val_loss = avg_val
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1

        if patience_counter >= params["patience"]:
            log.info(f"  Early stopping at epoch {epoch+1}")
            break

        if (epoch + 1) % 10 == 0:
            log.info(f"  Epoch {epoch+1}: train_loss={avg_train:.6f}, val_loss={avg_val:.6f}")

    model.load_state_dict(best_state)
    log.info(f"  Best val loss: {best_val_loss:.6f}")

    # Save
    model_path = SAVED_MODELS_DIR / "autoencoder.pt"
    torch.save(model.state_dict(), model_path)
    joblib.dump({"input_dim": input_dim, "hidden_dims": params["hidden_dims"],
                 "encoding_dim": params["encoding_dim"]}, SAVED_MODELS_DIR / "autoencoder_config.joblib")

    return {
        "model": model,
        "best_val_loss": best_val_loss,
        "train_losses": train_losses,
        "val_losses": val_losses,
    }


def compute_anomaly_scores(model, X, device=None) -> np.ndarray:
    """Compute reconstruction error as anomaly score."""
    device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = model.to(device)
    model.eval()
    X_tensor = torch.tensor(X, dtype=torch.float32).to(device)

    with torch.no_grad():
        reconstructed = model(X_tensor)
        # Per-sample MSE
        errors = ((X_tensor - reconstructed) ** 2).mean(dim=1).cpu().numpy()

    return errors


def compute_threshold(benign_errors: np.ndarray, percentile: float = None) -> float:
    """Compute anomaly threshold from benign reconstruction errors."""
    percentile = percentile or AUTOENCODER_PARAMS["anomaly_percentile"]
    threshold = np.percentile(benign_errors, percentile)
    log.info(f"  Anomaly threshold ({percentile}th percentile): {threshold:.6f}")
    return threshold


def train_isolation_forest(X_benign: np.ndarray) -> IsolationForest:
    """Train Isolation Forest for comparison."""
    log.info("🌲 Training Isolation Forest...")
    iso_forest = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_benign)
    joblib.dump(iso_forest, SAVED_MODELS_DIR / "isolation_forest.joblib")
    log.info("  Saved Isolation Forest")
    return iso_forest


def detect_anomalies(
    model, X_all, y_all, X_benign,
    threshold: float = None,
    encoder=None
) -> dict:
    """
    Run anomaly detection on all data.

    Returns:
        dict with anomaly_scores, predictions, metrics
    """
    log.info("🔍 Running anomaly detection...")

    # Autoencoder detection
    all_errors = compute_anomaly_scores(model, X_all)
    benign_errors = compute_anomaly_scores(model, X_benign)

    if threshold is None:
        threshold = compute_threshold(benign_errors)

    ae_predictions = (all_errors > threshold).astype(int)  # 1 = anomaly

    # Ground truth: 0 = normal, 1 = attack
    y_binary = (y_all != 0).astype(int) if isinstance(y_all[0], (int, np.integer)) else \
               (y_all != "Normal").astype(int)

    from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
    ae_metrics = {
        "accuracy": accuracy_score(y_binary, ae_predictions),
        "precision": precision_score(y_binary, ae_predictions, zero_division=0),
        "recall": recall_score(y_binary, ae_predictions, zero_division=0),
        "f1": f1_score(y_binary, ae_predictions, zero_division=0),
        "threshold": threshold,
    }
    log.info(f"  Autoencoder — Acc: {ae_metrics['accuracy']:.4f}, "
             f"Prec: {ae_metrics['precision']:.4f}, Rec: {ae_metrics['recall']:.4f}, "
             f"F1: {ae_metrics['f1']:.4f}")

    # Isolation Forest detection
    try:
        iso_forest = train_isolation_forest(X_benign)
        iso_preds = iso_forest.predict(X_all)
        iso_preds = (iso_preds == -1).astype(int)  # -1 = anomaly
        iso_metrics = {
            "accuracy": accuracy_score(y_binary, iso_preds),
            "precision": precision_score(y_binary, iso_preds, zero_division=0),
            "recall": recall_score(y_binary, iso_preds, zero_division=0),
            "f1": f1_score(y_binary, iso_preds, zero_division=0),
        }
        log.info(f"  Isolation Forest — Acc: {iso_metrics['accuracy']:.4f}, "
                 f"F1: {iso_metrics['f1']:.4f}")
    except Exception as e:
        log.warning(f"  Isolation Forest failed: {e}")
        iso_metrics = {}

    return {
        "anomaly_scores": all_errors,
        "ae_predictions": ae_predictions,
        "ae_metrics": ae_metrics,
        "iso_metrics": iso_metrics,
        "threshold": threshold,
    }
