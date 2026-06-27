"""
Model 3: Temporal prediction with LSTM and Transformer Encoder.
Predicts probability of future attack from sequential flow features.
"""
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset
import math
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import TEMPORAL_PARAMS, SAVED_MODELS_DIR
from utils.logger import get_logger
from utils.timer import Timer

log = get_logger(__name__)


class LSTMModel(nn.Module):
    """Bidirectional LSTM for temporal attack prediction."""
    def __init__(self, input_dim, hidden_dim, num_classes, num_layers=2, dropout=0.2):
        super().__init__()
        self.lstm = nn.LSTM(
            input_dim, hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0
        )
        self.fc1 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        # Take last timestep
        last_hidden = lstm_out[:, -1, :]
        out = F.relu(self.fc1(last_hidden))
        out = self.dropout(out)
        out = self.fc2(out)
        return out


class PositionalEncoding(nn.Module):
    """Sinusoidal positional encoding for Transformer."""
    def __init__(self, d_model, max_len=500, dropout=0.1):
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model))
        pe[:, 0::2] = torch.sin(position * div_term)
        if d_model % 2 == 1:
            pe[:, 1::2] = torch.cos(position * div_term[:-1])
        else:
            pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)
        self.register_buffer("pe", pe)

    def forward(self, x):
        x = x + self.pe[:, :x.size(1), :]
        return self.dropout(x)


class TransformerModel(nn.Module):
    """Transformer Encoder for temporal attack prediction."""
    def __init__(self, input_dim, hidden_dim, num_classes, num_heads=4, num_layers=2, dropout=0.2):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.pos_encoder = PositionalEncoding(hidden_dim, dropout=dropout)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim * 4,
            dropout=dropout,
            batch_first=True
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(hidden_dim, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        x = self.input_proj(x)
        x = self.pos_encoder(x)
        x = self.transformer(x)
        # Global average pooling
        x = x.mean(dim=1)
        x = self.dropout(x)
        x = self.fc(x)
        return x


def create_sequences(X, y, seq_length=20):
    """Create overlapping sequences for temporal modeling."""
    sequences, targets = [], []
    for i in range(len(X) - seq_length):
        sequences.append(X[i:i + seq_length])
        # Binary: is the next event an attack?
        targets.append(0 if y[i + seq_length] == 0 else 1)  # 0=Normal, else attack

    X_seq = np.array(sequences, dtype=np.float32)
    y_seq = np.array(targets, dtype=np.int64)
    return X_seq, y_seq


def train_temporal_model(
    X_train, y_train, X_val, y_val,
    model_type: str = "lstm",
    num_classes: int = 2
) -> dict:
    """
    Train an LSTM or Transformer model on sequential data.

    Args:
        X_train: (n_train, seq_len, n_features)
        y_train: (n_train,)
        model_type: 'lstm' or 'transformer'
    """
    params = TEMPORAL_PARAMS
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    log.info(f"⏰ Training {model_type.upper()} on {device}...")

    input_dim = X_train.shape[2]

    # Create dataloaders
    train_ds = TensorDataset(
        torch.tensor(X_train, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.long)
    )
    val_ds = TensorDataset(
        torch.tensor(X_val, dtype=torch.float32),
        torch.tensor(y_val, dtype=torch.long)
    )
    train_loader = DataLoader(train_ds, batch_size=params["batch_size"], shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=params["batch_size"])

    # Build model
    if model_type == "lstm":
        model = LSTMModel(input_dim, params["hidden_dim"], num_classes,
                         params["num_layers"], params["dropout"])
    else:
        model = TransformerModel(input_dim, params["hidden_dim"], num_classes,
                                params["num_heads"], params["num_layers"], params["dropout"])

    model = model.to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=params["lr"])
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=5, factor=0.5)

    best_val_acc = 0
    patience_counter = 0
    train_losses, val_accs = [], []

    for epoch in range(params["epochs"]):
        model.train()
        epoch_loss = 0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            out = model(X_batch)
            loss = F.cross_entropy(out, y_batch)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / len(train_loader)
        train_losses.append(avg_loss)

        # Validation
        model.eval()
        correct, total = 0, 0
        all_probs = []
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                out = model(X_batch)
                pred = out.argmax(dim=1)
                correct += (pred == y_batch).sum().item()
                total += len(y_batch)
                all_probs.append(F.softmax(out, dim=1).cpu())

        val_acc = correct / total
        val_accs.append(val_acc)
        scheduler.step(avg_loss)

        if val_acc > best_val_acc:
            best_val_acc = val_acc
            patience_counter = 0
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1

        if patience_counter >= params["patience"]:
            log.info(f"  Early stopping at epoch {epoch+1}")
            break

        if (epoch + 1) % 10 == 0:
            log.info(f"  Epoch {epoch+1}: loss={avg_loss:.4f}, val_acc={val_acc:.4f}")

    # Restore best
    model.load_state_dict(best_state)
    log.info(f"  Best val accuracy: {best_val_acc:.4f}")

    # Save
    model_path = SAVED_MODELS_DIR / f"temporal_{model_type}.pt"
    torch.save(model.state_dict(), model_path)
    # Save model config for re-loading
    joblib.dump({
        "model_type": model_type, "input_dim": input_dim,
        "hidden_dim": params["hidden_dim"], "num_classes": num_classes,
        "num_layers": params["num_layers"], "num_heads": params["num_heads"],
        "dropout": params["dropout"]
    }, SAVED_MODELS_DIR / f"temporal_{model_type}_config.joblib")

    return {
        "model": model,
        "best_val_acc": best_val_acc,
        "train_losses": train_losses,
        "val_accs": val_accs,
        "model_type": model_type,
    }


def train_all_temporal(X_train_seq, y_train_seq, X_val_seq, y_val_seq, num_classes=2) -> dict:
    """Train both LSTM and Transformer, compare."""
    results = {}
    for model_type in ["lstm", "transformer"]:
        with Timer(f"Temporal-{model_type}"):
            try:
                res = train_temporal_model(
                    X_train_seq, y_train_seq, X_val_seq, y_val_seq,
                    model_type=model_type, num_classes=num_classes
                )
                results[model_type] = res
            except Exception as e:
                log.error(f"  {model_type} failed: {e}")
                import traceback
                traceback.print_exc()

    if results:
        best = max(results, key=lambda k: results[k]["best_val_acc"])
        log.info(f"🏆 Best temporal model: {best} (acc={results[best]['best_val_acc']:.4f})")
    else:
        best = None
    return {"results": results, "best": best}
