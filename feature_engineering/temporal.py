"""
Temporal feature extraction: time deltas, sliding windows, temporal patterns.
"""
import pandas as pd
import numpy as np
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def extract_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract temporal features from timestamps and flow ordering.
    Works for both TrafficLabelling (has Timestamp) and MSCAD (no Timestamp).
    """
    log.info("⏰ Extracting temporal features...")

    # If timestamps exist, extract time components
    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], format="mixed", dayfirst=True, errors="coerce")
        df["Hour"] = df["Timestamp"].dt.hour
        df["DayOfWeek"] = df["Timestamp"].dt.dayofweek
        df["IsWeekend"] = (df["DayOfWeek"] >= 5).astype(int)
        df["IsNight"] = ((df["Hour"] < 6) | (df["Hour"] > 22)).astype(int)

        # Time since previous event
        df = df.sort_values("Timestamp").reset_index(drop=True)
        df["TimeDelta"] = df["Timestamp"].diff().dt.total_seconds().fillna(0)
        df["TimeDelta"] = df["TimeDelta"].clip(lower=0, upper=3600)  # cap at 1h

        log.info("  Extracted: Hour, DayOfWeek, IsWeekend, IsNight, TimeDelta")

    # Flow-order based features (works for all datasets)
    flow_dur_col = None
    for c in df.columns:
        if "flow_duration" in c.lower() or c == "Flow_Duration":
            flow_dur_col = c
            break

    if flow_dur_col:
        # Rolling window statistics over flow sequence
        df["FlowDur_RollingMean_10"] = df[flow_dur_col].rolling(window=10, min_periods=1).mean()
        df["FlowDur_RollingStd_10"] = df[flow_dur_col].rolling(window=10, min_periods=1).std().fillna(0)
        df["FlowDur_RollingMax_10"] = df[flow_dur_col].rolling(window=10, min_periods=1).max()

        # Rate of change
        df["FlowDur_Diff"] = df[flow_dur_col].diff().fillna(0)
        df["FlowDur_PctChange"] = df[flow_dur_col].pct_change().fillna(0).clip(-10, 10)

        log.info("  Extracted: Rolling flow duration stats, rate of change")

    return df


def create_sequences(
    X: np.ndarray,
    y: np.ndarray,
    seq_length: int = 20
) -> tuple:
    """
    Create overlapping sequences for temporal models (LSTM/Transformer).

    Args:
        X: feature matrix (n_samples, n_features)
        y: labels (n_samples,)
        seq_length: number of timesteps per sequence

    Returns:
        (X_seq, y_seq) where X_seq has shape (n_sequences, seq_length, n_features)
    """
    log.info(f"  Creating sequences: seq_length={seq_length}")
    sequences = []
    targets = []

    for i in range(len(X) - seq_length):
        sequences.append(X[i:i + seq_length])
        targets.append(y[i + seq_length])  # predict next label

    X_seq = np.array(sequences)
    y_seq = np.array(targets)
    log.info(f"  Sequences: {X_seq.shape}, Targets: {y_seq.shape}")
    return X_seq, y_seq
