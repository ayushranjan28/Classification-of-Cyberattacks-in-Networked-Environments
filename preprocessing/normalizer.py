"""
Feature normalization with StandardScaler and MinMaxScaler.
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SAVED_MODELS_DIR
from utils.logger import get_logger

log = get_logger(__name__)


def normalize_features(
    df: pd.DataFrame,
    feature_cols: list,
    method: str = "standard",
    scaler=None
) -> tuple:
    """
    Normalize numerical features.

    Args:
        df: DataFrame with features
        feature_cols: columns to normalize
        method: 'standard' (z-score) or 'minmax' (0-1)
        scaler: pre-fitted scaler (for val/test sets)

    Returns:
        (df_normalized, fitted_scaler)
    """
    log.info(f"📏 Normalizing {len(feature_cols)} features with {method} scaler")

    if scaler is None:
        scaler = StandardScaler() if method == "standard" else MinMaxScaler()
        df[feature_cols] = scaler.fit_transform(df[feature_cols].values)
        log.info("  Fitted new scaler")
    else:
        df[feature_cols] = scaler.transform(df[feature_cols].values)
        log.info("  Applied pre-fitted scaler")

    return df, scaler


def save_scaler(scaler, name: str = "feature_scaler"):
    """Save scaler to disk."""
    path = SAVED_MODELS_DIR / f"{name}.joblib"
    joblib.dump(scaler, path)
    log.info(f"  Saved scaler to {path}")


def load_scaler(name: str = "feature_scaler"):
    """Load scaler from disk."""
    path = SAVED_MODELS_DIR / f"{name}.joblib"
    return joblib.load(path)
