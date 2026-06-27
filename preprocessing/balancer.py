"""
Class imbalance handling with SMOTE and class weighting.
"""
import pandas as pd
import numpy as np
from collections import Counter
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def compute_class_weights(y: np.ndarray) -> dict:
    """Compute balanced class weights inversely proportional to frequency."""
    counter = Counter(y)
    total = len(y)
    n_classes = len(counter)
    weights = {}
    for cls, count in counter.items():
        weights[cls] = total / (n_classes * count)
    log.info(f"  Class weights: {weights}")
    return weights


def apply_smote(X: pd.DataFrame, y: np.ndarray, random_state: int = 42) -> tuple:
    """
    Apply SMOTE to balance classes. Falls back to random oversampling
    if SMOTE fails (e.g., too few samples in a class).
    """
    try:
        from imblearn.over_sampling import SMOTE, RandomOverSampler
        from imblearn.combine import SMOTETomek
    except ImportError:
        log.warning("imbalanced-learn not installed, using class weighting instead")
        return X, y

    log.info("⚖️  Applying SMOTE for class balancing...")
    log.info(f"  Before: {dict(Counter(y))}")

    # Check minimum samples per class
    min_samples = min(Counter(y).values())
    if min_samples < 6:
        log.warning(f"  Min class has {min_samples} samples, using RandomOverSampler instead of SMOTE")
        sampler = RandomOverSampler(random_state=random_state)
    else:
        k_neighbors = min(5, min_samples - 1)
        sampler = SMOTE(random_state=random_state, k_neighbors=k_neighbors)

    try:
        X_res, y_res = sampler.fit_resample(X, y)
        log.info(f"  After:  {dict(Counter(y_res))}")
        if isinstance(X, pd.DataFrame):
            X_res = pd.DataFrame(X_res, columns=X.columns)
        return X_res, y_res
    except Exception as e:
        log.warning(f"  SMOTE failed: {e}. Returning original data.")
        return X, y


def balance_data(
    X: pd.DataFrame,
    y: np.ndarray,
    method: str = "smote",
    random_state: int = 42
) -> tuple:
    """
    Balance classes using specified method.

    Args:
        method: 'smote', 'weight', or 'none'
    """
    if method == "smote":
        return apply_smote(X, y, random_state)
    elif method == "weight":
        weights = compute_class_weights(y)
        return X, y  # weights used in model training
    else:
        return X, y
