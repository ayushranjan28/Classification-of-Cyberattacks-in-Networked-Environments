"""
Data cleaning: deduplication, missing values, inf handling, irrelevant column removal.
"""
import pandas as pd
import numpy as np
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    n_before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    n_removed = n_before - len(df)
    if n_removed > 0:
        log.info(f"  Removed {n_removed} duplicate rows ({n_removed/n_before*100:.1f}%)")
    return df


def handle_missing(df: pd.DataFrame, max_missing_ratio: float = 0.5) -> pd.DataFrame:
    """
    Handle missing values:
    - Drop columns with > max_missing_ratio missing
    - Impute remaining with median (numeric) or mode (categorical)
    """
    # Drop columns with too many missing values
    missing_ratio = df.isnull().mean()
    cols_to_drop = missing_ratio[missing_ratio > max_missing_ratio].index.tolist()
    if cols_to_drop:
        log.info(f"  Dropping {len(cols_to_drop)} columns with >{max_missing_ratio*100:.0f}% missing: {cols_to_drop}")
        df = df.drop(columns=cols_to_drop)

    # Impute remaining
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if df[col].isnull().any():
            median_val = df[col].median()
            df[col] = df[col].fillna(median_val)

    categorical_cols = df.select_dtypes(include=["object", "category"]).columns
    for col in categorical_cols:
        if col != "Label" and df[col].isnull().any():
            mode_val = df[col].mode().iloc[0] if len(df[col].mode()) > 0 else "unknown"
            df[col] = df[col].fillna(mode_val)

    remaining_missing = df.isnull().sum().sum()
    if remaining_missing > 0:
        log.warning(f"  {remaining_missing} missing values remain after imputation")
    else:
        log.info("  No missing values remain")
    return df


def handle_infinities(df: pd.DataFrame) -> pd.DataFrame:
    """Replace inf/-inf with column max/min of finite values."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    n_inf = 0
    for col in numeric_cols:
        mask_pos = np.isposinf(df[col])
        mask_neg = np.isneginf(df[col])
        count = mask_pos.sum() + mask_neg.sum()
        if count > 0:
            n_inf += count
            finite_vals = df[col][np.isfinite(df[col])]
            if len(finite_vals) > 0:
                df.loc[mask_pos, col] = finite_vals.max()
                df.loc[mask_neg, col] = finite_vals.min()
            else:
                df.loc[mask_pos, col] = 0
                df.loc[mask_neg, col] = 0
    if n_inf > 0:
        log.info(f"  Replaced {n_inf} infinite values")
    return df


def remove_constant_columns(df: pd.DataFrame, label_col: str = "Label") -> pd.DataFrame:
    """Remove columns with zero variance (constant value)."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    constant_cols = [col for col in numeric_cols if df[col].nunique() <= 1]
    if constant_cols:
        log.info(f"  Removing {len(constant_cols)} constant columns: {constant_cols[:5]}...")
        df = df.drop(columns=constant_cols)
    return df


def remove_irrelevant_columns(df: pd.DataFrame, drop_cols: list = None) -> pd.DataFrame:
    """Remove columns not useful for modeling (IDs, raw IPs, etc.)."""
    if drop_cols is None:
        drop_cols = ["Flow_ID", "Source_IP", "Destination_IP", "Timestamp",
                     "Src_IP", "Dst_IP", "Flow_ID"]
    existing = [c for c in drop_cols if c in df.columns]
    if existing:
        log.info(f"  Dropping irrelevant columns: {existing}")
        df = df.drop(columns=existing)
    return df


def clean_data(df: pd.DataFrame, drop_cols: list = None) -> pd.DataFrame:
    """Run full cleaning pipeline."""
    log.info("🧹 Starting data cleaning...")
    log.info(f"  Input shape: {df.shape}")
    df = remove_duplicates(df)
    df = handle_infinities(df)
    df = handle_missing(df)
    df = remove_irrelevant_columns(df, drop_cols)
    df = remove_constant_columns(df)
    log.info(f"  Output shape: {df.shape}")
    return df
