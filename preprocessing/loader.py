"""
Dataset loader for MSCAD, MachineLearningCVE, and TrafficLabelling datasets.
Handles encoding issues, column name normalization, and multi-file concatenation.
"""
import pandas as pd
import numpy as np
from pathlib import Path
from tqdm import tqdm
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    MSCAD_CSV, ML_CVE_DIR, TRAFFIC_DIR, CICIDS_LABEL_MAP, SAMPLE_RATIO
)
from utils.logger import get_logger

log = get_logger(__name__)


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip quotes, whitespace, and standardize column names."""
    df.columns = (
        df.columns
        .str.strip()
        .str.strip("'\"")
        .str.strip()
        .str.replace(r"\s+", "_", regex=True)
    )
    return df


def load_mscad(sample_ratio: float = None) -> pd.DataFrame:
    """
    Load the MSCAD dataset (primary dataset).
    Columns use single-quoted names which are stripped.
    """
    sample_ratio = sample_ratio or SAMPLE_RATIO
    log.info(f"Loading MSCAD dataset from {MSCAD_CSV}")
    df = pd.read_csv(MSCAD_CSV, quotechar="'", low_memory=False)
    df = _normalize_columns(df)
    log.info(f"  Raw shape: {df.shape}")
    log.info(f"  Labels: {df['Label'].value_counts().to_dict()}")
    if sample_ratio < 1.0:
        df = df.sample(frac=sample_ratio, random_state=42).reset_index(drop=True)
        log.info(f"  Sampled to {len(df)} rows ({sample_ratio*100:.0f}%)")
    return df


def load_ml_cve(sample_ratio: float = None) -> pd.DataFrame:
    """
    Load all MachineLearningCVE CSV files and concatenate.
    Maps CIC-IDS2017 labels to MSCAD-compatible labels.
    """
    sample_ratio = sample_ratio or SAMPLE_RATIO
    csv_files = sorted(ML_CVE_DIR.glob("*.csv"))
    log.info(f"Loading MachineLearningCVE: {len(csv_files)} files")
    frames = []
    for f in tqdm(csv_files, desc="Loading ML-CVE"):
        chunk = pd.read_csv(f, low_memory=False, encoding="utf-8")
        chunk = _normalize_columns(chunk)
        frames.append(chunk)
    df = pd.concat(frames, ignore_index=True)
    # Normalize label column
    label_col = [c for c in df.columns if c.lower() == "label"][0]
    df.rename(columns={label_col: "Label"}, inplace=True)
    df["Label"] = df["Label"].str.strip()
    # Map to MSCAD labels
    df["Label"] = df["Label"].map(CICIDS_LABEL_MAP).fillna("Normal")
    log.info(f"  Combined shape: {df.shape}")
    log.info(f"  Mapped labels: {df['Label'].value_counts().to_dict()}")
    if sample_ratio < 1.0:
        df = df.sample(frac=sample_ratio, random_state=42).reset_index(drop=True)
        log.info(f"  Sampled to {len(df)} rows")
    return df


def load_traffic_labelling(sample_ratio: float = None) -> pd.DataFrame:
    """
    Load TrafficLabelling CSVs — preserves Flow ID, Source IP, Dest IP, Timestamp
    for graph construction.
    """
    sample_ratio = sample_ratio or SAMPLE_RATIO
    csv_files = sorted(TRAFFIC_DIR.glob("*.csv"))
    log.info(f"Loading TrafficLabelling: {len(csv_files)} files")
    frames = []
    for f in tqdm(csv_files, desc="Loading TrafficLabelling"):
        chunk = pd.read_csv(f, low_memory=False, encoding="latin-1")
        chunk = _normalize_columns(chunk)
        frames.append(chunk)
    df = pd.concat(frames, ignore_index=True)
    # Normalize label column
    label_col = [c for c in df.columns if c.lower() == "label"][0]
    df.rename(columns={label_col: "Label"}, inplace=True)
    df["Label"] = df["Label"].str.strip()
    log.info(f"  Combined shape: {df.shape}")
    log.info(f"  Labels: {df['Label'].value_counts().head(10).to_dict()}")
    if sample_ratio < 1.0:
        df = df.sample(frac=sample_ratio, random_state=42).reset_index(drop=True)
        log.info(f"  Sampled to {len(df)} rows")
    return df
