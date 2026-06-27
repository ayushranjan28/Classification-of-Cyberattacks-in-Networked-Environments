"""
Statistical feature engineering: connection rates, entropy, burst detection.
"""
import pandas as pd
import numpy as np
from scipy import stats
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import get_logger

log = get_logger(__name__)


def compute_packet_entropy(df: pd.DataFrame) -> pd.DataFrame:
    """Compute Shannon entropy of packet length distribution per flow."""
    pkt_cols = [c for c in df.columns if "Pkt_Len" in c or "Pkt_Size" in c]
    if pkt_cols:
        pkt_data = df[pkt_cols].values
        # Normalize per row to get distribution
        row_sums = pkt_data.sum(axis=1, keepdims=True)
        row_sums[row_sums == 0] = 1
        probs = np.abs(pkt_data) / row_sums
        probs[probs == 0] = 1e-10
        df["Pkt_Entropy"] = -np.sum(probs * np.log2(probs), axis=1)
        log.info("  Computed packet entropy")
    return df


def compute_flow_rates(df: pd.DataFrame) -> pd.DataFrame:
    """Compute rate-based features from flow statistics."""
    flow_dur_col = None
    for c in df.columns:
        if "flow_duration" in c.lower() or c == "Flow_Duration":
            flow_dur_col = c
            break

    if flow_dur_col:
        duration = df[flow_dur_col].replace(0, 1)  # avoid division by zero

        # Bytes per microsecond → bytes per second
        fwd_bytes_col = next((c for c in df.columns if "TotLen_Fwd" in c or "Subflow_Fwd_Byts" in c), None)
        bwd_bytes_col = next((c for c in df.columns if "TotLen_Bwd" in c or "Subflow_Bwd_Byts" in c), None)
        fwd_pkts_col = next((c for c in df.columns if "Tot_Fwd_Pkts" in c or "Subflow_Fwd_Pkts" in c), None)
        bwd_pkts_col = next((c for c in df.columns if "Tot_Bwd_Pkts" in c or "Subflow_Bwd_Pkts" in c), None)

        if fwd_bytes_col and bwd_bytes_col:
            total_bytes = df[fwd_bytes_col] + df[bwd_bytes_col]
            df["Avg_Bytes_Per_Sec"] = total_bytes / duration * 1e6
            df["Bytes_Ratio"] = df[fwd_bytes_col] / (df[bwd_bytes_col] + 1)
            log.info("  Computed byte rate features")

        if fwd_pkts_col and bwd_pkts_col:
            total_pkts = df[fwd_pkts_col] + df[bwd_pkts_col]
            df["Connection_Rate"] = total_pkts / duration * 1e6
            df["Pkts_Ratio"] = df[fwd_pkts_col] / (df[bwd_pkts_col] + 1)
            log.info("  Computed packet rate features")

    return df


def compute_burst_indicators(df: pd.DataFrame) -> pd.DataFrame:
    """Detect burst traffic patterns using statistical methods."""
    rate_cols = [c for c in df.columns if "Pkts/s" in c or "Byts/s" in c or "Flow_Pkts/s" in c]
    for col in rate_cols:
        if col in df.columns:
            # Z-score based burst detection
            mean_rate = df[col].mean()
            std_rate = df[col].std()
            if std_rate > 0:
                df[f"{col}_ZScore"] = (df[col] - mean_rate) / std_rate
                df[f"{col}_IsBurst"] = (df[f"{col}_ZScore"].abs() > 2).astype(int)

    if rate_cols:
        log.info(f"  Computed burst indicators for {len(rate_cols)} rate columns")
    return df


def compute_flag_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute aggregate flag-based features."""
    flag_cols = [c for c in df.columns if "Flag" in c and "Cnt" in c]
    if flag_cols:
        df["Total_Flags"] = df[flag_cols].sum(axis=1)
        # SYN without ACK ratio (potential scan indicator)
        syn_col = next((c for c in flag_cols if "SYN" in c), None)
        ack_col = next((c for c in flag_cols if "ACK" in c), None)
        if syn_col and ack_col:
            df["SYN_ACK_Ratio"] = df[syn_col] / (df[ack_col] + 1)
        log.info(f"  Computed flag features from {len(flag_cols)} columns")
    return df


def engineer_statistical_features(df: pd.DataFrame) -> pd.DataFrame:
    """Run all statistical feature engineering."""
    log.info("📐 Engineering statistical features...")
    n_before = len(df.columns)
    df = compute_packet_entropy(df)
    df = compute_flow_rates(df)
    df = compute_burst_indicators(df)
    df = compute_flag_features(df)
    n_new = len(df.columns) - n_before
    log.info(f"  Added {n_new} new features (total: {len(df.columns)})")
    return df
