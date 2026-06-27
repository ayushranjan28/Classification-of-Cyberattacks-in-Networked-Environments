"""
Label and feature encoding for attack classification.
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SAVED_MODELS_DIR
from utils.logger import get_logger

log = get_logger(__name__)


class AttackEncoder:
    """Encodes attack labels to integers and provides reverse mapping."""

    def __init__(self):
        self.label_encoder = LabelEncoder()
        self.label_map = {}
        self.inverse_map = {}

    def fit(self, labels: pd.Series) -> "AttackEncoder":
        """Fit the encoder on attack labels."""
        self.label_encoder.fit(labels)
        self.label_map = {
            label: idx for idx, label in enumerate(self.label_encoder.classes_)
        }
        self.inverse_map = {v: k for k, v in self.label_map.items()}
        log.info(f"  Label mapping: {self.label_map}")
        return self

    def transform(self, labels: pd.Series) -> np.ndarray:
        """Transform labels to integers."""
        return self.label_encoder.transform(labels)

    def inverse_transform(self, encoded: np.ndarray) -> np.ndarray:
        """Convert integer labels back to strings."""
        return self.label_encoder.inverse_transform(encoded)

    def get_label_name(self, idx: int) -> str:
        """Get label name from integer index."""
        return self.inverse_map.get(idx, f"Unknown_{idx}")

    @property
    def num_classes(self) -> int:
        return len(self.label_map)

    @property
    def classes(self) -> list:
        return list(self.label_encoder.classes_)

    def save(self, path: Path = None):
        path = path or SAVED_MODELS_DIR / "label_encoder.joblib"
        joblib.dump(self, path)
        log.info(f"  Saved encoder to {path}")

    @staticmethod
    def load(path: Path = None) -> "AttackEncoder":
        path = path or SAVED_MODELS_DIR / "label_encoder.joblib"
        return joblib.load(path)


def encode_labels(df: pd.DataFrame, label_col: str = "Label") -> tuple:
    """
    Encode the label column and return (df_with_encoded_labels, encoder).
    Original labels stored in 'Label_Original'.
    """
    log.info("🏷  Encoding labels...")
    encoder = AttackEncoder()
    encoder.fit(df[label_col])
    df["Label_Original"] = df[label_col].copy()
    df[label_col] = encoder.transform(df[label_col])
    log.info(f"  Encoded {encoder.num_classes} classes")
    return df, encoder
