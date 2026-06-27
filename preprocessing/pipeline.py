"""
Full preprocessing pipeline orchestrator.
Chains: load → clean → encode → normalize → balance → split → save
"""
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    SAVED_MODELS_DIR, PREPROCESSED_DIR,
    TRAIN_RATIO, VAL_RATIO, TEST_RATIO, RANDOM_STATE, SAMPLE_RATIO
)
from preprocessing.loader import load_mscad, load_ml_cve
from preprocessing.cleaner import clean_data
from preprocessing.encoder import encode_labels, AttackEncoder
from preprocessing.normalizer import normalize_features, save_scaler
from preprocessing.balancer import balance_data, compute_class_weights
from utils.logger import get_logger
from utils.timer import Timer

log = get_logger(__name__)


class PreprocessingPipeline:
    """End-to-end preprocessing pipeline with save/load support."""

    def __init__(self):
        self.encoder = None
        self.scaler = None
        self.feature_cols = None
        self.class_weights = None

    def run(
        self,
        dataset: str = "mscad",
        balance_method: str = "weight",
        sample_ratio: float = None
    ) -> dict:
        """
        Run full preprocessing pipeline.

        Args:
            dataset: 'mscad' or 'mlcve'
            balance_method: 'smote', 'weight', or 'none'
            sample_ratio: fraction of data to use

        Returns:
            dict with X_train, X_val, X_test, y_train, y_val, y_test,
            encoder, scaler, feature_cols, class_weights
        """
        sample_ratio = sample_ratio or SAMPLE_RATIO

        # Step 1: Load
        with Timer("Data Loading"):
            if dataset == "mscad":
                df = load_mscad(sample_ratio)
            else:
                df = load_ml_cve(sample_ratio)

        # Step 2: Clean
        with Timer("Data Cleaning"):
            df = clean_data(df)

        # Step 3: Encode labels
        with Timer("Label Encoding"):
            df, self.encoder = encode_labels(df)

        # Step 4: Separate features and target
        label_col = "Label"
        drop_meta = ["Label_Original"]
        meta_cols = [c for c in drop_meta if c in df.columns]
        non_numeric = df.select_dtypes(exclude=[np.number]).columns.tolist()
        exclude = [label_col] + meta_cols + [c for c in non_numeric if c != label_col]

        self.feature_cols = [c for c in df.columns if c not in exclude]
        log.info(f"  Using {len(self.feature_cols)} features for modeling")

        X = df[self.feature_cols].copy()
        y = df[label_col].values

        # Step 5: Handle any remaining NaN
        X = X.fillna(0)

        # Check minimum class count for stratification
        min_class_count = np.bincount(y).min() if len(y) > 0 else 0
        use_stratify = y if min_class_count >= 2 else None
        if min_class_count < 2:
            log.warning("  Some classes have <2 samples, disabling stratified split for train/temp")
            
        # Step 6: Train/Val/Test split
        with Timer("Data Splitting"):
            X_train, X_temp, y_train, y_temp = train_test_split(
                X, y, test_size=(VAL_RATIO + TEST_RATIO),
                random_state=RANDOM_STATE, stratify=use_stratify
            )
            relative_test = TEST_RATIO / (VAL_RATIO + TEST_RATIO)
            min_temp_class = np.bincount(y_temp).min() if len(y_temp) > 0 else 0
            use_stratify_temp = y_temp if min_temp_class >= 2 else None
            if min_temp_class < 2:
                log.warning("  Some classes have <2 samples in temp set, disabling stratified split for val/test")
            
            X_val, X_test, y_val, y_test = train_test_split(
                X_temp, y_temp, test_size=relative_test,
                random_state=RANDOM_STATE, stratify=use_stratify_temp
            )
            log.info(f"  Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")

        # Step 7: Normalize
        with Timer("Feature Normalization"):
            X_train, self.scaler = normalize_features(X_train, self.feature_cols, method="standard")
            X_val, _ = normalize_features(X_val, self.feature_cols, method="standard", scaler=self.scaler)
            X_test, _ = normalize_features(X_test, self.feature_cols, method="standard", scaler=self.scaler)

        # Step 8: Balance training data
        with Timer("Class Balancing"):
            self.class_weights = compute_class_weights(y_train)
            if balance_method == "smote":
                X_train, y_train = balance_data(X_train, y_train, method="smote")

        # Step 9: Save pipeline artifacts
        with Timer("Saving Pipeline"):
            self._save(X_train, X_val, X_test, y_train, y_val, y_test)

        result = {
            "X_train": X_train, "X_val": X_val, "X_test": X_test,
            "y_train": y_train, "y_val": y_val, "y_test": y_test,
            "encoder": self.encoder,
            "scaler": self.scaler,
            "feature_cols": self.feature_cols,
            "class_weights": self.class_weights,
        }
        log.info("✅ Preprocessing complete!")
        return result

    def _save(self, X_train, X_val, X_test, y_train, y_val, y_test):
        """Save all pipeline artifacts."""
        # Save encoder and scaler
        self.encoder.save()
        save_scaler(self.scaler)

        # Save processed data
        joblib.dump({
            "X_train": X_train, "X_val": X_val, "X_test": X_test,
            "y_train": y_train, "y_val": y_val, "y_test": y_test,
            "feature_cols": self.feature_cols,
            "class_weights": self.class_weights,
        }, PREPROCESSED_DIR / "processed_data.joblib")

        # Save pipeline config
        joblib.dump(self, SAVED_MODELS_DIR / "preprocessing_pipeline.joblib")
        log.info(f"  Saved pipeline to {SAVED_MODELS_DIR}")

    @staticmethod
    def load_processed() -> dict:
        """Load previously processed data."""
        path = PREPROCESSED_DIR / "processed_data.joblib"
        log.info(f"Loading processed data from {path}")
        return joblib.load(path)


if __name__ == "__main__":
    pipeline = PreprocessingPipeline()
    result = pipeline.run(dataset="mscad", balance_method="weight")
    print(f"\nTrain shape: {result['X_train'].shape}")
    print(f"Val shape:   {result['X_val'].shape}")
    print(f"Test shape:  {result['X_test'].shape}")
    print(f"Classes:     {result['encoder'].classes}")
