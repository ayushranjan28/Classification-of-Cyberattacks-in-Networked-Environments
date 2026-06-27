import sys
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import warnings

warnings.filterwarnings("ignore")

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SAVED_MODELS_DIR
from utils.logger import get_logger
from preprocessing.normalizer import normalize_features
from live_capture.database import insert_flow

log = get_logger(__name__)

class LiveInferenceEngine:
    def __init__(self):
        log.info("Loading ML models for live inference...")
        try:
            # 1. Load pipeline (Scaler + Features + Encoder)
            self.pipeline = joblib.load(SAVED_MODELS_DIR / "preprocessing_pipeline.joblib")
            self.feature_cols = self.pipeline.feature_cols
            
            # 2. Load best classifier
            self.classifier = joblib.load(SAVED_MODELS_DIR / "best_classifier.joblib")
            
            # 3. Load isolation forest (Autoencoder anomaly detection fallback)
            self.iso_forest = joblib.load(SAVED_MODELS_DIR / "isolation_forest.joblib")
            
            # 4. Load ensemble scorer
            self.ensemble = joblib.load(SAVED_MODELS_DIR / "ensemble_scorer.joblib")
            
            log.info("Live Inference Engine successfully loaded all models.")
        except Exception as e:
            log.error(f"Failed to load models: {e}")
            raise e

    def score_flow(self, flow_dict: dict, src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str):
        """
        Process a single flow dictionary from cicflowmeter.
        Normalizes the features, predicts the attack, and calculates risk.
        """
        # Create DataFrame from single row
        df = pd.DataFrame([flow_dict])
        
        # Ensure all feature columns exist, fill missing with 0
        for col in self.feature_cols:
            if col not in df.columns:
                df[col] = 0.0
                
        # Order columns identically to training
        X = df[self.feature_cols].copy()
        X = X.fillna(0)
        
        # Normalize
        X_norm, _ = normalize_features(X, self.feature_cols, method="standard", scaler=self.pipeline.scaler)
        
        # 1. Classifier Prediction
        class_idx = self.classifier.predict(X_norm)[0]
        class_probs = self.classifier.predict_proba(X_norm)[0]
        confidence = float(class_probs[class_idx])
        predicted_attack = self.pipeline.encoder.get_label_name(class_idx)
        
        # 2. Anomaly Score (Isolation Forest)
        iso_score = self.iso_forest.score_samples(X_norm)[0]
        # score_samples returns negative values; more negative = more anomalous
        # Typical range is roughly -0.7 (normal) to -1.0 (anomaly)
        # Convert to 0-1 scale: clamp to [-1, -0.3] then map to [0, 1]
        anomaly_01 = float(np.clip((-iso_score - 0.3) / 0.7, 0.0, 1.0))
        
        # 3. Compute risk score directly (simplified for single-flow live inference)
        # The classifier is the most reliable signal for attack type
        normal_idx = self.pipeline.encoder.label_map.get("Normal", 0)
        prob_attack = float(1.0 - class_probs[normal_idx])
        
        # Weighted combination: classifier is primary, anomaly is secondary
        # Use fixed weights: 70% classifier, 30% anomaly detector
        risk_score = (0.70 * prob_attack + 0.30 * anomaly_01) * 100.0
        risk_score = float(np.clip(risk_score, 0, 100))
        
        # Categorize risk
        risk_label = self.ensemble.categorize_risk(np.array([risk_score]))[0]
        
        # Log to database
        insert_flow(
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            risk_score=risk_score,
            risk_label=risk_label,
            predicted_attack=predicted_attack,
            confidence=confidence,
            features=flow_dict
        )
        
        return {
            "predicted_attack": predicted_attack,
            "confidence": confidence,
            "risk_score": risk_score,
            "risk_label": risk_label
        }

