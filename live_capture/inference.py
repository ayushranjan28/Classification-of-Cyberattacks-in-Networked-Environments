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
        # IF returns 1 (normal) or -1 (anomaly), score_samples returns negative anomaly score
        iso_score = self.iso_forest.score_samples(X_norm)[0]
        # Convert iso_score (negative) to a positive anomaly measure
        anomaly_score = np.array([abs(iso_score)])
        
        # 3. Ensemble Risk Calculation
        # For classifier_probs, pass the attack probability (1 - P(Normal))
        normal_idx = self.pipeline.encoder.label_map.get("Normal", 0)
        prob_attack = np.array([1.0 - class_probs[normal_idx]])
        
        risk_score_arr = self.ensemble.compute_risk(
            classifier_probs=prob_attack,
            anomaly_scores=anomaly_score,
            gnn_risk=None,       # Skip graph for real-time single flows
            temporal_probs=None  # Skip temporal for single flows
        )
        risk_score = float(risk_score_arr[0])
        
        # Categorize risk
        risk_label = self.ensemble.categorize_risk(risk_score_arr)[0]
        
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
