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
            
            # 5. Load GNN, LSTM, and SHAP
            import torch
            from collections import deque
            from training.temporal_model import LSTMModel
            from config import TEMPORAL_PARAMS, GNN_PARAMS
            from training.gnn_model import HAS_PYG, FallbackGNN
            if HAS_PYG:
                from training.gnn_model import GraphSAGEModel
            from explainability.shap_explainer import ShapExplainer
            
            num_classes = len(self.pipeline.encoder.classes)
            
            # LSTM (trained for binary classification: 0=Normal, 1=Attack)
            self.lstm_model = LSTMModel(
                input_dim=len(self.feature_cols),
                hidden_dim=TEMPORAL_PARAMS["hidden_dim"],
                num_classes=2,
                num_layers=TEMPORAL_PARAMS["num_layers"],
                dropout=TEMPORAL_PARAMS["dropout"]
            )
            try:
                self.lstm_model.load_state_dict(torch.load(SAVED_MODELS_DIR / "temporal_lstm.pt"))
                self.lstm_loaded = True
            except Exception as e:
                log.error(f"Failed to load LSTM weights: {e}")
                self.lstm_loaded = False
            self.lstm_model.eval()
            self.flow_sequence = deque(maxlen=20)
            
            # GNN
            if HAS_PYG:
                self.gnn_model = GraphSAGEModel(len(self.feature_cols), GNN_PARAMS["hidden_channels"], num_classes)
            else:
                self.gnn_model = FallbackGNN(len(self.feature_cols), GNN_PARAMS["hidden_channels"], num_classes)
            try:
                self.gnn_model.load_state_dict(torch.load(SAVED_MODELS_DIR / "gnn_graphsage.pt"))
                self.gnn_loaded = True
            except Exception as e:
                log.warning(f"GNN weights not compatible (expected 17 graph features, got 66 flow features). GNN will be disabled.")
                self.gnn_loaded = False
            self.gnn_model.eval()
            
            # SHAP
            self.explainer = ShapExplainer(self.classifier, self.feature_cols)
            self.explainer.fit()
            
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
        
        # Confidence gate: if the classifier says "attack" but isn't sure enough,
        # treat it as Normal to avoid false positives on background traffic.
        MIN_ATTACK_CONFIDENCE = 0.55
        if predicted_attack != "Normal" and confidence < MIN_ATTACK_CONFIDENCE:
            # Fall back to Normal — the model isn't confident enough
            normal_idx = self.pipeline.encoder.label_map.get("Normal", 0)
            predicted_attack = "Normal"
            class_idx = normal_idx
            confidence = float(class_probs[normal_idx])
        
        # 2. Anomaly Score (Isolation Forest)
        iso_score = self.iso_forest.score_samples(X_norm)[0]
        anomaly_01 = float(np.clip((-iso_score - 0.3) / 0.7, 0.0, 1.0))
        
        import torch
        from training.gnn_model import HAS_PYG
        
        # LSTM Prediction
        X_tensor_1d = torch.tensor(X_norm.values[0], dtype=torch.float32)
        self.flow_sequence.append(X_tensor_1d)
        
        temporal_probs = None
        normal_idx = self.pipeline.encoder.label_map.get("Normal", 0)
        
        if len(self.flow_sequence) > 0 and getattr(self, 'lstm_loaded', False):
            seq = list(self.flow_sequence)
            while len(seq) < 20:
                seq.insert(0, torch.zeros_like(X_tensor_1d))
            seq_tensor = torch.stack(seq).unsqueeze(0)
            with torch.no_grad():
                out_lstm = self.lstm_model(seq_tensor)
                probs = torch.nn.functional.softmax(out_lstm, dim=1).numpy()[0]
                temporal_probs = np.array([probs[1]])  # Prob of Attack
        
        # GNN Prediction
        X_tensor_2d = torch.tensor(X_norm.values, dtype=torch.float32)
        gnn_risk = None
        if getattr(self, 'gnn_loaded', False):
            with torch.no_grad():
                if HAS_PYG:
                    empty_edge_index = torch.empty((2, 0), dtype=torch.long)
                    out_gnn = self.gnn_model(X_tensor_2d, empty_edge_index)
                else:
                    out_gnn = self.gnn_model(X_tensor_2d)
                probs = torch.nn.functional.softmax(out_gnn, dim=1).numpy()[0]
                gnn_risk = np.array([(1.0 - probs[normal_idx]) * 100.0])
            
        # 3. Compute risk score via Ensemble Scorer
        risk_score_arr = self.ensemble.compute_risk(
            classifier_probs=np.array([1.0 - class_probs[normal_idx]]),
            gnn_risk=gnn_risk,
            temporal_probs=temporal_probs,
            anomaly_scores=np.array([anomaly_01])
        )
        risk_score = float(risk_score_arr[0])
        
        # If risk score is too low for an attack, override to Normal
        if predicted_attack != "Normal" and risk_score < 35.0:
            predicted_attack = "Normal"
        
        # Categorize risk
        risk_label = self.ensemble.categorize_risk(np.array([risk_score]))[0]
        
        # SHAP Explanation
        try:
            shap_res = self.explainer.explain_single(X_norm)
            explanation = shap_res.get("explanation_text", "Explanation unavailable.")
        except Exception:
            explanation = "Explanation unavailable."
        
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
            explanation=explanation,
            features=flow_dict
        )
        
        return {
            "predicted_attack": predicted_attack,
            "confidence": confidence,
            "risk_score": risk_score,
            "risk_label": risk_label
        }

