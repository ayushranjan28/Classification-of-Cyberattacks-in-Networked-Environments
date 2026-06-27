"""
Ensemble model: combines predictions from classifier, GNN, temporal, and autoencoder
into a final risk score (0-100) with categorical risk levels.
"""
import numpy as np
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ENSEMBLE_WEIGHTS, RISK_THRESHOLDS, SAVED_MODELS_DIR
from utils.logger import get_logger

log = get_logger(__name__)


class EnsembleRiskScorer:
    """
    Combines predictions from multiple models into a unified risk score.

    Risk = w1*classifier_prob + w2*gnn_risk + w3*temporal_prob + w4*anomaly_score
    Scaled to 0-100 with categories: Low/Medium/High/Critical
    """

    def __init__(self, weights: dict = None):
        self.weights = weights or ENSEMBLE_WEIGHTS.copy()
        self._normalize_weights()

    def _normalize_weights(self):
        total = sum(self.weights.values())
        for k in self.weights:
            self.weights[k] /= total

    def compute_risk(
        self,
        classifier_probs: np.ndarray = None,
        gnn_risk: np.ndarray = None,
        temporal_probs: np.ndarray = None,
        anomaly_scores: np.ndarray = None,
        n_samples: int = None
    ) -> np.ndarray:
        """
        Compute composite risk score for each sample.

        Each input should be a 1D array of shape (n_samples,) with values in [0, 1].
        Missing components get 0 weight.
        """
        if n_samples is None:
            for arr in [classifier_probs, gnn_risk, temporal_probs, anomaly_scores]:
                if arr is not None:
                    n_samples = len(arr)
                    break

        risk = np.zeros(n_samples)
        active_weight = 0

        if classifier_probs is not None:
            # Convert to attack probability (1 - P(normal))
            if classifier_probs.ndim == 2:
                attack_prob = 1 - classifier_probs[:, 0]  # assuming class 0 = Normal
            else:
                attack_prob = classifier_probs
            risk += self.weights["classifier"] * attack_prob
            active_weight += self.weights["classifier"]

        if gnn_risk is not None:
            risk += self.weights["gnn"] * (gnn_risk / 100.0)  # normalize from 0-100 to 0-1
            active_weight += self.weights["gnn"]

        if temporal_probs is not None:
            risk += self.weights["temporal"] * temporal_probs
            active_weight += self.weights["temporal"]

        if anomaly_scores is not None:
            # Normalize anomaly scores to [0, 1]
            if n_samples > 1 and anomaly_scores.max() > 0:
                norm_scores = np.clip(anomaly_scores / np.percentile(anomaly_scores, 99), 0, 1)
            else:
                norm_scores = np.clip(anomaly_scores, 0, 1)
            risk += self.weights["autoencoder"] * norm_scores
            active_weight += self.weights["autoencoder"]

        # Normalize by active weight and scale to 0-100
        if active_weight > 0:
            risk = (risk / active_weight) * 100
        risk = np.clip(risk, 0, 100)

        return risk

    @staticmethod
    def categorize_risk(risk_scores: np.ndarray) -> list:
        """Categorize risk scores into Low/Medium/High/Critical."""
        categories = []
        for score in risk_scores:
            if score <= RISK_THRESHOLDS["low"][1]:
                categories.append("Low")
            elif score <= RISK_THRESHOLDS["medium"][1]:
                categories.append("Medium")
            elif score <= RISK_THRESHOLDS["high"][1]:
                categories.append("High")
            else:
                categories.append("Critical")
        return categories

    @staticmethod
    def get_risk_color(category: str) -> str:
        """Get color for risk category."""
        from config import RISK_COLORS
        return RISK_COLORS.get(category.lower(), "#ffffff")

    def optimize_weights(self, y_true, classifier_probs=None, gnn_risk=None,
                        temporal_probs=None, anomaly_scores=None):
        """Optimize ensemble weights using logistic regression on validation set."""
        from sklearn.linear_model import LogisticRegression
        log.info("⚖️  Optimizing ensemble weights...")

        features = []
        names = []
        if classifier_probs is not None:
            if classifier_probs.ndim == 2:
                features.append(1 - classifier_probs[:, 0])
            else:
                features.append(classifier_probs)
            names.append("classifier")

        if gnn_risk is not None:
            features.append(gnn_risk / 100.0)
            names.append("gnn")

        if temporal_probs is not None:
            features.append(temporal_probs)
            names.append("temporal")

        if anomaly_scores is not None:
            if anomaly_scores.max() > 0:
                features.append(np.clip(anomaly_scores / np.percentile(anomaly_scores, 99), 0, 1))
            else:
                features.append(anomaly_scores)
            names.append("autoencoder")

        if not features:
            log.warning("  No features for optimization")
            return

        X = np.column_stack(features)
        y_binary = (y_true != 0).astype(int)

        lr = LogisticRegression(max_iter=1000)
        lr.fit(X, y_binary)

        # Convert coefficients to weights
        coefs = np.abs(lr.coef_[0])
        coef_sum = coefs.sum()
        for i, name in enumerate(names):
            self.weights[name] = coefs[i] / coef_sum if coef_sum > 0 else 1.0 / len(names)

        log.info(f"  Optimized weights: {self.weights}")

    def save(self):
        path = SAVED_MODELS_DIR / "ensemble_scorer.joblib"
        joblib.dump(self, path)
        log.info(f"  Saved ensemble to {path}")

    @staticmethod
    def load() -> "EnsembleRiskScorer":
        path = SAVED_MODELS_DIR / "ensemble_scorer.joblib"
        return joblib.load(path)
