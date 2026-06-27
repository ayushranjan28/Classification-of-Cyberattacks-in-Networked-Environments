"""
Explainable AI using SHAP: feature importance, per-prediction explanations,
and natural-language summaries.
"""
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import joblib
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import SAVED_MODELS_DIR
from utils.logger import get_logger

log = get_logger(__name__)


class ShapExplainer:
    """SHAP-based model explainability for tree ensemble classifiers."""

    def __init__(self, model=None, feature_names=None):
        self.model = model
        self.feature_names = list(feature_names) if feature_names is not None else None
        self.shap_values = None
        self.explainer = None

    def fit(self, X_background: np.ndarray = None, max_samples: int = 500):
        """Initialize SHAP explainer."""
        try:
            import shap
        except ImportError:
            log.warning("SHAP not installed — explainability unavailable")
            return self

        log.info("🔍 Initializing SHAP explainer...")

        try:
            self.explainer = shap.TreeExplainer(self.model)
            log.info("  Using TreeExplainer (fast)")
        except Exception:
            if X_background is not None:
                bg = X_background[:max_samples]
                self.explainer = shap.KernelExplainer(self.model.predict_proba, bg)
                log.info("  Using KernelExplainer (slower)")
            else:
                log.warning("  Could not create explainer")

        return self

    def explain(self, X: np.ndarray, max_samples: int = 1000) -> dict:
        """
        Compute SHAP values for samples.

        Returns:
            dict with shap_values, feature_importance, expected_value
        """
        if self.explainer is None:
            log.warning("  Explainer not initialized")
            return {}

        import shap

        X_explain = X[:max_samples] if len(X) > max_samples else X
        log.info(f"  Computing SHAP values for {len(X_explain)} samples...")

        self.shap_values = self.explainer.shap_values(X_explain)

        # Feature importance (mean absolute SHAP)
        if isinstance(self.shap_values, list):
            # Multi-class: average across classes
            all_shap = np.array(self.shap_values)
            importance = np.mean(np.abs(all_shap), axis=(0, 1))
        else:
            importance = np.mean(np.abs(self.shap_values), axis=0)

        if self.feature_names:
            feat_importance = dict(zip(self.feature_names, importance))
        else:
            feat_importance = dict(enumerate(importance))

        # Sort by importance
        feat_importance = dict(sorted(feat_importance.items(), key=lambda x: x[1], reverse=True))

        return {
            "shap_values": self.shap_values,
            "feature_importance": feat_importance,
            "expected_value": self.explainer.expected_value,
        }

    def explain_single(self, x: np.ndarray, top_n: int = 5) -> dict:
        """
        Generate explanation for a single prediction.

        Returns:
            dict with top_features, confidence, explanation_text
        """
        if self.explainer is None:
            return {"explanation_text": "Explainer not available", "top_features": []}

        import shap

        if x.ndim == 1:
            x = x.reshape(1, -1)

        sv = self.explainer.shap_values(x)

        # Get the predicted class
        pred = self.model.predict(x)[0]
        pred_proba = self.model.predict_proba(x)[0]
        confidence = pred_proba[pred]

        # SHAP values for predicted class
        if isinstance(sv, list):
            class_shap = sv[pred][0]
        else:
            class_shap = sv[0]

        # Top contributing features
        feature_names = self.feature_names or [f"Feature_{i}" for i in range(len(class_shap))]
        feature_contributions = list(zip(feature_names, class_shap, x[0]))
        feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
        top_features = feature_contributions[:top_n]

        # Generate natural language explanation
        explanation_parts = []
        for fname, shap_val, feat_val in top_features:
            direction = "increased" if shap_val > 0 else "decreased"
            readable_name = fname.replace("_", " ").lower()
            explanation_parts.append(
                f"{readable_name} {direction} risk (SHAP: {shap_val:+.3f}, value: {feat_val:.2f})"
            )

        explanation_text = (
            f"Risk assessment — Confidence: {confidence:.1%}. "
            f"Key factors: {'; '.join(explanation_parts)}."
        )

        return {
            "predicted_class": int(pred),
            "confidence": float(confidence),
            "top_features": [
                {"feature": f, "shap_value": float(s), "feature_value": float(v)}
                for f, s, v in top_features
            ],
            "explanation_text": explanation_text,
        }

    def plot_feature_importance(self, top_n: int = 20) -> go.Figure:
        """Create interactive feature importance plot."""
        if not hasattr(self, '_last_importance'):
            return go.Figure()

        importance = self._last_importance
        items = list(importance.items())[:top_n]
        items.reverse()

        fig = go.Figure(go.Bar(
            x=[v for _, v in items],
            y=[k for k, _ in items],
            orientation="h",
            marker_color="#3B82F6",
        ))
        fig.update_layout(
            title="SHAP Feature Importance (Top 20)",
            xaxis_title="Mean |SHAP Value|",
            paper_bgcolor="#0E1117",
            plot_bgcolor="#1A1A2E",
            font=dict(color="#E0E0E0"),
            height=600,
            margin=dict(l=200),
        )
        return fig

    def save(self):
        path = SAVED_MODELS_DIR / "shap_explainer.joblib"
        # Save without the model (it's saved separately)
        save_data = {
            "feature_names": self.feature_names,
            "shap_values": self.shap_values,
        }
        joblib.dump(save_data, path)
        log.info(f"  Saved SHAP data to {path}")
