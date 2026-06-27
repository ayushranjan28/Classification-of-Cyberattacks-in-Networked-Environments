"""
Comprehensive model evaluation with metrics, plots, and comparison tables.
"""
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, roc_curve, precision_recall_curve
)
import plotly.graph_objects as go
import plotly.figure_factory as ff
from plotly.subplots import make_subplots
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import REPORTS_DIR
from utils.logger import get_logger

log = get_logger(__name__)


def generate_comparison_table(results: dict) -> pd.DataFrame:
    """Generate a model comparison DataFrame."""
    rows = []
    for name, res in results.items():
        m = res.get("metrics", res)
        rows.append({
            "Model": name,
            "Accuracy": m.get("accuracy", 0),
            "Precision": m.get("precision_macro", m.get("precision", 0)),
            "Recall": m.get("recall_macro", m.get("recall", 0)),
            "F1 Score": m.get("f1_macro", m.get("f1", 0)),
            "ROC AUC": m.get("roc_auc_ovr", m.get("roc_auc", 0)),
            "Training Time (s)": m.get("training_time_s", 0),
            "Memory (MB)": m.get("memory_delta_mb", 0),
        })
    df = pd.DataFrame(rows).sort_values("F1 Score", ascending=False)
    return df


def plot_confusion_matrix(y_true, y_pred, class_names, title="Confusion Matrix") -> go.Figure:
    """Create an interactive confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    cm_normalized = cm.astype(float) / cm.sum(axis=1, keepdims=True)
    cm_normalized = np.nan_to_num(cm_normalized)

    text = [[f"{cm[i][j]}<br>({cm_normalized[i][j]:.1%})"
             for j in range(len(class_names))]
            for i in range(len(class_names))]

    fig = go.Figure(data=go.Heatmap(
        z=cm_normalized,
        x=class_names,
        y=class_names,
        text=text,
        texttemplate="%{text}",
        colorscale="Blues",
        showscale=True,
    ))
    fig.update_layout(
        title=title,
        xaxis_title="Predicted",
        yaxis_title="Actual",
        paper_bgcolor="#0E1117",
        plot_bgcolor="#0E1117",
        font=dict(color="#E0E0E0"),
        height=500,
    )
    return fig


def plot_roc_curves(results: dict, y_test, class_names) -> go.Figure:
    """Plot ROC curves for all models."""
    fig = go.Figure()
    colors = ["#3B82F6", "#10B981", "#F59E0B", "#EF4444", "#8B5CF6"]

    for i, (name, res) in enumerate(results.items()):
        model = res.get("model")
        if model is None:
            continue
        try:
            from preprocessing.pipeline import PreprocessingPipeline
            data = PreprocessingPipeline.load_processed()
            y_proba = model.predict_proba(data["X_test"])
            # Binary: attack vs normal
            y_binary = (y_test != 0).astype(int)
            attack_prob = 1 - y_proba[:, 0]
            fpr, tpr, _ = roc_curve(y_binary, attack_prob)
            auc = roc_auc_score(y_binary, attack_prob)
            fig.add_trace(go.Scatter(
                x=fpr, y=tpr,
                name=f"{name} (AUC={auc:.3f})",
                line=dict(color=colors[i % len(colors)], width=2)
            ))
        except Exception:
            pass

    fig.add_trace(go.Scatter(
        x=[0, 1], y=[0, 1],
        name="Random",
        line=dict(color="#555", dash="dash", width=1)
    ))
    fig.update_layout(
        title="ROC Curves",
        xaxis_title="False Positive Rate",
        yaxis_title="True Positive Rate",
        paper_bgcolor="#0E1117",
        plot_bgcolor="#1A1A2E",
        font=dict(color="#E0E0E0"),
        height=500,
        legend=dict(x=0.6, y=0.1)
    )
    return fig


def plot_training_history(train_losses: list, val_accs: list = None, title: str = "") -> go.Figure:
    """Plot training loss and validation accuracy curves."""
    fig = make_subplots(specs=[[{"secondary_y": True}]])
    fig.add_trace(
        go.Scatter(y=train_losses, name="Training Loss",
                   line=dict(color="#3B82F6", width=2)),
        secondary_y=False
    )
    if val_accs:
        fig.add_trace(
            go.Scatter(y=val_accs, name="Val Accuracy",
                       line=dict(color="#10B981", width=2)),
            secondary_y=True
        )
    fig.update_layout(
        title=title or "Training History",
        paper_bgcolor="#0E1117",
        plot_bgcolor="#1A1A2E",
        font=dict(color="#E0E0E0"),
        height=400,
    )
    fig.update_yaxes(title_text="Loss", secondary_y=False)
    fig.update_yaxes(title_text="Accuracy", secondary_y=True)
    return fig


def save_report(comparison_df: pd.DataFrame, all_metrics: dict):
    """Save evaluation report to disk."""
    report_path = REPORTS_DIR / "evaluation_report.json"
    # Convert metrics to serializable format
    serializable = {}
    for name, res in all_metrics.items():
        m = res.get("metrics", res)
        serializable[name] = {
            k: v.tolist() if isinstance(v, np.ndarray) else v
            for k, v in m.items()
            if not callable(v) and k != "classification_report"
        }
    with open(report_path, "w") as f:
        json.dump(serializable, f, indent=2, default=str)

    csv_path = REPORTS_DIR / "model_comparison.csv"
    comparison_df.to_csv(csv_path, index=False)
    log.info(f"  Saved report to {report_path}")
    log.info(f"  Saved comparison to {csv_path}")
