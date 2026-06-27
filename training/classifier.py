"""
Model 1: Attack Classification with XGBoost, LightGBM, CatBoost, Random Forest.
Trains, compares, and selects the best model.
"""
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import (
    XGBOOST_PARAMS, LIGHTGBM_PARAMS, CATBOOST_PARAMS, RF_PARAMS, SAVED_MODELS_DIR
)
from utils.logger import get_logger
from utils.timer import Timer, get_memory_usage_mb

log = get_logger(__name__)


def _compute_metrics(y_true, y_pred, y_proba, class_names):
    """Compute comprehensive classification metrics."""
    labels = list(range(len(class_names)))
    metrics = {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision_macro": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "recall_macro": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels),
        "classification_report": classification_report(y_true, y_pred, labels=labels, target_names=class_names, zero_division=0),
    }
    # ROC AUC (one-vs-rest)
    try:
        if y_proba is not None and y_proba.shape[1] > 1:
            metrics["roc_auc_ovr"] = roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro")
        else:
            metrics["roc_auc_ovr"] = 0.0
    except Exception:
        metrics["roc_auc_ovr"] = 0.0
    return metrics


def train_xgboost(X_train, y_train, X_val, y_val, class_weights=None):
    """Train XGBoost classifier."""
    from xgboost import XGBClassifier
    log.info("🌲 Training XGBoost...")
    params = XGBOOST_PARAMS.copy()
    params["num_class"] = len(np.unique(y_train))
    if class_weights:
        sample_weights = np.array([class_weights.get(y, 1.0) for y in y_train])
    else:
        sample_weights = None

    model = XGBClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        sample_weight=sample_weights,
        verbose=False
    )
    return model


def train_lightgbm(X_train, y_train, X_val, y_val, class_weights=None):
    """Train LightGBM classifier."""
    from lightgbm import LGBMClassifier
    log.info("🌿 Training LightGBM...")
    params = LIGHTGBM_PARAMS.copy()
    params["num_class"] = len(np.unique(y_train))
    if class_weights:
        params["class_weight"] = class_weights

    model = LGBMClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
    )
    return model


def train_catboost(X_train, y_train, X_val, y_val, class_weights=None):
    """Train CatBoost classifier."""
    from catboost import CatBoostClassifier
    log.info("🐱 Training CatBoost...")
    params = CATBOOST_PARAMS.copy()
    if class_weights:
        params["class_weights"] = class_weights

    model = CatBoostClassifier(**params)
    model.fit(
        X_train, y_train,
        eval_set=(X_val, y_val),
        verbose=False
    )
    return model


def train_random_forest(X_train, y_train, class_weights=None):
    """Train Random Forest classifier."""
    log.info("🌳 Training Random Forest...")
    params = RF_PARAMS.copy()
    if class_weights:
        params["class_weight"] = class_weights

    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)
    return model


def train_all_classifiers(data: dict) -> dict:
    """
    Train all 4 classifiers, compare, and select best.

    Args:
        data: dict with X_train, X_val, X_test, y_train, y_val, y_test,
              encoder, class_weights

    Returns:
        dict with models, metrics, best_model_name
    """
    X_train = data["X_train"]
    X_val = data["X_val"]
    X_test = data["X_test"]
    y_train = data["y_train"]
    y_val = data["y_val"]
    y_test = data["y_test"]
    class_weights = data.get("class_weights")
    encoder = data["encoder"]

    results = {}
    trainers = {
        "XGBoost": lambda: train_xgboost(X_train, y_train, X_val, y_val, class_weights),
        "LightGBM": lambda: train_lightgbm(X_train, y_train, X_val, y_val, class_weights),
        "CatBoost": lambda: train_catboost(X_train, y_train, X_val, y_val, class_weights),
        "RandomForest": lambda: train_random_forest(X_train, y_train, class_weights),
    }

    for name, trainer in trainers.items():
        log.info(f"\n{'='*60}")
        log.info(f"Training {name}")
        log.info(f"{'='*60}")

        mem_before = get_memory_usage_mb()
        with Timer(f"{name} training") as t:
            try:
                model = trainer()
            except Exception as e:
                log.error(f"  {name} failed: {e}")
                continue
        mem_after = get_memory_usage_mb()

        # Evaluate on test set
        y_pred = model.predict(X_test)
        try:
            y_proba = model.predict_proba(X_test)
        except Exception:
            y_proba = None

        metrics = _compute_metrics(y_test, y_pred, y_proba, encoder.classes)
        metrics["training_time_s"] = t.elapsed
        metrics["memory_delta_mb"] = mem_after - mem_before

        log.info(f"  Accuracy:  {metrics['accuracy']:.4f}")
        log.info(f"  F1 Macro:  {metrics['f1_macro']:.4f}")
        log.info(f"  ROC AUC:   {metrics['roc_auc_ovr']:.4f}")
        log.info(f"\n{metrics['classification_report']}")

        # Save model
        model_path = SAVED_MODELS_DIR / f"classifier_{name.lower()}.joblib"
        joblib.dump(model, model_path)
        log.info(f"  Saved to {model_path}")

        results[name] = {
            "model": model,
            "metrics": metrics,
            "model_path": str(model_path),
        }

    # Select best model by F1 macro
    if results:
        best_name = max(results, key=lambda k: results[k]["metrics"]["f1_macro"])
        log.info(f"\n🏆 Best classifier: {best_name} "
                 f"(F1={results[best_name]['metrics']['f1_macro']:.4f})")
        # Save best model
        joblib.dump(results[best_name]["model"], SAVED_MODELS_DIR / "best_classifier.joblib")
    else:
        best_name = None

    return {
        "results": results,
        "best_model_name": best_name,
        "best_model": results[best_name]["model"] if best_name else None,
    }
