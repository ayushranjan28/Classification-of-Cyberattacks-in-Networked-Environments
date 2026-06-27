"""
Master training pipeline — orchestrates all 11 steps from data loading to evaluation.

Usage:
    python main.py                      # Full pipeline
    python main.py --mode preprocess    # Only preprocessing
    python main.py --mode train         # Only training (uses saved preprocessed data)
    python main.py --mode evaluate      # Only evaluation (uses saved models)
    python main.py --sample-ratio 0.1   # Fast iteration with 10% data
"""
import sys
import argparse
import numpy as np
import pandas as pd
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from config import SAMPLE_RATIO, SAVED_MODELS_DIR
from utils.logger import get_logger
from utils.timer import Timer

log = get_logger("main")


def step_preprocess(args):
    """Step 1-2: Load and preprocess data."""
    from preprocessing.pipeline import PreprocessingPipeline
    pipeline = PreprocessingPipeline()
    data = pipeline.run(
        dataset=args.dataset,
        balance_method=args.balance,
        sample_ratio=args.sample_ratio
    )
    return data


def step_train_classifiers(data):
    """Step 5: Train XGBoost, LightGBM, CatBoost, RF."""
    from training.classifier import train_all_classifiers
    return train_all_classifiers(data)


def step_train_gnn(data):
    """Step 6: Train Graph Neural Networks."""
    log.info("\n" + "="*70)
    log.info("STEP 6: Graph Neural Network Training")
    log.info("="*70)

    try:
        from preprocessing.loader import load_traffic_labelling
        from graph.builder import build_pyg_data

        log.info("Loading TrafficLabelling data for graph construction...")
        traffic_df = load_traffic_labelling(sample_ratio=1.0)  # 100% for full graph

        # Map labels to integers before passing to PyG
        import joblib
        from config import CICIDS_LABEL_MAP, SAVED_MODELS_DIR
        traffic_df["Label"] = traffic_df["Label"].map(CICIDS_LABEL_MAP).fillna("Normal")
        encoder = joblib.load(SAVED_MODELS_DIR / "label_encoder.joblib")
        known_classes = set(encoder.classes)
        traffic_df["Label"] = traffic_df["Label"].apply(lambda x: x if x in known_classes else "Normal")
        traffic_df["Label"] = encoder.transform(traffic_df["Label"])

        graph_data = build_pyg_data(traffic_df)

        from training.gnn_model import train_all_gnns
        num_classes = len(data["encoder"].classes)
        gnn_results = train_all_gnns(graph_data, num_classes)
        return gnn_results
    except Exception as e:
        log.error(f"GNN training failed: {e}")
        import traceback
        traceback.print_exc()
        return {"results": {}, "best": None}


def step_train_temporal(data):
    """Step 7: Train LSTM and Transformer models."""
    log.info("\n" + "="*70)
    log.info("STEP 7: Temporal Model Training")
    log.info("="*70)

    from training.temporal_model import create_sequences, train_all_temporal

    seq_length = 20
    X_train_vals = data["X_train"].values if hasattr(data["X_train"], "values") else data["X_train"]
    X_val_vals = data["X_val"].values if hasattr(data["X_val"], "values") else data["X_val"]

    X_train_seq, y_train_seq = create_sequences(X_train_vals, data["y_train"], seq_length)
    X_val_seq, y_val_seq = create_sequences(X_val_vals, data["y_val"], seq_length)

    # Binary: normal (0) vs attack (1)
    y_train_binary = (y_train_seq != 0).astype(np.int64)
    y_val_binary = (y_val_seq != 0).astype(np.int64)

    results = train_all_temporal(X_train_seq, y_train_binary, X_val_seq, y_val_binary, num_classes=2)
    return results


def step_train_autoencoder(data):
    """Step 8: Train autoencoder on benign traffic."""
    log.info("\n" + "="*70)
    log.info("STEP 8: Autoencoder Training (Anomaly Detection)")
    log.info("="*70)

    from training.autoencoder import train_autoencoder, detect_anomalies

    X_train = data["X_train"].values if hasattr(data["X_train"], "values") else data["X_train"]
    X_val = data["X_val"].values if hasattr(data["X_val"], "values") else data["X_val"]
    X_test = data["X_test"].values if hasattr(data["X_test"], "values") else data["X_test"]

    # Select only benign samples for training
    benign_mask_train = data["y_train"] == 0
    benign_mask_val = data["y_val"] == 0

    X_benign_train = X_train[benign_mask_train]
    X_benign_val = X_val[benign_mask_val]

    if len(X_benign_train) < 10:
        log.warning("Too few benign samples for autoencoder training")
        return {}

    ae_result = train_autoencoder(X_benign_train, X_benign_val, X_train.shape[1])

    # Run anomaly detection on test set
    detection_result = detect_anomalies(
        ae_result["model"], X_test, data["y_test"], X_benign_val
    )

    ae_result.update(detection_result)
    return ae_result


def step_ensemble(data, classifier_results, gnn_results, temporal_results, ae_results):
    """Step 9: Build ensemble risk scorer."""
    log.info("\n" + "="*70)
    log.info("STEP 9: Ensemble Risk Scoring")
    log.info("="*70)

    from training.ensemble import EnsembleRiskScorer

    scorer = EnsembleRiskScorer()
    X_test = data["X_test"].values if hasattr(data["X_test"], "values") else data["X_test"]

    # Get classifier probabilities
    classifier_probs = None
    if classifier_results.get("best_model"):
        try:
            classifier_probs = classifier_results["best_model"].predict_proba(X_test)
        except Exception:
            pass

    # Get anomaly scores
    anomaly_scores = ae_results.get("anomaly_scores")

    # Compute risk
    risk_scores = scorer.compute_risk(
        classifier_probs=classifier_probs,
        anomaly_scores=anomaly_scores,
        n_samples=len(X_test)
    )

    categories = scorer.categorize_risk(risk_scores)
    log.info(f"  Risk distribution: {pd.Series(categories).value_counts().to_dict()}")

    scorer.save()

    return {
        "risk_scores": risk_scores,
        "categories": categories,
        "scorer": scorer,
    }


def step_evaluate(data, classifier_results):
    """Step 10: Comprehensive evaluation."""
    log.info("\n" + "="*70)
    log.info("STEP 10: Comprehensive Evaluation")
    log.info("="*70)

    from training.evaluate import generate_comparison_table, save_report

    if classifier_results.get("results"):
        comparison = generate_comparison_table(
            {k: v for k, v in classifier_results["results"].items()}
        )
        log.info(f"\n{comparison.to_string(index=False)}")
        save_report(comparison, classifier_results["results"])


def main():
    parser = argparse.ArgumentParser(description="IDS Training Pipeline")
    parser.add_argument("--mode", default="full", choices=["full", "preprocess", "train", "evaluate"])
    parser.add_argument("--dataset", default="mscad", choices=["mscad", "mlcve"])
    parser.add_argument("--balance", default="weight", choices=["smote", "weight", "none"])
    parser.add_argument("--sample-ratio", type=float, default=SAMPLE_RATIO)
    args = parser.parse_args()

    log.info("="*70)
    log.info("AI-Based Predictive Intrusion Detection System")
    log.info("IEEE DataPort Hackathon — Training Pipeline")
    log.info("="*70)

    import pandas as pd

    # Preprocessing
    if args.mode in ["full", "preprocess"]:
        with Timer("Total Preprocessing"):
            data = step_preprocess(args)
        if args.mode == "preprocess":
            return
    else:
        from preprocessing.pipeline import PreprocessingPipeline
        data = PreprocessingPipeline.load_processed()

    # Training
    if args.mode in ["full", "train"]:
        # Step 5: Classifiers
        with Timer("Classifier Training"):
            classifier_results = step_train_classifiers(data)

        # Step 6: GNN
        with Timer("GNN Training"):
            gnn_results = step_train_gnn(data)

        # Step 7: Temporal
        with Timer("Temporal Training"):
            temporal_results = step_train_temporal(data)

        # Step 8: Autoencoder
        with Timer("Autoencoder Training"):
            ae_results = step_train_autoencoder(data)

        # Step 9: Ensemble
        with Timer("Ensemble"):
            ensemble_results = step_ensemble(data, classifier_results, gnn_results, temporal_results, ae_results)

        # Step 10: Evaluate
        step_evaluate(data, classifier_results)

        # Step 11: SHAP
        log.info("\n" + "="*70)
        log.info("STEP 11: Explainable AI (SHAP)")
        log.info("="*70)
        try:
            from explainability.shap_explainer import ShapExplainer
            X_test = data["X_test"].values if hasattr(data["X_test"], "values") else data["X_test"]
            explainer = ShapExplainer(classifier_results["best_model"], data["feature_cols"])
            explainer.fit()
            shap_result = explainer.explain(X_test, max_samples=500)
            if shap_result:
                top5 = list(shap_result["feature_importance"].items())[:5]
                log.info(f"  Top 5 features: {top5}")
                explainer.save()
        except Exception as e:
            log.warning(f"  SHAP failed: {e}")

    log.info("\n" + "="*70)
    log.info("✅ Pipeline Complete!")
    log.info(f"   Models saved to: {SAVED_MODELS_DIR}")
    log.info(f"   Launch dashboard: streamlit run dashboard/app.py")
    log.info("="*70)


if __name__ == "__main__":
    main()
