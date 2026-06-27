import joblib
import sys
from pathlib import Path
import shap
import pandas as pd
import numpy as np

sys.path.insert(0, r'c:\Users\ayush\Desktop\dataport\project')
from config import SAVED_MODELS_DIR, PREPROCESSED_DIR
from explainability.shap_explainer import ShapExplainer

model = joblib.load(SAVED_MODELS_DIR / "best_classifier.joblib")
data = joblib.load(PREPROCESSED_DIR / "processed_data.joblib")
feature_names = data.get("feature_cols", [])

explainer = ShapExplainer(model, feature_names)
explainer.fit()

x = np.zeros((1, len(feature_names)))
res = explainer.explain_single(x)
print("SUCCESS!")
print(res["explanation_text"])
