import os
import joblib
import pandas as pd
from typing import Tuple
from sklearn.ensemble import RandomForestClassifier

from utils.feature_engineering import preprocess_dataframe, align_features


LABELS = ["benign", "suspicious", "malicious"]


def load_or_train_model(data_path: str, model_path: str):
    if os.path.exists(model_path):
        return joblib.load(model_path)
    # train lightweight model if not present
    from .train_model import train
    train(data_path, model_path)
    return joblib.load(model_path)


def predict_batch(model, processed_df: pd.DataFrame) -> Tuple[list, list]:
    X = align_features(processed_df, model.feature_names)
    probs = model.predict_proba(X)
    preds_idx = probs.argmax(axis=1)
    preds = [LABELS[i] for i in preds_idx]
    return preds, probs


def explain_prediction(model, single_processed_row: pd.DataFrame):
    X = align_features(single_processed_row, model.feature_names)
    importances = getattr(model, "feature_importances_", None)
    if importances is None:
        importances = getattr(model.clf, "feature_importances_", None)
    if importances is None:
        raise ValueError("Model does not provide feature_importances_")
    s = pd.Series(importances, index=model.feature_names)
    return s
