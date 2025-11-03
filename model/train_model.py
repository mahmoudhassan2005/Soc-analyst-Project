import os
import argparse
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from utils.feature_engineering import preprocess_dataframe


class SOCModel:
    def __init__(self, clf: RandomForestClassifier, feature_names):
        self.clf = clf
        self.feature_names = list(feature_names)

    def predict_proba(self, X):
        return self.clf.predict_proba(X)

    def predict(self, X):
        return self.clf.predict(X)

    @property
    def feature_importances_(self):
        return getattr(self.clf, "feature_importances_", None)


LABEL_MAP = {"benign": 0, "suspicious": 1, "malicious": 2}
INV_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}


def train(data_path: str, out_path: str):
    df = pd.read_csv(data_path)
    if "label" not in df.columns:
        raise ValueError("Training data must include 'label' column")

    X = preprocess_dataframe(df)
    y = df["label"].map(LABEL_MAP).fillna(0).astype(int)

    # Decide whether we can perform a stratified split
    vc = y.value_counts()
    can_stratify = (vc.min() >= 2) and (vc.size >= 2) and (len(y) >= 5)

    clf = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42, n_jobs=-1)

    if can_stratify:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        clf.fit(X_train, y_train)
        try:
            y_pred = clf.predict(X_test)
            print(classification_report(y_test, y_pred))
        except Exception:
            pass
    else:
        # Small/imbalanced dataset: fit on all data without split
        clf.fit(X, y)

    model = SOCModel(clf=clf, feature_names=X.columns)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    joblib.dump(model, out_path)
    print(f"Saved model to {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True, help="Path to training CSV")
    parser.add_argument("--out", required=True, help="Path to save model.pkl")
    args = parser.parse_args()
    train(args.data, args.out)
