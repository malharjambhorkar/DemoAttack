import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from . import DATA_DIR, FEATURE_COLUMNS, MODELS_DIR


def train_model() -> None:
    dataset_path = DATA_DIR / "phishing_dataset.csv"
    model_path = MODELS_DIR / "phishing_model.pkl"

    df = pd.read_csv(dataset_path)
    x = df[FEATURE_COLUMNS]
    y = df["label"]

    model = RandomForestClassifier(
        n_estimators=120,
        max_depth=6,
        random_state=42,
    )
    model.fit(x, y)

    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(model, model_path)
    print(f"Model trained and saved to {model_path}")
