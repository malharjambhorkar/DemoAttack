from pathlib import Path

import joblib
from flask import Flask


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"

FEATURE_COLUMNS = [
    "length",
    "dot_count",
    "dash_count",
    "has_https",
    "has_digits",
    "has_at_symbol",
    "is_shortener",
    "keyword_hits",
    "path_length",
]


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    app.config["BASE_DIR"] = BASE_DIR
    app.config["DATASET_PATH"] = DATA_DIR / "phishing_dataset.csv"
    app.config["EVENT_LOG_PATH"] = DATA_DIR / "demo_events.csv"
    app.config["MODEL_PATH"] = MODELS_DIR / "phishing_model.pkl"
    app.config["FEATURE_COLUMNS"] = FEATURE_COLUMNS
    app.config["MODEL"] = load_model(app.config["MODEL_PATH"])

    from .routes import main_bp

    app.register_blueprint(main_bp)
    return app


def load_model(model_path: Path):
    return joblib.load(model_path) if model_path.exists() else None
