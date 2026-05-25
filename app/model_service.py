import joblib
import pandas as pd

from utils import get_model_path


MODEL_FILE = "xgboost_live_url_model.joblib"
FEATURE_FILE = "live_url_feature_columns.joblib"


def load_model_and_features():
    model_path = get_model_path(MODEL_FILE)
    feature_path = get_model_path(FEATURE_FILE)

    model = joblib.load(model_path)
    selected_features = joblib.load(feature_path)

    return model, selected_features


def predict_url(model, selected_features, url_features):
    input_df = pd.DataFrame([url_features])

    for column in selected_features:
        if column not in input_df.columns:
            input_df[column] = 0

    input_df = input_df[selected_features]

    prediction = model.predict(input_df)[0]
    probability = model.predict_proba(input_df)[0]

    return {
        "prediction": int(prediction),
        "phishing_probability": float(probability[0]),
        "safe_probability": float(probability[1])
    }