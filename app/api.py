# #app/api.Py
from fastapi import FastAPI
from pydantic import BaseModel
# from app.detector import predict_phishing, detect_anomaly
from flask import Flask, request, jsonify
from detector import load_model

from detector import predict_phishing
from anomaly_detector import detect_anomaly





# from flask import Flask, request, jsonify
# from .feature_extractor import extract_features
# import pickle
# import pandas as pd
# import os
# from app.detector import load_model


# app = Flask(__name__)
# model_path = os.path.join(os.path.dirname(__file__), '../model/phishing_model.pkl')
# features_csv = os.path.join(os.path.dirname(__file__), '../data/selected_features.csv')
# model = pickle.load(open(model_path, "rb"))
# selected_features = pd.read_csv(features_csv)["label"].tolist()

# alerts = []  # Shared across modules

# @app.route("/predict", methods=["POST"])
# def predict():
#     url = request.json.get("url")
#     features = extract_features(url)
#     selected = [features.get(f, 0) for f in selected_features]
#     prediction = model.predict([selected])[0]
#     return jsonify({"phishing": int(prediction)})



from app.feature_extractor import extract_features_from_url
import joblib

app = Flask(__name__)
model = joblib.load("model/phishing_model.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    print(f"[API] Received URL: {url}")
    features = extract_features_from_url(url)
    feature_values = [features[ft] for ft in list(model.feature_names_in_)]
    prediction = model.predict([feature_values])[0]
    return jsonify({"phishing": bool(prediction)})


@app.route("/alerts", methods=["GET"])
def get_alerts():
    return jsonify(alerts)

def start_api():
    app.run(port=5000)

