# #app/detector.py
# import joblib
# import numpy as np
# from app.feature_extractor import extract_features_from_url
# from app.anomaly_detector import if_model, ocsvm_model


# # rf_model = joblib.load("model/phishing_model.pkl")

# # def predict_phishing(url):
# #     features = extract_features_from_url(url)
# #     prediction = rf_model.predict([features])[0]
# #     return {"url": url, "phishing": bool(prediction)}

# import pandas as pd

# selected_features = pd.read_csv("data/selected_features.csv").columns[:-1].tolist()

# def predict_phishing(url):
#     all_features = extract_features_from_url(url)
#     features_dict = dict(zip(FEATURE_NAMES, all_features))  # FEATURE_NAMES = full feature name list
#     filtered_features = [features_dict[f] for f in selected_features]
#     prediction = rf_model.predict([filtered_features])[0]
#     return {"url": url, "phishing": bool(prediction)}



import time
import threading
import requests
from .queue import url_queue
import joblib

# def load_model():
#     return joblib.load("model/phishing_model.pkl")


# ML_MODEL_API = "http://localhost:5000/predict"
# ALERT_THRESHOLD = 1

# alerts = []

# def start_detector():
#     print("[Detector] Starting detector thread...")
#     while True:
#         try:
#             url = url_queue.get()
#             print(f"[Detector] Checking URL: {url}")
#             res = requests.post(ML_MODEL_API, json={"url": url})
#             result = res.json()
#             if result.get("phishing") == ALERT_THRESHOLD:
#                 print(f"[ALERT] 🚨 Phishing detected: {url}")
#                 alerts.append({"timestamp": datetime.now().isoformat(), "url": suspicious_url,"label": "Phishing"})

#                 #alerts.append({"url": url, "alert": "Phishing Detected"})
#         except Exception as e:
#             print(f"[Detector Error] {e}")
#         time.sleep(1)



import joblib
from app.feature_extractor import extract_features_from_url
ML_MODEL_API = "http://localhost:5000/predict"

# Load model once
def load_model():
    return joblib.load("model/phishing_model.pkl")

def predict_phishing(url):
    model = load_model()
    all_features = extract_features_from_url(url)

    # Select only the expected 20 features
    EXPECTED_FEATURES = [
        'URL_Length', 'having_Sub_Domain', 'domain_token_count',
        'path_token_count', 'charcompvowels', 'URL_Letter_Count',
        'host_letter_count', 'Directory_LetterCount', 'ldl_url', 'domainlength',
        'pathLength', 'pathurlRatio', 'domainUrlRatio', 'pathDomainRatio',
        'SymbolCount_URL', 'SymbolCount_Domain', 'entropy_url', 'entropy_path',
        'spcharUrl', 'delimeter_Count', 'label'
    ]
    
    features_vector = [all_features.get(f, 0) for f in EXPECTED_FEATURES]
    prediction = model.predict([features_vector])[0]
    return prediction

def start_detector():
    def run():
        while True:
            try:
                url = "http://example.com"  # Replace with dynamic/sniffed URL if needed
                print(f"[Detector] Checking URL: {url}")
                response = requests.post("http://localhost:5000/predict", json={"url": url}, timeout=5)
                if response.status_code == 200:
                    result = response.json()
                    print(f"[Detector Result] {result}")
                else:
                    print(f"[Detector Error] Status {response.status_code}")
            except Exception as e:
                print(f"[Detector Error] {e}")
            time.sleep(5)  # Check every 5 seconds

    threading.Thread(target=run, daemon=True).start()