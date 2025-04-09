
#app/anomaly detector.py
import joblib
from urllib.parse import urlparse
from feature_extractor import extract_features_from_url

# Load models
if_model = joblib.load("model/anomaly_model_if.pkl")
ocsvm_model = joblib.load("model/anomaly_model_ocsvm.pkl")

# if_model = joblib.load("../model/anomaly_model.pkl")
# ocsvm_model = joblib.load("../model/anomaly_model.pkl")

def detect_anomaly(url):
    features = extract_features_from_url(url)
    score_if = if_model.predict([features])[0]
    score_ocsvm = ocsvm_model.predict([features])[0]
    return {"url": url, "is_anomaly": score_if == -1 or score_ocsvm == -1}
