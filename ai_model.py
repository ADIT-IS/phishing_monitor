# ai_model.py

import joblib  # or use pickle, torch, etc., depending on your model type
import requests
from flask import Flask, request, jsonify
from feature_extractor import extract_features_from_url
# import joblib
# Load your model (adjust path and loader if needed)
MODEL_PATH = "phishing_model.pkl"
model = joblib.load(MODEL_PATH)

def predict(url):
    # data = request.get_json()
    # url = data.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    print(f"[API] Received URL: {url}")
    features = extract_features_from_url(url)
    feature_values = []
    l = ['URL_Length', 'having_Sub_Domain', 'domain_token_count','path_token_count', 'charcompvowels', 'URL_Letter_Count','host_letter_count', 'Directory_LetterCount', 'ldl_url', 'domainlength','pathLength', 'pathurlRatio', 'domainUrlRatio', 'pathDomainRatio','SymbolCount_URL', 'SymbolCount_Domain', 'entropy_url', 'entropy_path','spcharUrl', 'delimeter_Count', 'label']
    for i in l:
        if i in features:
            feature_values.append(features[i])
    # for ft in model.feature_names_in_:
    #     # val = features.get(ft)
    #     try:
    #         feature_values.append(int(ft))
    #     except (ValueError, TypeError):
    #         # Skip if not convertible to int
    #         continue
    # print(features)
    # feature_values = [features[ft] for ft in list(model.feature_names_in_)]

    prediction = model.predict([feature_values])[0]
    print(f"[API] Prediction: {prediction}")
    return {"phishing": bool(prediction)}

def analyze_url(url: str) -> tuple[int, str]:
    """
    Use the provided model to analyze the URL.
    The model should return a score (0–100) and a verdict.
    """
    result = predict(url)
    # result = model.predict([url])  # <- Adjust based on your model's API

    # Example output: [ {"score": 87, "verdict": "Likely Safe"} ]
    score = result["phishing"]
    # verdict = result[0].get("verdict", "Unknown")
    if int(score) == 0:
        verdict = "Likely Safe"
    else:
        verdict = "Likely Phishing"
    return score, verdict
