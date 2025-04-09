#train_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
import joblib

# Load dataset
df = pd.read_csv("data/selected_features.csv")

df.columns = df.columns.str.strip()  # In case any columns have extra spaces
X = df.drop("label", axis=1)
y = df["label"]

rf_model = RandomForestClassifier(n_estimators=100)
rf_model.fit(X, y)
joblib.dump(rf_model, "model/phishing_model.pkl")

# Anomaly detection
if_model = IsolationForest(contamination=0.1)
ocsvm_model = OneClassSVM(nu=0.1, kernel="rbf")

if_model.fit(X)
ocsvm_model.fit(X)

joblib.dump(if_model, "model/anomaly_model_if.pkl")
joblib.dump(ocsvm_model, "model/anomaly_model_ocsvm.pkl")

print("Models trained and saved.")
