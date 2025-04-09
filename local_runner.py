# local_runner.py
import threading
import time
import requests
from app.api import start_api
from app.packet_sniffer import start_sniffer
from app.detector import start_detector
ML_MODEL_API = "http://localhost:5000/predict"

if __name__ == "__main__":
    print("✅ Starting API server...")
    threading.Thread(target=start_api, daemon=True).start()

    time.sleep(2)

    print("✅ Starting packet sniffer...")
    threading.Thread(target=start_sniffer, daemon=True).start()

    print("✅ Starting phishing detector...")
    threading.Thread(target=start_detector, daemon=True).start()

    url = "http://example.com"
    try:
        response = requests.post(ML_MODEL_API, json={"url": url}, timeout=5)
        print(f"[HTTP] Status Code: {response.status_code}")
        print(f"[HTTP] Raw Response: {response.text}")

        if response.ok:
            result = response.json()
            print(f"[✅ Result] {result}")
            if result.get("phishing") == 1:
                alerts.append({"url": url, "alert": "Phishing Detected"})
        else:
            print("[⚠️ Warning] Non-200 response from API")

    except Exception as e:
        print(f"[Detector Error] {e}")

    while True:
        time.sleep(10)