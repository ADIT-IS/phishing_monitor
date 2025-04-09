# #!/bin/bash

# echo "Starting Model Training..."
# python3 code/phishing_monitor/train_model.py

# echo "Starting FastAPI server..."
# uvicorn code.phishing_monitor.app.main:app --reload &

# echo "Starting Kafka Consumer..."
# python3 code/phishing_monitor/kafka/consumer.py &

# echo "Starting Kafka Producer..."
# python3 code/phishing_monitor/kafka/producer.py &

# echo "Starting Packet Sniffer..."
# sudo python3 code/phishing_monitor/sniffer/sniffer.py


#!/bin/bash

echo "🚀 Starting phishing monitor system (no Kafka)..."
source venv/bin/activate

python3 -u local_runner.py
