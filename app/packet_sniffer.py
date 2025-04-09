# #app/packet_sniffer.py


# from scapy.all import sniff
# from kafka import KafkaProducer

# producer = KafkaProducer(bootstrap_servers='localhost:9092')

# def packet_callback(packet):
#     if packet.haslayer("Raw"):
#         payload = str(packet["Raw"].load)
#         if "http" in payload:
#             url = payload.split("http", 1)[1].split()[0]
#             full_url = "http" + url
#             print(f"[Sniffer] URL: {full_url}")
#             producer.send("phishing_urls", value=full_url.encode())

# print("Starting packet sniffer...")
# sniff(prn=packet_callback, store=0)



from scapy.all import sniff, TCP, Raw
from urllib.parse import urlparse
from task_queue import url_queue

def packet_callback(packet):
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "Host:" in payload and "GET " in payload:
            try:
                host = payload.split("Host: ")[1].split("\r\n")[0]
                path = payload.split("GET ")[1].split(" HTTP")[0]
                full_url = f"http://{host}{path}"
                print(f"[Sniffer] URL: {full_url}")
                url_queue.put(full_url)
            except Exception as e:
                print(f"[Sniffer Error] {e}")

def start_sniffer():
    sniff(filter="tcp port 80", prn=packet_callback, store=0)
