# traffic_monitor.py

from scapy.all import sniff, TCP, Raw
from app.feature_extractor import extract_features_from_url
import csv
import re
import time
from datetime import datetime
import joblib  

CSV_FILE = 'threat_log.csv'
MODEL_PATH = "best_random_forest_model.pkl"
model = joblib.load(MODEL_PATH)
# Compile regex for URLs
URL_PATTERN = re.compile(
    r'https?://[^\s"<>]+'
)

# Setup CSV file
def init_csv():
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        headers = ["timestamp", "src_ip", "url"] + ['pathurlRatio','delimeter_Domain', 'domain_token_count','SymbolCount_Domain','entropy_path','Directory_LetterCount', 'having_Sub_Domain','pathDomainRatio','pathLength', 'subDirLen','sub-Directory_LongestWordLength','avgpathtokenlen','domainlength','URLQueries_variable','NumberRate_Domain','host_DigitCount','Path_LongestWordLength','LongestPathTokenLength','Extension_LetterCount','entropy_url'] + ['label']#["timestamp", "src_ip", "url"] + ['URL_Length', 'having_Sub_Domain', 'domain_token_count','path_token_count', 'charcompvowels', 'URL_Letter_Count','host_letter_count', 'Directory_LetterCount', 'ldl_url', 'domainlength','pathLength', 'pathurlRatio', 'domainUrlRatio', 'pathDomainRatio','SymbolCount_URL', 'SymbolCount_Domain', 'entropy_url', 'entropy_path','spcharUrl', 'delimeter_Count'] + ['label']
        writer.writerow(headers)

# Callback for each sniffed packet
def process_packet(packet):
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode(errors='ignore')
            urls = URL_PATTERN.findall(payload)
            for url in urls:
                # print(url)
                features = extract_features_from_url(url)
                feature_values = []
                l = ['pathurlRatio','delimeter_Domain', 'domain_token_count','SymbolCount_Domain','entropy_path','Directory_LetterCount', 'having_Sub_Domain','pathDomainRatio','pathLength', 'subDirLen','sub-Directory_LongestWordLength','avgpathtokenlen','domainlength','URLQueries_variable','NumberRate_Domain','host_DigitCount','Path_LongestWordLength','LongestPathTokenLength','Extension_LetterCount','entropy_url']#['URL_Length', 'having_Sub_Domain', 'domain_token_count','path_token_count', 'charcompvowels', 'URL_Letter_Count','host_letter_count', 'Directory_LetterCount', 'ldl_url', 'domainlength','pathLength', 'pathurlRatio', 'domainUrlRatio', 'pathDomainRatio','SymbolCount_URL', 'SymbolCount_Domain', 'entropy_url', 'entropy_path','spcharUrl', 'delimeter_Count']
                for i in l:
                    if i in features:
                        feature_values.append(features[i])
                    else:
                        print(i)
                prediction = model.predict([feature_values])[0]
                # print(f"[*] Features: {features}")
                final_list = feature_values + [int(prediction)]
                # print(f"[*] Features: {final_list}")
                with open(CSV_FILE, mode='a', newline='') as file:
                    writer = csv.writer(file)
                    row = [datetime.now().isoformat(), packet[0][1].src, url] + final_list
                    writer.writerow(row)
                print(f"[+] Logged: {url,row}")
        except Exception as e:
            print(f"[!] Error processing packet: {e}")

def start_sniffing():
    print("[*] Starting network traffic monitoring...")
    sniff(filter="tcp port 80 or tcp port 443",iface="eth0", prn=process_packet, store=0)

if __name__ == "__main__":
    init_csv()
    start_sniffing()
