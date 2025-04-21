from scapy.all import sniff, Raw

def show_payload(packet):
    if packet.haslayer(Raw):
        try:
            print(packet[Raw].load.decode(errors="ignore"))
        except:
            pass

sniff(filter="tcp port 80 or tcp port 443", iface="eth0", prn=show_payload)
