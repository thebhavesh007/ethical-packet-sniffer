from scapy.all import sniff, IP
from datetime import datetime

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = packet.proto
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print("=" * 60)
        print(f"Packet Captured at {timestamp}")
        print(f"Source IP      : {ip_layer.src}")
        print(f"Destination IP : {ip_layer.dst}")
        print(f"Protocol       : {protocol}")

        try:
            print(f"Payload        : {bytes(packet.payload)}")
        except Exception:
            print("Payload could not be decoded.")

        print("=" * 60)

def start_sniffer():
    print("🔍 Packet sniffing started... (Press Ctrl+C to stop)\n")
    sniff(filter="ip", prn=analyze_packet, store=False)

if __name__ == "__main__":
    print("=== Packet Sniffer Tool ===")
    start_sniffer()
