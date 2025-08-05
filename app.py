from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def process_packet(packet):
    print("="*60)
    print(f"Time: {datetime.now()}")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        if packet.haslayer(TCP):
            print("Protocol Layer: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol Layer: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                print(f"Payload: {payload.decode('utf-8', errors='ignore')}")
            except:
                print("Payload: [Non-decodable data]")

def start_sniffing(interface=None, count=0):
    print(f"Starting packet sniffer... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=process_packet, store=False,count=count)