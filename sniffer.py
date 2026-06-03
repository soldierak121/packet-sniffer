from scapy.all import sniff, IP, TCP, UDP

packet_count = 0

def process_packet(packet):
    global packet_count
    if IP in packet:
        src_ip = packet[IP].src
        dest_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            proto_name = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            proto_name = "UDP"
        else:
            src_port = 0
            dest_port = 0
            proto_name = "OTHER"
        
        packet_count += 1
        print(f"[{packet_count}] [{proto_name}] {src_ip}:{src_port} -> {dest_ip}:{dest_port}")

print("Starting packet sniffer... Press Ctrl+C to stop\n")
sniff(prn=process_packet, store=0)
