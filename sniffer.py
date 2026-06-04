from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
import socket
from datetime import datetime

packet_count = 0

def get_service(port):
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP",
        110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt"
    }
    return services.get(port, "Unknown")

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

def process_packet(packet):
    global packet_count

    if IP not in packet:
        return

    src_ip = packet[IP].src
    dest_ip = packet[IP].dst
    timestamp = datetime.now().strftime("%H:%M:%S")

    # DNS detection
    if DNS in packet and packet[DNS].qr == 0:
        if DNSQR in packet:
            query = packet[DNSQR].qname.decode().rstrip('.')
            packet_count += 1
            line = f"[{packet_count}] [{timestamp}] [DNS]   {src_ip} -> {dest_ip}  Query: {query}"
            print(line)
            log(line)
            return

    # TCP/UDP detection
    if TCP in packet:
        src_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        service = get_service(dest_port) or get_service(src_port)

        # HTTP detection
        if Raw in packet and dest_port == 80:
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                if payload.startswith("GET") or payload.startswith("POST"):
                    host_line = [l for l in payload.split('\n') if l.startswith('Host:')]
                    host = host_line[0].strip() if host_line else dest_ip
                    packet_count += 1
                    line = f"[{packet_count}] [{timestamp}] [HTTP]  {src_ip} -> {host}"
                    print(line)
                    log(line)
                    return
            except:
                pass

        packet_count += 1
        hostname = get_hostname(dest_ip)
        line = f"[{packet_count}] [{timestamp}] [{service:7}] {src_ip}:{src_port} -> {hostname}:{dest_port}"
        print(line)
        log(line)

    elif UDP in packet:
        src_port = packet[UDP].sport
        dest_port = packet[UDP].dport
        service = get_service(dest_port) or get_service(src_port)
        packet_count += 1
        line = f"[{packet_count}] [{timestamp}] [{service:7}] {src_ip}:{src_port} -> {dest_ip}:{dest_port}"
        print(line)
        log(line)

def log(line):
    with open("packets.log", "a") as f:
        f.write(line + "\n")

print("=" * 60)
print("  PACKET SNIFFER v2.0 - Press Ctrl+C to stop")
print("=" * 60)
sniff(prn=process_packet, store=0)
