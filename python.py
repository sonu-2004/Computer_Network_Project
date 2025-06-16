from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import time

LOG_FILE = "ids_alerts.txt"
WINDOW = 5
THRESHOLD = 10
TARGET_IP = "192.168.1.10"

attack_tracker = {
    "SYN": defaultdict(list),
    "NULL": defaultdict(list),
    "FIN": defaultdict(list),
    "XMAS": defaultdict(list),
}

def log_alert(message):
    print(message)
    with open(LOG_FILE, "a") as f:
        f.write(message + "\n")

def detect_attacks(pkt):
    now = time.time()

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if TARGET_IP not in [src_ip, dst_ip]:
            return

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            dst_port = pkt[TCP].dport

            if flags == 0x02:
                attack_tracker["SYN"][src_ip].append((now, dst_port))
                attack_tracker["SYN"][src_ip] = [(t, p) for t, p in attack_tracker["SYN"][src_ip] if now - t <= WINDOW]
                unique_ports = set(p for _, p in attack_tracker["SYN"][src_ip])
                if len(unique_ports) >= THRESHOLD:
                    log_alert(f"[{datetime.now()}] SYN Scan detected from {src_ip}")
                    attack_tracker["SYN"][src_ip] = []

            elif flags == 0x00:
                attack_tracker["NULL"][src_ip].append(now)
                attack_tracker["NULL"][src_ip] = [t for t in attack_tracker["NULL"][src_ip] if now - t <= WINDOW]
                if len(attack_tracker["NULL"][src_ip]) >= THRESHOLD:
                    log_alert(f"[{datetime.now()}] NULL Scan detected from {src_ip}")
                    attack_tracker["NULL"][src_ip] = []

            elif flags == 0x01:
                attack_tracker["FIN"][src_ip].append(now)
                attack_tracker["FIN"][src_ip] = [t for t in attack_tracker["FIN"][src_ip] if now - t <= WINDOW]
                if len(attack_tracker["FIN"][src_ip]) >= THRESHOLD:
                    log_alert(f"[{datetime.now()}] FIN Scan detected from {src_ip}")
                    attack_tracker["FIN"][src_ip] = []

            elif flags == 0x29:
                attack_tracker["XMAS"][src_ip].append(now)
                attack_tracker["XMAS"][src_ip] = [t for t in attack_tracker["XMAS"][src_ip] if now - t <= WINDOW]
                if len(attack_tracker["XMAS"][src_ip]) >= THRESHOLD:
                    log_alert(f"[{datetime.now()}] XMAS Scan detected from {src_ip}")
                    attack_tracker["XMAS"][src_ip] = []

print(f"IDS running... Detecting atacks...")
sniff(filter="ip", prn=detect_attacks, store=0)
