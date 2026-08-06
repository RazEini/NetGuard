from scapy.all import IP, TCP, UDP, Raw, send
import time

TARGET_IP = "10.100.102.1"  # ה-IP מתוך ה-Logs של הסניפר שלך

def test_dpi():
    print("[+] Sending DPI Attack Payload...")
    # שליחת פאקטת TCP עם ה-Payload password
    pkt = IP(dst=TARGET_IP)/TCP(dport=80)/Raw(load="GET /login?user=admin&password=123 HTTP/1.1\r\n\r\n")
    send(pkt, verbose=False)
    print("[✔] DPI Packet Sent!")

def test_port_scan():
    print("[+] Simulating Port Scan (20 ports)...")
    # שליחת פאקטות ל-20 פורטים שונים מהר מאוד
    for port in range(1000, 1022):
        pkt = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)
    print("[✔] Port Scan Finished!")

if __name__ == "__main__":
    test_dpi()
    time.sleep(1)
    test_port_scan()