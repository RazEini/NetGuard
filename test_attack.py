#!/usr/bin/env python3
"""
NetGuard NIDS - Safe Attack Simulator Script
Simulates various attack patterns (DPI, Port Scanning, SYN Flood, Port 0)
to validate NIDS detection rules and observability pipelines safely.
"""

from scapy.all import IP, TCP, UDP, Raw, send
import time
import sys

# Target IP - Change this to your NIDS interface IP or 127.0.0.1 for local testing
TARGET_IP = "127.0.0.1"


def print_step(title):
    print(f"\n{'='*50}\n[+] {title}\n{'='*50}")


def test_dpi_signatures():
    """
    Simulates L7 Payload attacks (SQL Injection, Credential Leak, Path Traversal)
    """
    print_step("Testing DPI Engine (Layer 7 Signatures)")

    payloads = [
        ("SQL Injection", "GET /products?id=1' UNION SELECT username, password FROM users-- HTTP/1.1\r\n\r\n"),
        ("Cleartext Credentials", "POST /login HTTP/1.1\r\nHost: test.com\r\n\r\nuser=admin&password=123456&secret=key"),
        ("Path Traversal", "GET /../../../../etc/passwd HTTP/1.1\r\nHost: victim.com\r\n\r\n"),
        ("Command Injection", "POST /api/exec HTTP/1.1\r\n\r\ncmd=cat /etc/shadow; id; whoami"),
    ]

    for name, payload in payloads:
        print(f"  [>] Sending {name} payload...")
        pkt = IP(dst=TARGET_IP) / TCP(dport=80) / Raw(load=payload)
        send(pkt, verbose=False)
        time.sleep(0.2)

    print("[✔] DPI Test Suite Finished!")


def test_port_scan():
    """
    Simulates a horizontal port scan across 25 distinct ports (TCP SYN)
    """
    print_step("Testing Port Scan Detection (Sliding Window)")
    print("  [>] Scanning ports 1000 to 1025...")

    for port in range(1000, 1026):
        pkt = IP(dst=TARGET_IP) / TCP(dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)  # Fast enough to trigger threshold, safe for network

    print("[✔] Port Scan Test Finished!")


def test_port_zero():
    """
    Simulates edge-case scan targeting TCP Port 0 (Verifies Port 0 Bug Fix)
    """
    print_step("Testing Port 0 Detection (Edge Case)")
    print("  [>] Sending packet targeting TCP Port 0...")

    pkt = IP(dst=TARGET_IP) / TCP(dport=0, flags="S")
    send(pkt, verbose=False)

    print("[✔] Port 0 Test Finished!")


def test_syn_flood():
    """
    Simulates a controlled DoS SYN Flood attack (High rate in short time)
    """
    print_step("Testing DoS / SYN Flood Detection")
    print("  [>] Bursting 150 SYN packets to port 80...")

    for _ in range(150):
        pkt = IP(dst=TARGET_IP) / TCP(dport=80, flags="S")
        send(pkt, verbose=False)

    print("[✔] SYN Flood Test Finished!")


def main():
    print("🕵️  NetGuard Attack Simulator Initializing...")
    print(f"🎯 Target IP set to: {TARGET_IP}")
    print("⚠️  Safe mode active: Sending synthetic packets only.\n")

    try:
        test_dpi_signatures()
        time.sleep(1)

        test_port_scan()
        time.sleep(1)

        test_port_zero()
        time.sleep(1)

        test_syn_flood()

        print("\n" + "="*50)
        print("🎉 All test vectors executed successfully!")
        print("📊 Check your Grafana Dashboard and Loki logs for alerts.")
        print("="*50)

    except PermissionError:
        print("\n❌ Error: Permission denied!")
        print("👉 Raw Sockets require Administrator / Root privileges.")
        print("   On Windows: Run PowerShell / CMD as Administrator.")
        print("   On Linux: Run with 'sudo python test_attack.py'")
        sys.exit(1)


if __name__ == "__main__":
    main()
