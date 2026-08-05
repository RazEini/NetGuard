import logging
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP, Raw, DNSQR

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"

class ColoredConsoleFormatter(logging.Formatter):
    """פורמטר שמחיל צבעים רק על פלט ה-Console"""
    COLOR_MAP = {
        logging.WARNING: Colors.YELLOW,
        logging.ERROR: Colors.RED,
        logging.CRITICAL: Colors.RED,
        logging.INFO: Colors.CYAN
    }

    def format(self, record):
        color = self.COLOR_MAP.get(record.levelno, Colors.RESET)
        message = super().format(record)
        return f"{color}{message}{Colors.RESET}"

def setup_logger():
    logger = logging.getLogger("NetworkGuardian")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Console Handler (עם צבעים)
    ch = logging.StreamHandler()
    ch.setFormatter(ColoredConsoleFormatter('%(asctime)s [%(levelname)s] %(message)s'))
    
    # File Handler (טקסט נקי בלבד לטובת SIEM/Log parsing)
    fh = logging.FileHandler("network_security.log")
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger

class NetworkGuardian:
    def __init__(self, dos_threshold=50, scan_threshold=15, time_window_sec=10):
        self.logger = setup_logger()
        self.packet_queue = Queue(maxsize=10000) # מניעת הצפת זיכרון בלתי מוגבלת
        self.running = True
        
        self.DOS_THRESHOLD = dos_threshold
        self.SCAN_THRESHOLD = scan_threshold
        self.TIME_WINDOW = timedelta(seconds=time_window_sec)
        
        self.whitelist = set()
        self.blacklist = {} # ip -> expire_time
        
        # Sliding Windows: IP -> deque of timestamps
        self.syn_history = defaultdict(deque)
        # Sliding Windows: IP -> deque of (timestamp, port)
        self.port_history = defaultdict(deque)

        self.suspicious_keywords = [b"admin", b"password", b"etc/passwd", b"select * from"]

    def is_isolated(self, ip: str, now: datetime) -> bool:
        if ip in self.blacklist:
            if now < self.blacklist[ip]:
                return True
            del self.blacklist[ip]
        return False

    def _clean_old_records(self, history_deque: deque, now: datetime):
        """מנקה רשומות שחרגו מחלון הזמן הנייד (Sliding Window)"""
        while history_deque and (now - history_deque[0][0] if isinstance(history_deque[0], tuple) else now - history_deque[0]) > self.TIME_WINDOW:
            history_deque.popleft()

    def analyze_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        now = datetime.now()
        src_ip = pkt[IP].src

        if src_ip in self.whitelist or self.is_isolated(src_ip, now):
            return

        # 1. DNS Query Inspection
        if pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                if not query.endswith(".local."):
                    self.logger.info(f"[DNS] Device {src_ip} query: {query}")
            except Exception:
                pass

        # 2. DoS (SYN Flood) with Sliding Window
        if pkt.haslayer(TCP):
            # בדיקת Bitwise לחשיפת דגל SYN
            if pkt[TCP].flags & 0x02:
                syn_deque = self.syn_history[src_ip]
                self._clean_old_records(syn_deque, now)
                syn_deque.append(now)

                if len(syn_deque) > self.DOS_THRESHOLD:
                    self.blacklist[src_ip] = now + timedelta(minutes=5)
                    self.logger.critical(f"[DoS DETECTED] Isolating IP: {src_ip} for 5 minutes")
                    syn_deque.clear()

        # 3. Port Scanning with Sliding Window
        dst_port = None
        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        if dst_port:
            ports_deque = self.port_history[src_ip]
            self._clean_old_records(ports_deque, now)
            ports_deque.append((now, dst_port))

            unique_ports = {port for _, port in ports_deque}
            if len(unique_ports) > self.SCAN_THRESHOLD:
                self.logger.warning(f"[PORT SCAN DETECTED] Host {src_ip} scanned {len(unique_ports)} unique ports")
                ports_deque.clear()

        # 4. Deep Packet Inspection (DPI) על בסיס Bytes (חיסכון ב-Decode)
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.lower()
            for kw in self.suspicious_keywords:
                if kw in payload:
                    self.logger.warning(f"[SECURITY DPI] Suspicious keyword '{kw.decode()}' from {src_ip}")

    def packet_worker(self):
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=0.5)
                self.analyze_packet(packet)
                self.packet_queue.task_done()
            except Empty:
                continue

    def start(self):
        self.logger.info("NetworkGuardian Engine Starting...")
        worker = threading.Thread(target=self.packet_worker, daemon=True)
        worker.start()

        self.logger.info("[*] Worker active. Sniffing interface...")
        try:
            # store=0 מונע זליגת זיכרון של Scapy בתוך הזיכרון הפנימי
            sniff(prn=lambda x: self.packet_queue.put_nowait(x) if not self.packet_queue.full() else None, store=0)
        except KeyboardInterrupt:
            self.logger.info("Shutting down engine...")
            self.running = False

if __name__ == "__main__":
    guardian = NetworkGuardian()
    guardian.start()
