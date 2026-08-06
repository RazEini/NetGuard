import json
import logging
import os
import threading
import time
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

class JsonFileFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger": record.name
        }
        
        if hasattr(record, 'src_ip'):
            log_record['src_ip'] = record.src_ip
        if hasattr(record, 'event_type'):
            log_record['event_type'] = record.event_type
        if hasattr(record, 'details'):
            log_record['details'] = record.details

        return json.dumps(log_record, ensure_ascii=False)

def setup_logger():
    logger = logging.getLogger("NetworkGuardian")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    os.makedirs("logs", exist_ok=True)

    ch = logging.StreamHandler()
    ch.setFormatter(ColoredConsoleFormatter('%(asctime)s [%(levelname)s] %(message)s'))
    
    fh = logging.FileHandler(os.path.join("logs", "network_security.json"), encoding="utf-8")
    fh.setFormatter(JsonFileFormatter())

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger

class NetworkGuardian:
    def __init__(self, dos_threshold=50, scan_threshold=15, time_window_sec=10, cleanup_interval_sec=30):
        self.logger = setup_logger()
        self.packet_queue = Queue(maxsize=10000)
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        
        self.DOS_THRESHOLD = dos_threshold
        self.SCAN_THRESHOLD = scan_threshold
        self.TIME_WINDOW = timedelta(seconds=time_window_sec)
        self.CLEANUP_INTERVAL = cleanup_interval_sec
        
        self.whitelist = set()
        self.blacklist = {}  # {ip: unblock_time}
        
        self.syn_history = defaultdict(deque)
        self.port_history = defaultdict(deque)

        self.suspicious_keywords = [b"admin", b"password", b"etc/passwd", b"select * from"]

    def _enqueue_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
            
        src_ip = pkt[IP].src
        now = datetime.now()
        
        with self.lock:
            if src_ip in self.whitelist:
                return

            if src_ip in self.blacklist:
                if now < self.blacklist[src_ip]:
                    return
                else:
                    del self.blacklist[src_ip]

        if not self.packet_queue.full():
            self.packet_queue.put_nowait(pkt)

    def _clean_old_records(self, history_deque, now):
        while history_deque and (now - history_deque[0][0]) > self.TIME_WINDOW:
            history_deque.popleft()

    def _cleanup_worker(self):
        while not self.stop_event.is_set():
            time.sleep(self.CLEANUP_INTERVAL)
            now = datetime.now()
            
            with self.lock:
                expired_syn_ips = []
                for ip, history in list(self.syn_history.items()):
                    self._clean_old_records(history, now)
                    if not history:
                        expired_syn_ips.append(ip)
                for ip in expired_syn_ips:
                    del self.syn_history[ip]

                expired_port_ips = []
                for ip, history in list(self.port_history.items()):
                    self._clean_old_records(history, now)
                    if not history:
                        expired_port_ips.append(ip)
                for ip in expired_port_ips:
                    del self.port_history[ip]

                expired_blacklist = [ip for ip, exp_time in self.blacklist.items() if now >= exp_time]
                for ip in expired_blacklist:
                    del self.blacklist[ip]

    def analyze_packet(self, pkt):
        now = datetime.now()
        src_ip = pkt[IP].src

        if pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                if not query.endswith(".local."):
                    self.logger.info(
                        f"[DNS] Device {src_ip} query: {query}",
                        extra={"src_ip": src_ip, "event_type": "DNS_QUERY", "details": query}
                    )
            except Exception as e:
                self.logger.debug(f"[DNS] Parsing error: {e}")

        dst_port = None
        is_syn = False

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            if pkt[TCP].flags & 0x02:
                is_syn = True
        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        with self.lock:
            if src_ip in self.whitelist:
                return

            if is_syn:
                syn_deque = self.syn_history[src_ip]
                self._clean_old_records(syn_deque, now)
                syn_deque.append((now, None))

                if len(syn_deque) > self.DOS_THRESHOLD:
                    self.blacklist[src_ip] = now + timedelta(minutes=5)
                    self.logger.critical(
                        f"[DoS DETECTED] Isolating IP: {src_ip} for 5 minutes",
                        extra={"src_ip": src_ip, "event_type": "DOS_ATTACK", "details": "SYN Flood threshold exceeded"}
                    )
                    syn_deque.clear()

            if dst_port:
                ports_deque = self.port_history[src_ip]
                self._clean_old_records(ports_deque, now)
                ports_deque.append((now, dst_port))

                unique_ports = {port for _, port in ports_deque}
                if len(unique_ports) > self.SCAN_THRESHOLD:
                    self.logger.warning(
                        f"[PORT SCAN DETECTED] Host {src_ip} scanned {len(unique_ports)} unique ports",
                        extra={"src_ip": src_ip, "event_type": "PORT_SCAN", "details": f"{len(unique_ports)} ports scanned"}
                    )
                    ports_deque.clear()

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.lower()
            for kw in self.suspicious_keywords:
                if kw in payload:
                    kw_str = kw.decode('utf-8', errors='ignore')
                    self.logger.warning(
                        f"[SECURITY DPI] Suspicious keyword '{kw_str}' from {src_ip}",
                        extra={"src_ip": src_ip, "event_type": "DPI_ALERT", "details": f"Keyword match: {kw_str}"}
                    )

    def packet_worker(self):
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
                self.analyze_packet(packet)
                self.packet_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                self.logger.error(f"[WORKER ERROR] {e}")

    def start(self):
        self.logger.info("NetworkGuardian Engine Starting...")
        
        worker = threading.Thread(target=self.packet_worker, daemon=True)
        worker.start()

        cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        cleanup_thread.start()

        self.logger.info("[*] Engine Active. Sniffing packets...")
        try:
            sniff(
                prn=self._enqueue_packet, 
                store=0, 
                filter="ip", 
                stop_filter=lambda _: self.stop_event.is_set()
            )
        except KeyboardInterrupt:
            self.logger.info("Shutting down engine...")
            self.stop_event.set()
            worker.join(timeout=2)
            cleanup_thread.join(timeout=2)

if __name__ == "__main__":
    guardian = NetworkGuardian()
    guardian.start()
