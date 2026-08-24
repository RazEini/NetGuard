import math
import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from queue import Queue, Empty
from scapy.all import sniff, IP, TCP, UDP, Raw, DNSQR

try:
    import colorama
    colorama.init()
except ImportError:
    pass

try:
    import ahocorasick
    HAS_AHOCORASICK = True
except ImportError:
    HAS_AHOCORASICK = False


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
            "message": str(record.getMessage()),
            "logger": record.name
        }

        if hasattr(record, 'src_ip'):
            log_record['src_ip'] = str(record.src_ip)
        if hasattr(record, 'event_type'):
            log_record['event_type'] = str(record.event_type)
        if hasattr(record, 'details'):
            log_record['details'] = str(record.details)

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


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy of a string to detect encrypted/encoded DNS subdomains."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    frequencies = defaultdict(int)
    for char in text:
        frequencies[char] += 1
    for count in frequencies.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return entropy


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

        # Build Aho-Corasick Automaton for O(N) DPI safely
        if HAS_AHOCORASICK:
            self.automaton = ahocorasick.Automaton()
            for idx, key in enumerate(self.suspicious_keywords):
                # pyahocorasick requires string keys
                key_str = key.decode('utf-8', errors='ignore') if isinstance(key, bytes) else str(key)
                self.automaton.add_word(key_str, (idx, key_str))
            self.automaton.make_automaton()
            self.logger.info("[+] Aho-Corasick DPI Engine initialized successfully.")
        else:
            self.automaton = None
            self.logger.info("[+] Note: 'pyahocorasick' library not found. Falling back to native string searching.")

    def _is_blacklisted(self, src_ip, now):
        """Helper function to evaluate blacklist state under lock."""
        if src_ip in self.blacklist:
            if now < self.blacklist[src_ip]:
                return True
            else:
                del self.blacklist[src_ip]
        return False

    def _enqueue_packet(self, pkt):
        if not pkt.haslayer(IP) or self.packet_queue.full():
            return

        src_ip = pkt[IP].src
        now = datetime.now()

        # Fast non-blocking check before acquiring lock
        if src_ip in self.whitelist:
            return

        with self.lock:
            if src_ip in self.whitelist or self._is_blacklisted(src_ip, now):
                return

        try:
            self.packet_queue.put_nowait(pkt)
        except Exception:
            pass  # Queue full, drop packet safely under pressure

    def _clean_old_records(self, history_deque, now):
        while history_deque and (now - history_deque[0][0]) > self.TIME_WINDOW:
            history_deque.popleft()

    def _cleanup_worker(self):
        while not self.stop_event.is_set():
            time.sleep(self.CLEANUP_INTERVAL)
            now = datetime.now()

            with self.lock:
                # Cleanup SYN history
                for ip in list(self.syn_history.keys()):
                    history = self.syn_history[ip]
                    self._clean_old_records(history, now)
                    if not history:
                        del self.syn_history[ip]

                # Cleanup Port Scan history
                for ip in list(self.port_history.keys()):
                    history = self.port_history[ip]
                    self._clean_old_records(history, now)
                    if not history:
                        del self.port_history[ip]

                # Cleanup expired Blacklist entries
                expired_blacklist = [ip for ip, exp_time in self.blacklist.items() if now >= exp_time]
                for ip in expired_blacklist:
                    del self.blacklist[ip]

    def _check_dpi(self, payload: bytes, src_ip: str):
        payload_lower_str = payload.lower().decode('utf-8', errors='ignore')
        
        if self.automaton:
            for end_index, (idx, kw_str) in self.automaton.iter(payload_lower_str):
                self.logger.warning(
                    f"[SECURITY DPI] Suspicious keyword '{kw_str}' from {src_ip}",
                    extra={"src_ip": src_ip, "event_type": "DPI_ALERT", "details": f"Keyword match: {kw_str}"}
                )
        else:
            payload_lower_bytes = payload.lower()
            for kw in self.suspicious_keywords:
                if kw in payload_lower_bytes:
                    kw_str = kw.decode('utf-8', errors='ignore')
                    self.logger.warning(
                        f"[SECURITY DPI] Suspicious keyword '{kw_str}' from {src_ip}",
                        extra={"src_ip": src_ip, "event_type": "DPI_ALERT", "details": f"Keyword match: {kw_str}"}
                    )

    def analyze_packet(self, pkt):
        now = datetime.now()
        src_ip = pkt[IP].src

        with self.lock:
            if src_ip in self.whitelist or self._is_blacklisted(src_ip, now):
                return

        # 1. DNS Inspection & Tunneling Detection
        if pkt.haslayer(DNSQR):
            try:
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
                if not query.endswith(".local."):
                    entropy = calculate_entropy(query)
                    if len(query) > 60 or entropy > 4.2:
                        self.logger.warning(
                            f"[DNS TUNNELING SUSPECT] Host {src_ip} query len={len(query)} entropy={entropy:.2f}: {query}",
                            extra={"src_ip": src_ip, "event_type": "DNS_TUNNELING", "details": f"Len: {len(query)}, Entropy: {entropy:.2f}"}
                        )
                    else:
                        self.logger.info(
                            f"[DNS] Device {src_ip} query: {query}",
                            extra={"src_ip": src_ip, "event_type": "DNS_QUERY", "details": query}
                        )
            except Exception as e:
                self.logger.debug(f"[DNS] Parsing error: {e}")

        dst_port = None
        is_syn = False
        tcp_flags = None

        if pkt.haslayer(TCP):
            dst_port = pkt[TCP].dport
            tcp_flags = int(pkt[TCP].flags)
            if tcp_flags & 0x02:  # SYN Flag
                is_syn = True

            # 2. Stealth Scan Detection (NULL, FIN, XMAS)
            stealth_type = None
            if tcp_flags == 0:
                stealth_type = "NULL Scan"
            elif tcp_flags == 0x01:
                stealth_type = "FIN Scan"
            elif tcp_flags == 0x29:  # FIN + PSH + URG
                stealth_type = "XMAS Scan"

            if stealth_type:
                self.logger.warning(
                    f"[STEALTH SCAN DETECTED] {stealth_type} from {src_ip} to port {dst_port}",
                    extra={"src_ip": src_ip, "event_type": "STEALTH_SCAN", "details": f"{stealth_type} on port {dst_port}"}
                )

        elif pkt.haslayer(UDP):
            dst_port = pkt[UDP].dport

        # 3. DoS & Port Scan Detection
        with self.lock:
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

            if dst_port is not None:
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

        # 4. Deep Packet Inspection (DPI)
        if pkt.haslayer(Raw):
            self._check_dpi(pkt[Raw].load, src_ip)

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

    def start(self, num_workers=4):
        self.logger.info("NetworkGuardian Engine Starting...")

        # Initialize Worker Pool for multi-threading throughput
        workers = []
        for i in range(num_workers):
            w = threading.Thread(target=self.packet_worker, daemon=True, name=f"Worker-{i}")
            w.start()
            workers.append(w)

        cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True, name="CleanupGC")
        cleanup_thread.start()

        self.logger.info(f"[*] Engine Active. Listening with {num_workers} worker threads...")
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
            for w in workers:
                w.join(timeout=2)
            cleanup_thread.join(timeout=2)


if __name__ == "__main__":
    guardian = NetworkGuardian()
    guardian.start(num_workers=4)