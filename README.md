<h1 align="center"> 🕵️ NetGuard – Hybrid Python/C NIDS & Observability Engine </h1>

<p align="center">
  A full end-to-end real-time <strong>Network Intrusion Detection & Prevention System (NIDS/NIPS)</strong>.
  <br>
  Combines a Multi-threaded Python (Scapy) capture and analysis engine with a <strong>Native C-Extension DPI Engine (Batch-Optimized)</strong>, Sliding-Window anomaly detection, OS Firewall Active Defense, and a fully code-managed monitoring stack (<strong>Dashboard as Code</strong>) on <strong>Docker (Grafana + Loki + Promtail)</strong>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
  <img src="https://img.shields.io/badge/DPI-C_Extension-00599C?logo=c&logoColor=white" alt="C Badge">
  <img src="https://img.shields.io/badge/Library-Scapy-red" alt="Scapy Badge">
  <img src="https://img.shields.io/badge/Stack-Docker_Compose-2496ED?logo=docker" alt="Docker Badge">
  <img src="https://img.shields.io/badge/Monitoring-Grafana-F46800?logo=grafana" alt="Grafana Badge">
  <img src="https://img.shields.io/badge/Logs-Loki_%26_Promtail-orange" alt="Loki Badge">
  <img src="https://img.shields.io/badge/Security-DPI_%26_NIDS-brightgreen" alt="NIDS Badge">
  <img src="https://img.shields.io/badge/IaC-Dashboards_as_Code-blueviolet" alt="IaC Badge">
</p>

---

## 🔎 Overview & Architecture

**NetGuard** provides a complete solution for monitoring, analyzing, and responding to network security events across OSI layers 3, 4, and 7.
The architecture is built on a continuous Producer-Consumer pipeline that separates low-level packet capture, real-time threat analysis, and structured observability shipping:

```mermaid
flowchart LR
    %% Traffic Input
    NIC[📡 NIC] -->|Raw Packets| SnifferThread[🐍 Sniffer Thread<br>Scapy store=0]

    %% Core Engine
    subgraph Engine [Python NIDS Core Engine]
        SnifferThread -->|Non-blocking Put| Queue[📦 Queue<br>maxsize=10000]
        Queue -->|Get Packet| Worker[⚙️ Worker Pool]

        subgraph Detection [Detection & Defense]
            Worker -->|L3/L4 Window| Anomaly[🛡️ DoS / Scan Detector]
            Worker -->|L7 Payload| DPI[⚡ Native C DPI Engine]
            Anomaly -->|Threshold Breach| Firewall[🧱 OS Firewall<br>netsh / iptables]
            Anomaly & DPI -->|Update| State[🔒 State & Blacklist]
        end

        GC[🧹 GC Thread] -->|Clean Every 30s| State
    end

    %% Logging & Observability
    Worker -->|JSON Log| LogFile[📄 logs/network_security.json]
    LogFile --> Promtail[🔄 Promtail Container]
    Promtail -->|Push| Loki[🗄️ Loki DB]
    Loki --> Grafana[📊 Grafana Dashboard]
```

---

## 📊 Dashboard Preview

Live view of the **NetGuard Security Overview** Grafana dashboard, provisioned automatically from code.

<p align="center">
  <img src="assets/dashboard_overview.png" alt="NetGuard Live Security Log Stream & Events Distribution" width="95%">
  <br><em>Live JSON log stream with DNS query events, alongside real-time Security Events Distribution and Threat Timeline panels.</em>
</p>

<p align="center">
  <img src="assets/dashboard_threat_detection.png" alt="NetGuard DoS Detection & DNS Tunneling Alert" width="95%">
  <br><em>Active Defense in action — a DoS/SYN Flood attack triggers automatic IP isolation, alongside a DNS Tunneling detection alert (Shannon entropy-based).</em>
</p>

<p align="center">
  <img src="assets/dashboard_analytics.png" alt="NetGuard Security Events Breakdown & Top Suspicious Source IPs" width="95%">
  <br><em>Full event-type breakdown (Port Scans, Stealth Scans, DPI Alerts, DoS Attacks) with Top Suspicious Source IPs and Total Security Alerts panels.</em>
</p>

---

## ⚡ Performance & Resilience Analysis

- **Memory Backpressure & Drop Policy** — The engine utilizes a bounded `Queue(maxsize=10000)` combined with `store=0` in Scapy to ensure zero in-memory packet buffering by the sniffer thread. Under high-throughput conditions, excess packets are dropped safely rather than causing Out-Of-Memory (OOM) fatal crashes.
- **Concurrency & C-Level Unlocking** — Low-level packet capture executes within native socket primitives (C-level libpcap/WinPcap), releasing Python's Global Interpreter Lock (GIL) and allowing the background worker thread and garbage collector thread to execute processing tasks concurrently.
- **Thread Safety & Granular Locking** — Multi-threaded access to volatile state structures (`syn_history`, `port_history`, `blacklist`) is protected using explicit `threading.Lock` primitives to guarantee atomic read/write state transitions without data races.
- **Active Defense & OS Firewall Integration** — Automatically triggers dynamic OS firewall mitigation rules (`netsh advfirewall` on Windows, `iptables` on Linux) upon identifying DoS/SYN Flood attacks. Commands execute asynchronously in detached daemon threads to keep processing queues zero-latency.
- **Deterministic Resource Cleanup (Garbage Collector)** — Dormant IP records and expired blacklist entries are purged every 30 seconds by a background garbage collection thread in bounded $O(N)$ time, ensuring steady memory utilization under sustained traffic.

---

## 🏎️ DPI Native C Engine Performance

- **Batch Processing & Bounds-Checked Safety** — By eliminating Python FFI execution overhead and passing contiguous memory blocks directly to native C primitives, payload scanning avoids GIL bottlenecks. The engine uses bounds-checked `memchr`/`memcmp` scanning to prevent Out-Of-Bounds reads and Null-Byte truncation issues on raw binary network traffic.
- **Micro-Benchmark Results (100,000 Packets Evaluation)**:

| Engine Implementation | Execution Time | Throughput | Acceleration |
| :--- | :--- | :--- | :--- |
| 🐍 **Python Pure** | `0.3134 sec` | `319,038 Packets/sec` | Baseline (1.0x) |
| ⚡ **Native C Extension (Safe)** | `0.0395 sec` | `2,532,165 Packets/sec` | **7.94x Faster** |

> **Run Benchmark Locally:**
> ```bash
> # Linux / macOS
> make -C c_src
> # Windows (GCC) — requires MinGW/MSYS2 installed
> gcc -shared -O3 -march=native -o libdpi.dll c_src/dpi.c
>
> python benchmark_dpi.py
> ```

---

## 📂 Project Structure

```text
NetGuard/
├── assets/                          # Static Documentation Assets (Dashboard Screenshots)
│   ├── dashboard_overview.png
│   ├── dashboard_threat_detection.png
│   └── dashboard_analytics.png
├── benchmark_dpi.py                # Native C vs Python DPI Micro-Benchmark
├── c_src/                          # Low-Level Native C Extensions
│   ├── dpi.c                       # Native C DPI Engine (Batch Engine)
│   └── Makefile                    # C Compilation Setup
├── grafana/
│   └── dashboards/                 # Standard JSON Dashboard (Git Version-Controlled)
│       └── dashboard-NetGuard Security Overview.json
├── provisioning/                   # Grafana Automated Provisioning Configs
│   ├── dashboards/
│   │   └── dashboards.yml
│   └── datasources/
│       └── datasources.yml
├── logs/                           # Runtime Log Directory (Ignored by Git)
├── .env.example
├── .gitignore
├── docker-compose.yml
├── main.py                         # NIDS Core Engine (Thread-Safe & GC Refactored)
├── promtail-config.yml
├── requirements.txt
└── test_attack.py                  # Traffic Simulator
```

---

## 🚀 Core Features

| Domain | Feature | Status | Description | Performance Indicator |
| :--- | :--- | :---: | :--- | :--- |
| 📡 **Network** | Real-time L2-L7 Sniffing | ✅ | Real-time capture and analysis of IP, TCP, UDP, and DNS traffic while preventing memory overflow (`store=0`). | Zero-copy capture, O(1) enqueue |
| 🛡️ **Cyber Security** | Sliding-Window & Stealth Detection | ✅ | Detects **DoS (SYN Flood)**, standard port scans, and **Stealth Scans (NULL, FIN, XMAS)** via moving time windows. | O(1) queue operations |
| 🧬 **DNS Security** | DNS Tunneling Detection | ✅ | Shannon Entropy calculation & query length evaluation to catch exfiltration over DNS. | O(N) entropy check |
| ⚡ **Active Defense** | Dynamic IP Isolation & OS Firewall | ✅ | Active mitigation mechanism that dynamically injects OS firewall rules (`netsh` / `iptables`) to block malicious hosts upon threshold breach. | Non-blocking async execution, O(1) blacklist check |
| 🔍 **DPI Engine** | Deep Packet Inspection | ✅ | Byte-level Raw Payload scanning leveraging a **Native C Extension (Batch-Optimized)** to search for credential leakages and injection patterns in parallel. | O(N+M) string matching, 8x-10x native acceleration |
| ⚙️ **Architecture** | Producer-Consumer & Thread-Safety | ✅ | Bounded `Queue`, `threading.Lock` primitives, and a dedicated background Garbage Collector thread to prevent memory leaks. | Bounded queue, backpressure-safe |
| 📊 **Observability & IaC** | Dashboard as Code (Grafana + Loki) | ✅ | Five pre-defined dashboards in standard JSON format, automatically loaded on container startup via Provisioning files. | Instant provisioning on boot |
| 📝 **Logging** | Structured JSON Dual-Stream | ✅ | Colorized console output alongside structured JSON log writes (`logs/network_security.json`), tailored for collection by Promtail. | Low-overhead async writes |
| 🧪 **Testing** | Traffic Attack Simulator | ✅ | Simulation script (`test_attack.py`) that generates synthetic attack traffic to validate detection mechanisms. | Configurable synthetic load |

---

## 🛠️ Technologies & Architectural Highlights

- **Python & Scapy** — Raw-socket-level packet capture, protocol parsing, and deep payload-level inspection (DPI).
- **Native C Extension (ctypes)** — Batch-optimized, memory-safe C DPI engine invoked via ctypes, delivering an **8x–10x** bounds-checked throughput acceleration over pure Python.
- **Producer-Consumer Architecture** — Full separation between packet capture and analysis via `queue.Queue(maxsize=10000)`, preventing packet loss under load.
- **Thread-Safety & Active Defense** — Whitelist/Blacklist state management guarded by `threading.Lock` to prevent data races, integrated with background dynamic OS Firewall rule injection (`netsh` / `iptables`).
- **Background Garbage Collector** — A dedicated background thread that cleans up stale data structures (Sliding Window History & Blacklist) from memory every 30 seconds, synchronously and thread-safely, ensuring zero memory leaks from dormant IP addresses.
- **Promtail & Grafana Loki** — Shipping of structured JSON logs from the local logs directory and indexing them in Loki.
- **Dashboards as Code (IaC)** — Full version control of 5 dashboards in Git under `grafana/dashboards/`, automatically loaded into Grafana on container startup.
- **Docker Compose Stack** — One-click deployment of the entire observability infrastructure.

---

## 📋 Prerequisites

- **Git** — Required to clone the repository.
- **Docker & Docker Compose** — For running Loki, Promtail, and Grafana.
- **Python 3.10+** — Required for running the NIDS engine and test suite.
- **GCC / Make** — Required for compiling the native C DPI engine shared object (`libdpi.so` on Linux, `libdpi.dylib` on macOS, `libdpi.dll` on Windows).
- **Administrator / Root Privileges** — Required to capture raw socket traffic via Scapy and inject OS Firewall blocking rules (or use the least-privilege `setcap` option below on Linux).
- **Npcap (Windows only)** — Required for Scapy to capture raw packets on Windows network adapters.

---

## 📝 JSON Log Structure (Structured Logging)

```json
{
  "timestamp": "2026-08-06T10:30:15.123456",
  "level": "WARNING",
  "message": "[PORT SCAN DETECTED] Host 10.0.0.4 scanned 18 unique ports",
  "logger": "NetworkGuardian",
  "src_ip": "10.0.0.4",
  "event_type": "PORT_SCAN",
  "details": "18 ports scanned"
}
```

---

## ⚙️ Installation & Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/RazEini/NetGuard.git
cd NetGuard

# 2. Environment Setup
cp .env.example .env  # Set your Grafana password in .env

# 3. Start Observability Stack (Grafana, Loki, Promtail)
# Grafana will automatically provision all dashboards from grafana/dashboards/
docker compose up -d

# 4. Setup Python Environment
python -m venv .venv
.\.venv\Scripts\activate     # On Windows
source .venv/bin/activate    # On Linux/Mac
pip install -r requirements.txt

# 5. Compile the Native C DPI Engine & Run Benchmark (Optional)
make -C c_src                                                # Linux / macOS
gcc -shared -O3 -march=native -o libdpi.dll c_src/dpi.c      # Windows — requires MinGW/MSYS2 installed
python benchmark_dpi.py                                      # Verify ~8x memory-safe speedup
```

### 6a. Run NIDS Engine — Linux / macOS

```bash
# Principle of Least Privilege - grant raw socket capability without full sudo:
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
.venv/bin/python main.py

# Or run directly with root:
sudo .venv/bin/python main.py
```

### 6b. Run NIDS Engine — Windows

```powershell
# Run PowerShell / CMD as Administrator:
python main.py
```

### 7. Run Attack Simulator (in a separate terminal)

```bash
# Automatically targets local active IP:
python test_attack.py

# Or target a specific IP address explicitly:
python test_attack.py <TARGET_IP>
```

📊 **Accessing Grafana:** Open your browser to [http://localhost:3000](http://localhost:3000) (username: `admin`, password set in `.env`). All dashboards will already be loaded and ready to use!

---

## 📄 License

This project is distributed under the **MIT** license – free to use and modify for educational and research purposes.

---

<p align="center"><strong>👨‍💻 Raz Eini (2026)</strong></p>
