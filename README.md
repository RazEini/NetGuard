<h1 align="center">🕵️ NetGuard – Full-Stack NIDS & Security Observability Engine</h1>

<p align="center">
  A full end-to-end real-time <strong>Network Intrusion Detection System (NIDS)</strong>.
  <br>
  Combines a Multi-threaded Python (Scapy) capture and analysis engine with <strong>DPI</strong>, Sliding-Window anomaly detection, Active Defense mechanisms, and a fully code-managed monitoring stack (<strong>Dashboard as Code</strong>) on <strong>Docker (Grafana + Loki + Promtail)</strong>.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
  <img src="https://img.shields.io/badge/Library-Scapy-red" alt="Scapy Badge">
  <img src="https://img.shields.io/badge/Stack-Docker_Compose-2496ED?logo=docker" alt="Docker Badge">
  <img src="https://img.shields.io/badge/Monitoring-Grafana-F46800?logo=grafana" alt="Grafana Badge">
  <img src="https://img.shields.io/badge/Logs-Loki_%26_Promtail-orange" alt="Loki Badge">
  <img src="https://img.shields.io/badge/Security-DPI_%26_NIDS-brightgreen" alt="NIDS Badge">
  <img src="https://img.shields.io/badge/IaC-Dashboards_as_Code-blueviolet" alt="IaC Badge">
</p>

<hr>

<h2 align="center">🔎 Overview & Architecture</h2>
<p align="center">
  <strong>NetGuard</strong> provides a complete solution for monitoring, analyzing, and responding to network security events across OSI layers 3, 4, and 7.
  <br>
  The architecture is built on a continuous data pipeline that separates packet capture, real-time processing, and feeding data into the visualization system:
</p>

```mermaid
graph TD
    %% Traffic Input
    NIC[📡 Network Interface] -->|Raw Packets| SnifferThread[🐍 Sniffer Thread - Scapy store=0]
    
    %% Core Engine
    subgraph Engine [Python NIDS Core Engine]
        SnifferThread -->|Put Packet| Queue[📦 Bounded Queue maxsize=10000]
        Queue -->|Get Packet| Worker[⚙️ Worker Threads Pool]
        
        subgraph Detection [Detection & Active Defense]
            Worker -->|L3/L4 Sliding Window| Anomaly[🛡️ DoS / Port Scan Detector]
            Worker -->|L7 Raw Payload| DPI[🔍 DPI Engine SQLi/Creds]
            Anomaly & DPI -->|Check/Update| State[🔒 Lock-Guarded State & Blacklist]
        end
        
        GC[🧹 Background GC Thread] -->|Clean Stale State Every 30s| State
    end

    %% Logging & Observability
    Worker -->|Write JSON Log| LogFile[📄 logs/netguard.json]
    Promtail[🔄 Promtail Container] -->|Tail & Ship| LogFile
    Promtail -->|HTTP/Push| Loki[🗄️ Loki DB Container]
    Loki -->|PromQL/LogQL| Grafana[📊 Grafana Dashboard as Code]
```

<hr>

<h2 align="center">📂 Project Structure</h2>

```text
python_sniffer/
├── grafana/
│   └── dashboards/                 # Standard JSON Dashboards (Git Version-Controlled)
│       ├── dashboard-Live Security Log Stream.json
│       ├── dashboard-Security Events Distribution.json
│       ├── dashboard-Threat Timeline & Severity Levels.json
│       ├── dashboard-Top Suspicious Source IPs.json
│       └── dashboard-Total Security Alerts.json
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

<hr>

<h2 align="center">🚀 Core Features</h2>

<table align="center">
  <thead>
    <tr>
      <th align="left">Domain</th>
      <th align="left">Feature</th>
      <th align="center">Status</th>
      <th align="left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td align="left">📡 <strong>Network</strong></td>
      <td align="left">Real-time L2-L7 Sniffing</td>
      <td align="center">✅</td>
      <td align="left">Real-time capture and analysis of IP, TCP, UDP, and DNS traffic while preventing memory overflow (<code>store=0</code>).</td>
    </tr>
    <tr>
      <td align="left">🛡️ <strong>Cyber Security</strong></td>
      <td align="left">Sliding-Window Detection</td>
      <td align="center">✅</td>
      <td align="left">Detection of <strong>DoS (SYN Flood)</strong> and port scans based on a precise moving time window.</td>
    </tr>
    <tr>
      <td align="left">⚡ <strong>Active Defense</strong></td>
      <td align="left">Dynamic IP Isolation</td>
      <td align="center">✅</td>
      <td align="left">Active mitigation mechanism that isolates attacking addresses for a limited time (Blacklist with automatic expiry).</td>
    </tr>
    <tr>
      <td align="left">🔍 <strong>DPI Engine</strong></td>
      <td align="left">Deep Packet Inspection</td>
      <td align="center">✅</td>
      <td align="left">Byte-level Raw Payload scanning to detect suspicious strings (SQLi, Credentials, Path Traversal).</td>
    </tr>
    <tr>
      <td align="left">⚙️ <strong>Architecture</strong></td>
      <td align="left">Producer-Consumer & Thread-Safety</td>
      <td align="center">✅</td>
      <td align="left">Bounded <code>Queue</code>, <code>threading.Lock</code> locks, and a dedicated background Garbage Collector thread to prevent memory leaks.</td>
    </tr>
    <tr>
      <td align="left">📊 <strong>Observability & IaC</strong></td>
      <td align="left">Dashboard as Code (Grafana + Loki)</td>
      <td align="center">✅</td>
      <td align="left">Five pre-defined dashboards in standard JSON format, automatically loaded on container startup via Provisioning files.</td>
    </tr>
    <tr>
      <td align="left">📝 <strong>Logging</strong></td>
      <td align="left">Structured JSON Dual-Stream</td>
      <td align="center">✅</td>
      <td align="left">Colorized console output alongside structured JSON log writes, tailored for collection by Promtail.</td>
    </tr>
    <tr>
      <td align="left">🧪 <strong>Testing</strong></td>
      <td align="left">Traffic Attack Simulator</td>
      <td align="center">✅</td>
      <td align="left">Simulation script (<code>test_attack.py</code>) that generates synthetic attack traffic to validate detection mechanisms.</td>
    </tr>
  </tbody>
</table>

<hr>

<h2 align="center">🛠️ Technologies & Architectural Highlights</h2>

- **Python & Scapy** — Raw-socket-level packet capture, protocol parsing, and deep payload-level inspection (DPI).
- **Producer-Consumer Architecture** — Full separation between packet capture and analysis via `queue.Queue(maxsize=10000)`, preventing packet loss under load.
- **Thread-Safety & Active Defense** — Whitelist/Blacklist state management and anomaly detection guarded by `threading.Lock` to prevent data races, alongside dynamic, time-limited blocking of attacking IP addresses.
- **Background Garbage Collector** — A dedicated background thread that cleans up stale data structures (Sliding Window History & Blacklist) from memory every 30 seconds, synchronously and thread-safely, ensuring zero memory leaks from dormant IP addresses.
- **Promtail & Grafana Loki** — Shipping of structured JSON logs from the local logs directory and indexing them in Loki.
- **Dashboards as Code (IaC)** — Full version control of 5 dashboards in Git under `grafana/dashboards/`, automatically loaded into Grafana on container startup.
- **Docker Compose Stack** — One-click deployment of the entire observability infrastructure.

<hr>

<h2 align="left">📋 Prerequisites</h2>

- **Docker & Docker Compose** — For running Loki, Promtail, and Grafana.
- **Python 3.10+** — Required for running the NIDS engine and test suite.
- **Administrator / Root Privileges** — Required to capture raw socket traffic via Scapy.
- **Npcap (Windows only)** — Required for Scapy to capture raw packets on Windows network adapters.

<hr>

<h2 align="left">📝 JSON Log Structure (Structured Logging)</h2>

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

<hr>

<h2 align="left">⚙️ Installation & Quick Start</h2>

```bash
# 1. Clone the repository
git clone https://github.com/RazEini/python_sniffer.git
cd python_sniffer

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

# 5. Run NIDS Engine (Requires Administrator / Root)
# On Linux / Mac:
sudo .venv/bin/python main.py

# On Windows (Run PowerShell / CMD as Administrator):
python main.py

# 6. Run Attack Simulator (in a separate terminal)
# Automatically targets local active IP:
python test_attack.py

# Or target a specific IP address explicitly:
python test_attack.py <TARGET_IP>
```

📊 **Accessing Grafana:** Open your browser to `http://localhost:3000` (username: `admin`, password set in `.env`). All dashboards will already be loaded and ready to use!

<hr>

<h2 align="left">📄 License</h2>
<p align="left">
  This project is distributed under the <strong>MIT</strong> license – free to use and modify for educational and research purposes.
</p>

<hr>

<p align="center"><strong>👨‍💻 Raz Eini (2026)</strong></p>
