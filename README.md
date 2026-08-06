<div dir="rtl">

  <h1 align="center">🕵️ NetGuard – Full-Stack NIDS & Security Observability Engine</h1>

  <p align="center" dir="rtl">
    מערכת <strong>Network Intrusion Detection System (NIDS)</strong> מקצה לקצה בזמן אמת.
    <br>
    משלבת מנוע לכידה וניתוח ב-Python (Scapy) בארכיטקטורת Multi-threaded, יחד עם **DPI**, זיהוי אנומליות ב-Sliding Window, וסטאק ניטור וויזואליזציה מלא ב-<strong>Docker (Grafana + Loki + Promtail)</strong>.
  </p>

  <br>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
    <img src="https://img.shields.io/badge/Library-Scapy-red" alt="Scapy Badge">
    <img src="https://img.shields.io/badge/Stack-Docker_Compose-2496ED?logo=docker" alt="Docker Badge">
    <img src="https://img.shields.io/badge/Monitoring-Grafana-F46800?logo=grafana" alt="Grafana Badge">
    <img src="https://img.shields.io/badge/Logs-Loki_%26_Promtail-orange" alt="Loki Badge">
    <img src="https://img.shields.io/badge/Security-DPI_%26_NIDS-brightgreen" alt="NIDS Badge">
  </p>

  <br>

  <hr>

  <h2 align="center">🔎 Overview & Architecture</h2>
  <p align="right" dir="rtl">
    <strong>NetGuard</strong> מספקת מענה שלם לניטור ואבטחת תעבורת רשת בשכבות 3, 4 ו-7 של מודל ה-OSI. 
    <br>
    הארכיטקטורה מבוססת צינור עיבוד נתונים (Data Pipeline) מלא:
  </p>

  <div align="center" dir="ltr">
    <code>
      [ Network Traffic ] ──► [ Python/Scapy Engine ] ──► [ JSON Logs File ]
                                                                │
      [ Grafana Dashboard ] ◄── [ Loki DB ] ◄── [ Promtail ] ◄──┘
    </code>
  </div>

  <br>

  <hr>

  <h2 align="center">🚀 Core Features</h2>

  <table align="center">
    <thead>
      <tr>
        <th align="left">Domain</th>
        <th align="left">Feature</th>
        <th align="center">Status</th>
        <th align="right">Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td align="left">📡 <strong>Network</strong></td>
        <td align="left">Real-time L2-L7 Sniffing</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">לכידה וניתוח של תעבורת IP, TCP, UDP ו-DNS בזמן אמת.</td>
      </tr>
      <tr>
        <td align="left">🛡️ <strong>Cyber Security</strong></td>
        <td align="left">Sliding-Window Anomaly Detection</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">זיהוי <strong>DoS (SYN Flood)</strong> וסריקת פורטים מבוסס חלון זמן נייד מדויק.</td>
      </tr>
      <tr>
        <td align="left">🔍 <strong>DPI Engine</strong></td>
        <td align="left">Deep Packet Inspection</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">סריקת Raw Payload ברמת ה-Bytes לזיהוי מחרוזות חשודות (SQLi, Credentials, Path Traversal).</td>
      </tr>
      <tr>
        <td align="left">📊 <strong>Observability</strong></td>
        <td align="left">Grafana & Loki Dashboards</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">וויזואליזציה בזמן אמת של אירועי אבטחה, כמות הלוגים לפי חומרה (INFO/WARN/CRITICAL) ושאילתות LogQL.</td>
      </tr>
      <tr>
        <td align="left">⚙️ <strong>Architecture</strong></td>
        <td align="left">Producer-Consumer Model</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">שימוש ב-<strong>Threading & Bounded Queue</strong> למניעת Packet Loss והצפת זיכרון.</td>
      </tr>
      <tr>
        <td align="left">📝 <strong>Logging</strong></td>
        <td align="left">Structured JSON Dual-Stream</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">פלט קונסולה צבעוני במקביל לכתיבת לוגים במבנה JSON מובנה המותאם לאיסוף ע"י Promtail.</td>
      </tr>
      <tr>
        <td align="left">🧪 <strong>Testing</strong></td>
        <td align="left">Traffic Attack Simulator</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">סקריפט סימולציה (<code>test_attack.py</code>) ליצירת תעבורת תקיפה סינתטית לאימות מנגנוני הזיהוי.</td>
      </tr>
    </tbody>
  </table>

  <br>

  <hr>

  <div dir="rtl" align="right">
  <h2 align="center">🛠️ טכנולוגיות וארכיטקטורה</h2>
    <ul>
      <li><strong>Python & Scapy:</strong> לכידת חבילות נתונים ברמת ה-Raw Sockets ופיענוח פרוטוקולי תקשורת.</li>
      <li><strong>Concurrency & Threading:</strong> הפרדת לכידת החבילות מהניתוח באמצעות <code>queue.Queue(maxsize=10000)</code> ומניעת זליגת זיכרון ב-Scapy עם <code>store=0</code>.</li>
      <li><strong>Promtail & Grafana Loki:</strong> שינוע הלוגים המובנים (JSON Structured Logs) מתיקיית ה-Logs המקומית ואינדוקסם ב-Loki.</li>
      <li><strong>Grafana Visuals:</strong> בניית לוחות בקרה (Dashboards) מבוססי LogQL לצפייה בזמן אמת באירועי אבטחה והתראות.</li>
      <li><strong>Docker Compose Stack:</strong> פריסה מהירה ורציפה של כל תשתיות ה-Observability.</li>
    </ul>
  </div>

  <hr>

  <h2 align="right" dir="rtl">📝 מבנה לוג JSON (Structured Logging)</h2>
  <div dir="ltr" align="left">
    <pre><code>{
  "timestamp": "2026-08-06T10:30:15.123456",
  "level": "WARNING",
  "message": "[PORT SCAN DETECTED] Host 10.0.0.4 scanned 18 unique ports",
  "logger": "NetworkGuardian",
  "src_ip": "10.0.0.4",
  "event_type": "PORT_SCAN",
  "details": "18 ports scanned"
}</code></pre>
  </div>

  <hr>

  <h2 align="right" dir="rtl">⚙️ התקנה והרצה (Quick Start)</h2>
  <div dir="ltr" align="left">
    <pre><code>## 1. Clone the repository
git clone https://github.com/Raz-Eini/python_sniffer.git
cd python_sniffer

## 2. Environment Setup
cp .env.example .env # Set your Grafana password in .env

## 3. Start Observability Stack (Grafana, Loki, Promtail)
docker compose up -d

## 4. Setup Python Environment
python -m venv .venv
.\.venv\Scripts\activate     # On Windows
source .venv/bin/activate    # On Linux/Mac
pip install -r requirements.txt

## 5. Run NIDS Engine (Requires Administrator / Root)
python main.py

## 6. (Optional) Run Attack Simulator in a separate terminal
python test_attack.py</code></pre>
  </div>

  <br>

  <div dir="rtl" align="right">
    <p>📊 <strong>גישה ל-Grafana:</strong> היכנס בדפדפן ל-<code>http://localhost:3000</code> (שם משתמש: <code>admin</code>, סיסמה מוגדרת ב-<code>.env</code>).</p>
  </div>

  <hr>

  <h2 align="right" dir="rtl">📄 רישיון</h2>
  <p align="right" dir="rtl">
    הפרויקט מופץ תחת רישיון <strong>MIT</strong> – חופשי לשימוש ושינוי למטרות לימודיות ומחקריות.
  </p>

  <hr>

  <p align="center"><strong>👨‍💻 Raz Eini (2026)</strong></p>

</div>
