<div dir="rtl">

  <h1 align="center">🕵️ NetGuard – Python Network Sniffer & DPI Engine</h1>

  <p align="center">
    מנוע לניתוח תעבורת רשת בזמן אמת עם יכולות <strong>Deep Packet Inspection (DPI)</strong>, 
    זיהוי אנומליות מבוסס היוריסטיקה וחלון זמן נייד (Sliding Window), והתראות אבטחה מתקדמות.
    <br>
    מבוסס <strong>Python + Scapy</strong> בארכיטקטורת Multi-threaded.
  </p>

  <br>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python Badge">
    <img src="https://img.shields.io/badge/Library-Scapy-red" alt="Scapy Badge">
    <img src="https://img.shields.io/badge/Security-DPI-orange" alt="DPI Badge">
    <img src="https://img.shields.io/badge/Analysis-Multithreaded-lightgrey" alt="Arch Badge">
  </p>

  <br>

  <hr>

  <h2 align="center">🔎 Overview</h2>
  <p align="center" dir="rtl">
    <strong>NetGuard</strong> הוא כלי ניטור רשת (Sniffer) מתקדם שנועד לספק שקיפות מלאה לשכבות 3, 4 ו-7 במודל ה-OSI. 
    <br>
    בניגוד לסניפרים סטנדרטיים, הכלי משלב <strong>Sliding Window Heuristic Analysis</strong> לזיהוי מדויק של דפוסי תקיפה בזמן אמת (כמו DoS ו-Port Scanning) ומבצע ניתוח של שכבת האפליקציה (Application Layer) כדי לחשוף מידע רגיש בתעבורה.
  </p>

  <br>

  <hr>

  <h2 align="center">🚀 Core Features</h2>

  <table align="center" dir="rtl">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Feature</th>
        <th>Status</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>📡 <strong>Network</strong></td>
        <td>Real-time L2-L7 Sniffing</td>
        <td>✅</td>
        <td>לכידה וניתוח של תעבורת IP, TCP, UDP ו-DNS בזמן אמת.</td>
      </tr>
      <tr>
        <td>🛡️ <strong>Cyber Security</strong></td>
        <td>Sliding-Window Anomaly Detection</td>
        <td>✅</td>
        <td>זיהוי <strong>DoS (SYN Flood)</strong> וסריקת פורטים מבוסס חלון זמן נייד (Sliding Window) מדויק.</td>
      </tr>
      <tr>
        <td>🔍 <strong>DPI</strong></td>
        <td>Deep Packet Inspection</td>
        <td>✅</td>
        <td>סריקת Raw Payload ברמת ה-Bytes לזיהוי מחרוזות חשודות (בדיקות SQLi, Path Traversal וכו').</td>
      </tr>
      <tr>
        <td>⚙️ <strong>Architecture</strong></td>
        <td>Producer-Consumer Model</td>
        <td>✅</td>
        <td>שימוש ב-<strong>Threading & Bounded Queue</strong> למניעת Packet Loss והצפת זיכרון.</td>
      </tr>
      <tr>
        <td>🚦 <strong>IPS Logic</strong></td>
        <td>Automatic Host Isolation</td>
        <td>✅</td>
        <td>מנגנון לבידוד זמני (Blacklisting) של IP עוין לאחר חריגה מהסף המוגדר.</td>
      </tr>
      <tr>
        <td>📝 <strong>Logging</strong></td>
        <td>Dual-Stream Log Engine</td>
        <td>✅</td>
        <td>הפרדה בין פלט קונסולה צבעוני לבין כתיבת לוגים טקסטואליים נקיים ל-SIEM / Forensics.</td>
      </tr>
    </tbody>
  </table>

  <br>

  <hr>

  <div dir="rtl">
  <h2 align="center">🛠️ טכנולוגיות וארכיטקטורה</h2>
  <ul>
    <li><strong>Concurrency & Memory Safety:</strong> שימוש ב-<code>queue.Queue(maxsize=10000)</code> להפרדה בין הלכידה לניתוח, ומניעת זליגת זיכרון ב-Scapy בעזרת <code>store=0</code>.</li>
    <li><strong>Sliding Window Engine:</strong> שימוש ב-<code>collections.deque</code> ו-<code>defaultdict</code> לניהול מעקב זמנים מדויק בזמן אמת ללא איפוסי זיכרון מלאכותיים.</li>
    <li><strong>DPI Engine:</strong> ניתוח Bytes ישיר בשכבת ה-Raw Payload לזיהוי מחרוזות חשודות ויעילות בביצועים.</li>
    <li><strong>Clean Logging Strategy:</strong> פורמטר ייעודי (<code>ColoredConsoleFormatter</code>) לצביעת הודעות בקונסולה מבלי לזהם את קובצי הלוג בתווי ANSI.</li>
  </ul>
</div>

  <hr>

  <h2>🖥️ דוגמת פלט (Console Output)</h2>
  <div dir="ltr" align="left">
    <pre>
2026-08-06 01:50:10 [INFO] [DNS] Device 192.168.1.15 query: example.com
2026-08-06 01:50:12 [WARNING] [PORT SCAN DETECTED] Host 10.0.0.4 scanned 18 unique ports
2026-08-06 01:50:15 [CRITICAL] [DoS DETECTED] Isolating IP: 10.0.0.99 for 5 minutes
2026-08-06 01:50:18 [WARNING] [SECURITY DPI] Suspicious keyword 'select * from' from 192.168.1.50
    </pre>
  </div>

  <hr>

  <h2>⚙️ התקנה והרצה (Quick Start)</h2>
  <div dir="ltr" align="left">
    <pre>
## Clone the repository
git clone https://github.com/Raz-Eini/python_sniffer.git
cd python_sniffer

## Setup Virtual Environment
python -m venv .venv
.\.venv\Scripts\activate  # On Windows
source .venv/bin/activate # On Linux/Mac

## Install Dependencies
pip install scapy

## Run as Administrator / Sudo (Required for Raw Sockets)
python main.py
    </pre>
  </div>

  <hr>

  <h2>📄 רישיון</h2>
  <p>
    הפרויקט מופץ תחת רישיון <strong>MIT</strong> – חופשי לשימוש ושינוי למטרות לימודיות ומחקריות.
  </p>

  <hr>

  <p align="center"><strong>👨‍💻 Raz Eini (2026)</strong></p>

</div>
