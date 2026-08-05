<div dir="rtl">

  <h1 align="center">🕵️ NetGuard – Python Network Sniffer &amp; DPI Engine</h1>

  <p align="center" dir="rtl">
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
  <p align="right" dir="rtl">
    <strong>NetGuard</strong> הוא כלי ניטור רשת (Sniffer) מתקדם שנועד לספק שקיפות מלאה לשכבות 3, 4 ו-7 במודל ה-OSI. 
    <br>
    בניגוד לסניפרים סטנדרטיים, הכלי משלב <strong>Sliding Window Heuristic Analysis</strong> לזיהוי מדויק של דפוסי תקיפה בזמן אמת (כמו DoS ו-Port Scanning) ומבצע ניתוח של שכבת האפליקציה (Application Layer) כדי לחשוף מידע רגיש בתעבורה.
  </p>

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
        <td align="right" dir="rtl">זיהוי <strong>DoS (SYN Flood)</strong> וסריקת פורטים מבוסס חלון זמן נייד (Sliding Window) מדויק.</td>
      </tr>
      <tr>
        <td align="left">🔍 <strong>DPI</strong></td>
        <td align="left">Deep Packet Inspection</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">סריקת Raw Payload ברמת ה-Bytes לזיהוי מחרוזות חשודות (בדיקות SQLi, Path Traversal וכו').</td>
      </tr>
      <tr>
        <td align="left">⚙️ <strong>Architecture</strong></td>
        <td align="left">Producer-Consumer Model</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">שימוש ב-<strong>Threading &amp; Bounded Queue</strong> למניעת Packet Loss והצפת זיכרון.</td>
      </tr>
      <tr>
        <td align="left">🚦 <strong>IPS Logic</strong></td>
        <td align="left">Automatic Host Isolation</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">מנגנון לבידוד זמני (Blacklisting) של IP עוין לאחר חריגה מהסף המוגדר.</td>
      </tr>
      <tr>
        <td align="left">📝 <strong>Logging</strong></td>
        <td align="left">Dual-Stream Log Engine</td>
        <td align="center">✅</td>
        <td align="right" dir="rtl">הפרדה בין פלט קונסולה צבעוני לבין כתיבת לוגים טקסטואליים נקיים ל-SIEM / Forensics.</td>
      </tr>
    </tbody>
  </table>

  <br>

  <hr>

  <div dir="rtl" align="right">
  <h2 align="center">🛠️ טכנולוגיות וארכיטקטורה</h2>
    <li><strong>Concurrency &amp; Memory Safety:</strong> שימוש ב-<code dir="ltr">queue.Queue(maxsize=10000)</code> להפרדה בין הלכידה לניתוח, ומניעת זליגת זיכרון ב-Scapy בעזרת <code dir="ltr">store=0</code>.</li>
    <li><strong>Sliding Window Engine:</strong> שימוש ב-<code dir="ltr">collections.deque</code> ו-<code dir="ltr">defaultdict</code> לניהול מעקב זמנים מדויק בזמן אמת ללא איפוסי זיכרון מלאכותיים.</li>
    <li><strong>DPI Engine:</strong> ניתוח Bytes ישיר בשכבת ה-Raw Payload לזיהוי מחרוזות חשודות ויעילות בביצועים.</li>
    <li><strong>Clean Logging Strategy:</strong> פורמטר ייעודי (<code dir="ltr">ColoredConsoleFormatter</code>) לצביעת הודעות בקונסולה מבלי לזהם את קובצי הלוג בתווי ANSI.</li>
</div>

  <hr>

  <h2 align="right" dir="rtl">🖥️ דוגמת פלט (Console Output)</h2>
  <div dir="ltr" align="left">
    <pre>
2026-08-06 01:50:10 [INFO] [DNS] Device 192.168.1.15 query: example.com
2026-08-06 01:50:12 [WARNING] [PORT SCAN DETECTED] Host 10.0.0.4 scanned 18 unique ports
2026-08-06 01:50:15 [CRITICAL] [DoS DETECTED] Isolating IP: 10.0.0.99 for 5 minutes
2026-08-06 01:50:18 [WARNING] [SECURITY DPI] Suspicious keyword 'select * from' from 192.168.1.50
    </pre>
  </div>

  <hr>

  <h2 align="right" dir="rtl">⚙️ התקנה והרצה (Quick Start)</h2>
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

  <h2 align="right" dir="rtl">📄 רישיון</h2>
  <p align="right" dir="rtl">
    הפרויקט מופץ תחת רישיון <strong>MIT</strong> – חופשי לשימוש ושינוי למטרות לימודיות ומחקריות.
  </p>

  <hr>

  <p align="center"><strong>👨‍💻 Raz Eini (2026)</strong></p>

</div>
