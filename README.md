# SentinelShield – Custom Web Application Firewall (WAF)

SentinelShield is a lightweight application-level firewall built with Python and Flask. I created this project to understand how Web Application Firewalls (WAF) and Intrusion Detection Systems (IDS) inspect incoming HTTP requests and block common security threats before they hit the backend logic.

It filters traffic for common attack patterns, enforces IP-based rate limiting, writes clean security logs, and visualizes live stats through an interactive dashboard.

---

## 🌟 Features

* **Threat Detection:** Filters incoming query parameters and headers for common payloads (SQL Injection, XSS, Path Traversal).
* **Rate Limiting:** Tracks request counts per IP to prevent brute-force or basic DoS spam (returns HTTP `429 Too Many Requests`).
* **Security Logs:** Saves structured incident data (IP, timestamp, threat type, path) inside `sentinel_alerts.log`.
* **Live Dashboard:** A simple browser dashboard using Chart.js to monitor total requests, blocked attacks, and dynamic charts in real time.

---

## 🛠️ Built With

* **Backend:** Python, Flask
* **Frontend:** HTML5, CSS3, Chart.js
* **Testing:** Python `requests` module (custom script for simulating attacks)

---

## 📊 How Attacks Are Handled

| Attack Type | Detection Strategy | HTTP Status Code |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Checks for signatures like `UNION SELECT` or `OR '1'='1'` | `403 Forbidden` |
| **Cross-Site Scripting (XSS)** | Blocks script tags like `<script>` or `javascript:` | `403 Forbidden` |
| **Path Traversal** | Catches relative path inputs like `../` or `/etc/passwd` | `403 Forbidden` |
| **Rate Limit Exceeded** | Limits high-frequency requests from a single IP | `429 Too Many Requests` |

---

## 🚀 How to Run Locally

### 1. Install Dependencies
Make sure you have Python installed, then run:
```bash
pip install flask requests

2. Start the App
Run the Flask server with the security middleware enabled:
python app.py

3. Test Attack Detection
In a second terminal window, run the automated attack simulation script:
python force_test.py

4. Open the Security Dashboard
Go to your browser and visit:
http://127.0.0.1:5000/dashboard
