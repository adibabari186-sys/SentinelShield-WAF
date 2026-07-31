from flask import Flask, request, jsonify, render_template_string
import time
import os
import rules

app = Flask(__name__)

LOG_FILE = "sentinel_alerts.log"
request_tracker = {}
MAX_REQUESTS = 5
TIME_WINDOW = 10

# Embedded Dashboard HTML Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SentinelShield - Security Operations Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
        h1 { color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 10px; }
        .metrics { display: flex; gap: 20px; margin-bottom: 20px; }
        .card { background: #1e293b; padding: 15px; border-radius: 8px; flex: 1; border: 1px solid #334155; }
        .metric-val { font-size: 26px; font-weight: bold; color: #f43f5e; margin-top: 5px; }
        .chart-container { background: #1e293b; padding: 20px; border-radius: 8px; width: 450px; margin-bottom: 20px; border: 1px solid #334155; }
        table { width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #38bdf8; }
    </style>
</head>
<body>

    <h1>SentinelShield - WAF Security Dashboard</h1>

    <div class="metrics">
        <div class="card">
            <div>TOTAL THREATS DETECTED</div>
            <div class="metric-val" id="totalEvents">0</div>
        </div>
        <div class="card">
            <div>MOST FREQUENT ATTACK</div>
            <div class="metric-val" id="topThreat" style="color:#f59e0b;">-</div>
        </div>
    </div>

    <div class="chart-container">
        <h3>Threat Distribution</h3>
        <canvas id="attackChart"></canvas>
    </div>

    <h2>Live Security Incident Log</h2>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Source IP</th>
                <th>Attack Category</th>
                <th>Requested Path</th>
            </tr>
        </thead>
        <tbody id="logRows"></tbody>
    </table>

    <script>
        async function loadData() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();

                document.getElementById('totalEvents').innerText = data.total_events;
                document.getElementById('topThreat').innerText = data.top_threat;

                const tbody = document.getElementById('logRows');
                tbody.innerHTML = '';
                
                data.recent_logs.slice().reverse().forEach(log => {
                    tbody.innerHTML += `<tr>
                        <td>${log.time}</td>
                        <td>${log.ip}</td>
                        <td><b style="color:#f43f5e">${log.threat}</b></td>
                        <td>${log.path}</td>
                    </tr>`;
                });

                const ctx = document.getElementById('attackChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(data.threat_counts),
                        datasets: [{
                            data: Object.values(data.threat_counts),
                            backgroundColor: ['#ef4444', '#f59e0b', '#3b82f6', '#10b981']
                        }]
                    },
                    options: { plugins: { legend: { labels: { color: '#e2e8f0' } } } }
                });

            } catch(e) { console.error('Error loading metrics:', e); }
        }
        loadData();
    </script>
</body>
</html>
"""

def log_event(ip, attack_type, endpoint, details):
    current_time = time.strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{current_time}] - IP: {ip} - Type: {attack_type} - URL: {endpoint} - Input: {details}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_line)

def check_rate_limit(ip):
    now = time.time()
    if ip not in request_tracker:
        request_tracker[ip] = []
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t < TIME_WINDOW]
    
    if len(request_tracker[ip]) >= MAX_REQUESTS:
        return True
    request_tracker[ip].append(now)
    return False

@app.before_request
def inspect_traffic():
    # Bypass inspection for dashboard view and API
    if request.path == '/dashboard' or request.path.startswith('/api'):
        return

    user_ip = request.remote_addr or "127.0.0.1"
    path = request.path

    if check_rate_limit(user_ip):
        log_event(user_ip, "Rate Limit Exceeded", path, "Flooding Traffic")
        return jsonify({"status": "Blocked", "reason": "Too many requests."}), 429

    for key, user_input in request.args.items():
        detected = rules.scan_text(user_input)
        if detected:
            log_event(user_ip, detected, path, f"{key}={user_input}")
            return jsonify({"status": "Blocked", "reason": f"Attack detected: {detected}"}), 403

@app.route('/')
def home():
    return "SentinelShield WAF Middleware Active."

@app.route('/login')
def login():
    user = request.args.get('username', 'Guest')
    return f"Login page - Hello {user}"

@app.route('/dashboard')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/metrics')
def get_metrics():
    if not os.path.exists(LOG_FILE):
        return jsonify({"total_events": 0, "threat_counts": {}, "top_threat": "None", "recent_logs": []})

    total = 0
    threats = {}
    logs = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split(" - ")
            if len(parts) >= 4:
                total += 1
                t_type = parts[2].replace("Type: ", "")
                threats[t_type] = threats.get(t_type, 0) + 1
                logs.append({
                    "time": parts[0],
                    "ip": parts[1].replace("IP: ", ""),
                    "threat": t_type,
                    "path": parts[3].replace("URL: ", "")
                })

    top_t = max(threats, key=threats.get) if threats else "None"
    return jsonify({
        "total_events": total,
        "threat_counts": threats,
        "top_threat": top_t,
        "recent_logs": logs[-10:]
    })

if __name__ == '__main__':
    print("Starting SentinelShield Server on http://127.0.0.1:5000/dashboard")
    app.run(port=5000, debug=True)
