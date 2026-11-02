from flask import Flask, request, jsonify, redirect, url_for, render_template_string
import sqlite3
import uuid
import os
import hashlib
import json
from datetime import datetime, timedelta

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "tickets.db")

STATUSES = ["Open", "In Progress", "Resolved"]
SEVERITIES = ["Critical", "High", "Medium", "Low"]

def now():
    return datetime.now().isoformat(timespec="seconds")

def get_db():
    conn = sqlite3.connect(DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=10000")
    return conn

def initialize_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            ticket_id TEXT PRIMARY KEY,
            title TEXT,
            source_ip TEXT,
            username TEXT,
            severity TEXT,
            description TEXT,
            status TEXT,
            created_at TEXT
        )
        """)
        # Additive migrations: preserve all existing tickets.
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(tickets)")}
        additions = {
            "event_type": "TEXT DEFAULT 'General'",
            "dest_ip": "TEXT DEFAULT 'Unknown'",
            "last_seen": "TEXT",
            "occurrence_count": "INTEGER DEFAULT 1",
            "fingerprint": "TEXT",
            "raw_event": "TEXT"
        }
        for name, definition in additions.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE tickets ADD COLUMN {name} {definition}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_fingerprint ON tickets(fingerprint)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_created ON tickets(created_at)")

def first_value(obj, names, default="Unknown"):
    for name in names:
        value = obj.get(name)
        if value not in (None, ""):
            if isinstance(value, (list, dict)):
                return json.dumps(value, ensure_ascii=False)
            return str(value)
    return default

def normalize_event(payload):
    # Accept a single result, a list of results, or common Splunk webhook wrappers.
    data = payload if isinstance(payload, dict) else {}
    result = data.get("result")
    if isinstance(result, list):
        result = result[0] if result else {}
    if not isinstance(result, dict):
        result = data.get("results")
        if isinstance(result, list):
            result = result[0] if result else {}
    if not isinstance(result, dict):
        result = data.get("event")
    if not isinstance(result, dict):
        result = data

    title = first_value(result, [
        "incident", "alert_name", "search_name", "rule_name",
        "signature", "msg", "title", "event_type", "sourcetype"
    ], first_value(data, ["search_name", "alert_name", "name"], "Security Alert"))

    source_ip = first_value(result, [
        "src_ip", "source_ip", "src", "client_ip", "attacker_ip",
        "remote_addr", "ip"
    ])
    dest_ip = first_value(result, [
        "dest_ip", "destination_ip", "dest", "target_ip", "server_ip"
    ])
    username = first_value(result, ["username", "user", "account", "src_user"])
    severity = first_value(result, ["severity", "priority", "risk"], "High").title()
    if severity.lower() in ("informational", "info", "notice"):
        severity = "Low"
    if severity.lower() not in [s.lower() for s in SEVERITIES]:
        severity = "High"

    event_type = first_value(result, [
        "alert_type", "event_type", "category", "signature", "sourcetype"
    ], "General")
    description = first_value(result, [
        "description", "message", "msg", "_raw", "details"
    ], "")
    if description == "":
        description = json.dumps(result, ensure_ascii=False)
    if len(description) > 6000:
        description = description[:6000] + "…"

    # Include alert identity and endpoints. Do not include timestamps/counts,
    # so repeated copies of the same alert can be grouped together.
    identity = "|".join([
        title.lower(), source_ip.lower(), dest_ip.lower(),
        username.lower(), event_type.lower()
    ])
    fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return {
        "title": title[:250],
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "username": username,
        "severity": severity,
        "event_type": event_type[:250],
        "description": description,
        "fingerprint": fingerprint,
        "raw_event": json.dumps(payload, ensure_ascii=False)[:12000]
    }

DASHBOARD = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>SOC Command Center</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e5e7eb;font-family:Arial,sans-serif}
header{padding:22px 4%;background:#111c30;border-bottom:1px solid #29364c;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{font-size:22px;font-weight:700}.sub,.muted{color:#94a3b8;font-size:12px;margin-top:6px}.live{color:#4ade80;font-size:13px}
main{width:94%;max-width:1600px;margin:28px auto}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin:18px 0 26px}
.card,.panel{background:#111c30;border:1px solid #29364c;border-radius:12px;padding:18px}.card p{margin:0 0 12px;color:#94a3b8;font-size:13px}.num{font-size:29px;font-weight:bold}
.red{color:#f87171}.blue{color:#60a5fa}.green{color:#4ade80}.yellow{color:#fbbf24}
.filters{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}
input,select{background:#0b1220;color:#e5e7eb;border:1px solid #34435c;border-radius:7px;padding:10px}
input{flex:1;min-width:180px}button,.btn{border:0;border-radius:7px;padding:10px 13px;background:#2563eb;color:white;font-weight:bold;cursor:pointer;text-decoration:none}
.clear{background:#334155}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:1100px}
th,td{text-align:left;padding:13px 10px;border-bottom:1px solid #29364c;font-size:12px;vertical-align:top}
th{color:#94a3b8}.id{color:#60a5fa;font-weight:bold}.pill{display:inline-block;padding:5px 8px;border-radius:5px;font-size:11px;font-weight:bold}
.critical,.high{background:#54242b;color:#fca5a5}.medium{background:#4b3819;color:#fcd34d}.low{background:#153d32;color:#86efac}
.open{background:#54242b;color:#fca5a5}.in-progress{background:#183c62;color:#93c5fd}.resolved{background:#153d32;color:#86efac}
.status-form{display:flex;gap:5px}.status-form select{padding:6px;max-width:115px}
a{color:#60a5fa;text-decoration:none}a:hover{text-decoration:underline}
footer{text-align:center;color:#64748b;padding:24px;font-size:12px}
@media(max-width:600px){header{padding:17px}main{width:96%}.panel{padding:12px}}
</style></head>
<body>
<header><div><div class="brand">🛡 SOC COMMAND CENTER</div><div class="sub">SPLUNK SIEM · SURICATA IDS · INCIDENT MANAGEMENT</div></div><div class="live">● LIVE · Auto-refresh 30 seconds</div></header>
<main>
<h2>Security Overview</h2>
<section class="cards">
<div class="card"><p>Total Tickets</p><div class="num">{{ stats.total }}</div></div>
<div class="card"><p>Open</p><div class="num red">{{ stats.open }}</div></div>
<div class="card"><p>In Progress</p><div class="num blue">{{ stats.progress }}</div></div>
<div class="card"><p>Resolved</p><div class="num green">{{ stats.resolved }}</div></div>
<div class="card"><p>High / Critical</p><div class="num yellow">{{ stats.high }}</div></div>
<div class="card"><p>Alert Occurrences</p><div class="num">{{ stats.occurrences }}</div></div>
</section>
<section class="panel">
<h2>Alert & Ticket Management</h2>
<form method="get" class="filters">
<input name="q" placeholder="Search ID, alert, IP, username..." value="{{ q }}">
<select name="event_type"><option value="">All alert types</option>{% for x in event_types %}<option value="{{ x }}" {% if event_type==x %}selected{% endif %}>{{ x }}</option>{% endfor %}</select>
<select name="status"><option value="">All statuses</option>{% for x in statuses %}<option value="{{ x }}" {% if status==x %}selected{% endif %}>{{ x }}</option>{% endfor %}</select>
<select name="severity"><option value="">All severities</option>{% for x in severities %}<option value="{{ x }}" {% if severity==x %}selected{% endif %}>{{ x }}</option>{% endfor %}</select>
<button>Filter</button><a class="btn clear" href="/">Clear</a>
</form>
<div class="table-wrap"><table><thead><tr>
<th>Ticket</th><th>Alert / Incident</th><th>Alert Type</th><th>Source IP</th><th>Destination IP</th><th>User</th><th>Severity</th><th>Count</th><th>Status</th><th>First Seen</th><th>Last Seen</th><th>Update</th>
</tr></thead><tbody>
{% for t in tickets %}<tr>
<td class="id"><a href="/ticket/{{ t.ticket_id }}">{{ t.ticket_id }}</a></td><td>{{ t.title }}</td><td>{{ t.event_type or 'General' }}</td>
<td>{{ t.source_ip }}</td><td>{{ t.dest_ip or 'Unknown' }}</td><td>{{ t.username }}</td>
<td><span class="pill {{ (t.severity or 'low')|lower }}">{{ t.severity }}</span></td><td>{{ t.occurrence_count or 1 }}</td>
<td><span class="pill {{ (t.status or 'open')|lower|replace(' ','-') }}">{{ t.status }}</span></td>
<td>{{ t.created_at }}</td><td>{{ t.last_seen or t.created_at }}</td>
<td><form class="status-form" method="post" action="/ticket/{{ t.ticket_id }}/status"><select name="status">{% for s in statuses %}<option {% if t.status==s %}selected{% endif %}>{{ s }}</option>{% endfor %}</select><button>Save</button></form></td>
</tr>{% else %}<tr><td colspan="12">No matching alerts found.</td></tr>{% endfor %}
</tbody></table></div>
<p class="muted">Repeated matching alerts are grouped into one active ticket. Occurrence count and last-seen time are updated.</p>
</section></main><footer>SOC Incident Management · Splunk SIEM + Suricata IDS</footer></body></html>
"""

@app.route("/")
def dashboard():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    severity = request.args.get("severity", "").strip()
    event_type = request.args.get("event_type", "").strip()
    with get_db() as conn:
        stats = {
            "total": conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0],
            "open": conn.execute("SELECT COUNT(*) FROM tickets WHERE status='Open'").fetchone()[0],
            "progress": conn.execute("SELECT COUNT(*) FROM tickets WHERE status='In Progress'").fetchone()[0],
            "resolved": conn.execute("SELECT COUNT(*) FROM tickets WHERE status='Resolved'").fetchone()[0],
            "high": conn.execute("SELECT COUNT(*) FROM tickets WHERE UPPER(severity) IN ('HIGH','CRITICAL')").fetchone()[0],
            "occurrences": conn.execute("SELECT COALESCE(SUM(occurrence_count),0) FROM tickets").fetchone()[0]
        }
        sql = "SELECT * FROM tickets WHERE 1=1"
        params = []
        if q:
            like = f"%{q}%"
            sql += " AND (ticket_id LIKE ? OR title LIKE ? OR source_ip LIKE ? OR dest_ip LIKE ? OR username LIKE ? OR event_type LIKE ?)"
            params.extend([like] * 6)
        if status in STATUSES:
            sql += " AND status=?"; params.append(status)
        if severity in SEVERITIES:
            sql += " AND UPPER(severity)=UPPER(?)"; params.append(severity)
        if event_type:
            sql += " AND event_type=?"; params.append(event_type)
        sql += " ORDER BY COALESCE(last_seen,created_at) DESC LIMIT 500"
        tickets = conn.execute(sql, params).fetchall()
        event_types = [r[0] for r in conn.execute("SELECT DISTINCT COALESCE(event_type,'General') FROM tickets ORDER BY 1")]
    return render_template_string(DASHBOARD, stats=stats, tickets=tickets, q=q,
        status=status, severity=severity, event_type=event_type,
        statuses=STATUSES, severities=SEVERITIES, event_types=event_types)

@app.route("/ticket/<ticket_id>")
def ticket_detail(ticket_id):
    with get_db() as conn:
        ticket = conn.execute(
            "SELECT * FROM tickets WHERE ticket_id = ?",
            (ticket_id,)
        ).fetchone()

    if not ticket:
        return "Ticket not found", 404

    raw = ticket["raw_event"] or "No raw event payload stored."

    return render_template_string("""
    <html>
    <head>
        <title>{{ ticket.ticket_id }}</title>
        <style>
            body {
                background: #0b1220;
                color: #e5e7eb;
                font-family: Arial;
                padding: 30px;
            }
            .box {
                background: #111c30;
                padding: 24px;
                border-radius: 12px;
                max-width: 900px;
            }
            pre {
                white-space: pre-wrap;
                overflow-wrap: anywhere;
                background: #0b1220;
                padding: 14px;
            }
            a { color: #60a5fa; }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>Security Incident Details</h1>
            <h2>{{ ticket.ticket_id }} — {{ ticket.title }}</h2>

            <p><b>Alert Type:</b> {{ ticket.event_type }}</p>
            <p><b>Severity:</b> {{ ticket.severity }}</p>
            <p><b>Status:</b> {{ ticket.status }}</p>
            <p><b>Source IP:</b> {{ ticket.source_ip }}</p>
            <p><b>Destination IP:</b> {{ ticket.dest_ip }}</p>
            <p><b>Username:</b> {{ ticket.username }}</p>
            <p><b>Occurrences:</b> {{ ticket.occurrence_count }}</p>
            <p><b>First Seen:</b> {{ ticket.created_at }}</p>
            <p><b>Last Seen:</b> {{ ticket.last_seen }}</p>

            <h3>Description</h3>
            <pre>{{ ticket.description }}</pre>

            <h3>Original Event Payload</h3>
            <pre>{{ raw }}</pre>

            <a href="/">← Back to Dashboard</a>
        </div>
    </body>
    </html>
    """, ticket=ticket, raw=raw)

@app.route("/ticket/<ticket_id>/status", methods=["POST"])
def update_status(ticket_id):
    new_status = request.form.get("status", "")
    if new_status not in STATUSES:
        return "Invalid status", 400
    with get_db() as conn:
        cur = conn.execute("UPDATE tickets SET status=? WHERE ticket_id=?", (new_status, ticket_id))
        if cur.rowcount == 0:
            return "Ticket not found", 404
    return redirect(url_for("dashboard"))

@app.route("/webhook", methods=["POST"])
def create_ticket():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Expected a JSON object"}), 400
    event = normalize_event(payload)
    timestamp = now()
    # Deduplicate the same alert against an active ticket seen in the last 15 minutes.
    cutoff = (datetime.now() - timedelta(minutes=15)).isoformat(timespec="seconds")
    with get_db() as conn:
        existing = conn.execute("""
            SELECT ticket_id FROM tickets
            WHERE fingerprint=? AND status!='Resolved'
              AND COALESCE(last_seen,created_at)>=?
            ORDER BY created_at DESC LIMIT 1
        """, (event["fingerprint"], cutoff)).fetchone()
        if existing:
            conn.execute("""
                UPDATE tickets SET occurrence_count=COALESCE(occurrence_count,1)+1,
                    last_seen=?, severity=?, description=?, raw_event=?
                WHERE ticket_id=?
            """, (timestamp, event["severity"], event["description"], event["raw_event"], existing["ticket_id"]))
            return jsonify({"message": "Duplicate alert grouped into existing ticket",
                            "ticket_id": existing["ticket_id"], "duplicate": True}), 200

        ticket_id = "SOC-" + uuid.uuid4().hex[:8].upper()
        conn.execute("""
            INSERT INTO tickets
            (ticket_id,title,source_ip,username,severity,description,status,created_at,
             event_type,dest_ip,last_seen,occurrence_count,fingerprint,raw_event)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (ticket_id,event["title"],event["source_ip"],event["username"],event["severity"],
              event["description"],"Open",timestamp,event["event_type"],event["dest_ip"],
              timestamp,1,event["fingerprint"],event["raw_event"]))
    return jsonify({"message":"Ticket created successfully","ticket_id":ticket_id,"duplicate":False}), 201

@app.route("/tickets", methods=["GET"])
def get_tickets():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM tickets ORDER BY COALESCE(last_seen,created_at) DESC").fetchall()
    return jsonify([dict(row) for row in rows])

if __name__ == "__main__":
    initialize_db()
    # Keep local-only until authentication and HTTPS are configured.
    app.run(host="127.0.0.1", port=5000)
