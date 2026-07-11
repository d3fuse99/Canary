import os
import sqlite3
from config import db_path

def init_db():
    db_dir = os.path.dirname(db_path)
    try:
        os.makedirs(db_dir, exist_ok=True)
    except Exception:
        pass
        
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            decoy_file TEXT,
            event_type TEXT,
            pid INTEGER,
            ppid INTEGER,
            exe TEXT,
            cmdline TEXT,
            status TEXT,
            threat_score INTEGER
        )
    """)
    conn.commit()
    conn.close()

def log_event(timestamp, decoy, event_type, pid, ppid, exe, cmdline, status, score):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status, threat_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, decoy, event_type, pid, ppid, exe, cmdline, status, score)
    )
    cursor.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200)")
    conn.commit()
    conn.close()

def get_recent_events():
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status, threat_score FROM events ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    events = []
    for r in rows:
        events.append({
            "timestamp": r[0],
            "decoy_file": r[1],
            "event_type": r[2],
            "pid": r[3],
            "ppid": r[4],
            "exe": r[5],
            "cmdline": r[6],
            "status": r[7],
            "threat_score": r[8]
        })
    return events