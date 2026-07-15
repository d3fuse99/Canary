import os
import time
import sqlite3
from config import db_path, max_events_to_keep, version, default_trusted_processes

def init_db():
    db_dir = os.path.dirname(db_path)
    try:
        os.makedirs(db_dir, exist_ok=True)
    except Exception:
        pass
        
    conn = sqlite3.connect(db_path, timeout=10)
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
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            proc_name TEXT UNIQUE
        )
    """)
    conn.commit()
    
    cursor.execute("SELECT COUNT(*) FROM whitelist")
    if cursor.fetchone()[0] == 0:
        for proc in default_trusted_processes:
            try:
                cursor.execute("INSERT OR IGNORE INTO whitelist (proc_name) VALUES (?)", (proc.lower(),))
            except Exception:
                pass
        conn.commit()
    
    cursor.execute("SELECT COUNT(*) FROM events")
    if cursor.fetchone()[0] == 0:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO events (timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status, threat_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, "System", "ENGINE_STARTUP", os.getpid(), os.getppid() if hasattr(os, "getppid") else 0, "server.py", f"Canary Engine v{version} Active Protection Initialized", "Secure", 0)
        )
        conn.commit()
        
    conn.close()

def add_to_whitelist(proc_name):
    conn = sqlite3.connect(db_path, timeout=10)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT OR IGNORE INTO whitelist (proc_name) VALUES (?)", (proc_name.lower(),))
        conn.commit()
    except Exception:
        pass
    conn.close()

def is_whitelisted(proc_name):
    conn = sqlite3.connect(db_path, timeout=10)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT COUNT(*) FROM whitelist WHERE proc_name = ?", (proc_name.lower(),))
        count = cursor.fetchone()[0]
    except Exception:
        count = 0
    conn.close()
    return count > 0

def log_event(timestamp, decoy, event_type, pid, ppid, exe, cmdline, status, score):
    conn = sqlite3.connect(db_path, timeout=10)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO events (timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status, threat_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (timestamp, decoy, event_type, pid, ppid, exe, cmdline, status, score)
    )
    cursor.execute(
        "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
        (max_events_to_keep,)
    )
    cursor.execute("VACUUM")
    conn.commit()
    conn.close()

def get_recent_events():
    conn = sqlite3.connect(db_path, timeout=10)
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