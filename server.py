import os
import sys
import time
import ctypes
import sqlite3
import json
import threading
import queue
import random
import string
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import psutil

if os.name == "nt":
    decoy_dir = r"C:\ProgramData\CanarySentry\Decoys"
    db_path = r"C:\ProgramData\CanarySentry\canary_sentry.db"
else:
    decoy_dir = os.path.join(os.getcwd(), "CanarySentryDecoys")
    db_path = os.path.join(os.getcwd(), "canary_sentry.db")

decoys = [
    os.path.join(decoy_dir, "_critical_ledger.docx"),
    os.path.join(decoy_dir, "00_database_backup.db"),
    os.path.join(decoy_dir, "0_auth_vault.txt")
]

file_states = {}
clients = []
clients_lock = threading.Lock()

def init_db():
    db_folder = os.path.dirname(db_path)
    os.makedirs(db_folder, exist_ok=True)
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
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

def generate_dummy_data():
    words = ["security", "vault", "ledger", "backup", "auth", "config", "database", "credentials", "private", "key", "root", "admin", "token", "session"]
    lines = []
    for _ in range(50):
        line = " ".join(random.choices(words, k=5)) + " " + "".join(random.choices(string.ascii_letters + string.digits, k=15))
        lines.append(line)
    return "\n".join(lines)

def recreate_decoy(path):
    try:
        content = generate_dummy_data()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

def init_decoys():
    try:
        os.makedirs(decoy_dir, exist_ok=True)
        if os.name == "nt":
            ctypes.windll.kernel32.SetFileAttributesW(decoy_dir, 2)
    except Exception:
        pass

    for path in decoys:
        if not os.path.exists(path):
            recreate_decoy(path)

def init_file_states():
    for path in decoys:
        if os.path.exists(path):
            file_states[path] = {
                "mtime": os.path.getmtime(path),
                "size": os.path.getsize(path),
                "exists": True
            }
        else:
            file_states[path] = {
                "mtime": 0.0,
                "size": 0,
                "exists": False
            }

def is_safe_to_terminate(proc_name):
    critical_processes = [
        "system idle process", "system", "registry", "smss.exe", 
        "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", 
        "svchost.exe", "spoolsv.exe", "explorer.exe", "python.exe",
        "conhost.exe", "cmd.exe", "powershell.exe"
    ]
    return proc_name.lower() not in critical_processes

def find_offending_process(target_path):
    target_lower = target_path.lower()
    target_folder = os.path.dirname(target_path).lower()
    procs = []
    
    for p in psutil.process_iter(['pid', 'create_time', 'name', 'exe', 'cmdline']):
        try:
            procs.append(p)
        except Exception:
            pass
            
    procs.sort(key=lambda x: x.info.get('create_time', 0), reverse=True)
    
    for p in procs:
        try:
            for f in p.open_files():
                if f.path.lower() == target_lower:
                    return p
        except Exception:
            pass
            
    for p in procs:
        try:
            exe = p.info.get('exe')
            if exe and (target_lower in exe.lower() or target_folder in exe.lower()):
                if is_safe_to_terminate(p.name()):
                    return p
            cmd = p.info.get('cmdline')
            if cmd:
                cmd_str = " ".join(cmd).lower()
                if target_lower in cmd_str or target_folder in cmd_str:
                    if is_safe_to_terminate(p.name()):
                        return p
        except Exception:
            pass
            
    return None

def broadcast_event(data):
    payload = json.dumps(data)
    with clients_lock:
        for q in clients:
            q.put(payload)

def mitigate_process(proc, path, event_type):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    pid = -1
    ppid = -1
    exe = "Unknown Source"
    cmdline = "Unknown Context"
    status = "Detected (Source Untraced)"

    if proc is not None:
        try:
            pid = proc.pid
            ppid = proc.ppid()
            exe = proc.exe()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else proc.name()
            proc_name = proc.name()
            
            if is_safe_to_terminate(proc_name):
                proc.terminate()
                try:
                    proc.wait(timeout=1.0)
                    status = "Blocked (Terminated)"
                except psutil.TimeoutExpired:
                    proc.kill()
                    status = "Blocked (Forcefully Killed)"
            else:
                status = f"Bypassed Safety Lock (Critical: {proc_name})"
        except Exception as e:
            status = f"Mitigation Failed ({str(e)})"

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO events (timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (timestamp, os.path.basename(path), event_type, pid, ppid, exe, cmdline, status)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

    event_data = {
        "timestamp": timestamp,
        "decoy_file": os.path.basename(path),
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
        "exe": exe,
        "cmdline": cmdline,
        "status": status
    }
    broadcast_event(event_data)

def monitor_thread():
    init_decoys()
    init_file_states()
    
    while True:
        time.sleep(0.05)
        for path in decoys:
            exists = os.path.exists(path)
            prev = file_states.get(path)
            if not prev:
                continue
                
            triggered = False
            event_type = ""

            if prev["exists"] and not exists:
                triggered = True
                event_type = "DELETION"
            elif exists:
                try:
                    mtime = os.path.getmtime(path)
                    size = os.path.getsize(path)
                    if not prev["exists"]:
                        triggered = True
                        event_type = "CREATION"
                    elif mtime != prev["mtime"] or size != prev["size"]:
                        triggered = True
                        event_type = "MODIFICATION"
                except Exception:
                    pass

            if triggered:
                offender = find_offending_process(path)
                mitigate_process(offender, path, event_type)
                
                if not os.path.exists(path):
                    recreate_decoy(path)
                
                try:
                    file_states[path] = {
                        "mtime": os.path.getmtime(path),
                        "size": os.path.getsize(path),
                        "exists": True
                    }
                except Exception:
                    file_states[path] = {
                        "mtime": 0.0,
                        "size": 0,
                        "exists": False
                    }

class SentryHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.serve_index()
        elif self.path == "/api/history":
            self.serve_history()
        elif self.path == "/api/events":
            self.serve_events()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

    def serve_index(self):
        try:
            dir_path = os.path.dirname(os.path.realpath(__file__))
            file_path = os.path.join(dir_path, "index.html")
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(content.encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"index.html not found. Place it in the same directory as server.py.")
        except Exception as e:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(str(e).encode("utf-8"))

    def serve_history(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        
        events = []
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, decoy_file, event_type, pid, ppid, exe, cmdline, status FROM events ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            for r in rows:
                events.append({
                    "timestamp": r[0],
                    "decoy_file": r[1],
                    "event_type": r[2],
                    "pid": r[3],
                    "ppid": r[4],
                    "exe": r[5],
                    "cmdline": r[6],
                    "status": r[7]
                })
            conn.close()
        except Exception:
            pass
            
        self.wfile.write(json.dumps(events).encode("utf-8"))

    def serve_events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        q = queue.Queue()
        with clients_lock:
            clients.append(q)

        try:
            self.wfile.write(b"data: {\"status\": \"connected\"}\n\n")
            self.wfile.flush()

            while True:
                try:
                    event_data = q.get(timeout=10.0)
                    self.wfile.write(f"data: {event_data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
        except Exception:
            pass
        finally:
            with clients_lock:
                if q in clients:
                    clients.remove(q)

def main():
    init_db()
    
    t = threading.Thread(target=monitor_thread, daemon=True)
    t.start()
    
    server_address = ("127.0.0.1", 9090)
    httpd = ThreadingHTTPServer(server_address, SentryHTTPHandler)
    
    print("CanarySentry Core Engine successfully initiated.")
    print("Security Shield: Active")
    print("Database State: Mounted")
    print("Monitoring Directory: " + decoy_dir)
    print("Web Console Hosted At: http://127.0.0.1:9090")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down CanarySentry core operations...")
        httpd.server_close()
        sys.exit(0)

if __name__ == "__main__":
    main()