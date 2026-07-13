import json
import threading
import queue
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import db
import monitor
from config import server_host, server_port

clients = []
clients_lock = threading.Lock()

class SentryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"REQUEST: {args[0]} -> RESPONSE STATUS: {args[1]}")

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.serve_file("index.html", "text/html")
        elif self.path == "/api/history":
            self.send_json(db.get_recent_events())
        elif self.path == "/api/events":
            self.serve_sse()
        elif self.path == "/api/test":
            self.trigger_test()
        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, filename, content_type):
        try:
            dir_path = os.path.dirname(os.path.abspath(__file__))
            full_path = os.path.join(dir_path, filename)
            with open(full_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            print(f"SERVER: Successfully served: {filename}")
        except Exception as e:
            print(f"SERVER: ERROR reading {filename}: {str(e)}")
            self.send_response(404)
            self.end_headers()

    def send_json(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def trigger_test(self):
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            import time
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            
        mock_event = {
            "timestamp": timestamp,
            "decoy_file": "_critical_ledger.docx",
            "event_type": "SIMULATED_ATTACK",
            "pid": 9999,
            "ppid": 1111,
            "exe": "C:\\Windows\\Temp\\ransomware_simulation.exe",
            "cmdline": "ransomware_simulation.exe --encrypt C:\\ProgramData\\CanarySentry\\Decoys",
            "status": "Blocked (Simulation)",
            "threat_score": 100
        }
        
        db.log_event(
            mock_event["timestamp"],
            mock_event["decoy_file"],
            mock_event["event_type"],
            mock_event["pid"],
            mock_event["ppid"],
            mock_event["exe"],
            mock_event["cmdline"],
            mock_event["status"],
            mock_event["threat_score"]
        )
        
        broadcast(mock_event)
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "Simulation triggered"}).encode("utf-8"))

    def serve_sse(self):
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

def broadcast(event_data):
    payload = json.dumps(event_data)
    with clients_lock:
        for q in clients:
            q.put(payload)

def print_headless(event_data):
    print(f"[{event_data['timestamp']}] Canary Incident Triggered: {event_data['event_type']} on {event_data['decoy_file']}")
    print(f"TARGET PID: {event_data['pid']} ({event_data['exe']}) -> STATUS: {event_data['status']}")

def launch_browser():
    try:
        import webbrowser
        webbrowser.open(f"http://{server_host}:{server_port}")
    except Exception:
        pass

def main():
    db.init_db()
    
    headless_mode = "--headless" in sys.argv
    
    if headless_mode:
        monitor.on_trigger = print_headless
        print("Sentry running in Headless (Console-Only) mode. Filesystem monitoring active.")
        monitor.monitor_loop()
    else:
        monitor.on_trigger = broadcast
        t = threading.Thread(target=monitor.monitor_loop, daemon=True)
        t.start()
        
        server_address = (server_host, server_port)
        httpd = ThreadingHTTPServer(server_address, SentryHandler)
        print(f"Sentry Core online. Servicing interface on http://{server_host}:{server_port}")
        
        threading.Timer(0.5, launch_browser).start()
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.server_close()

if __name__ == "__main__":
    main()