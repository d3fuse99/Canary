import json
import threading
import queue
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import db
import monitor

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
        else:
            self.send_response(404)
            self.end_headers()

    def serve_file(self, filename, content_type):
        try:
            dir_path = os.path.dirname(os.path.abspath(__file__))
            full_path = os.path.join(dir_path, filename)
            print(f"SERVER: Attempting to read: {full_path}")
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

def main():
    db.init_db()
    monitor.on_trigger = broadcast
    
    t = threading.Thread(target=monitor.monitor_loop, daemon=True)
    t.start()
    
    server_address = ("127.0.0.1", 9090)
    httpd = ThreadingHTTPServer(server_address, SentryHandler)
    print("Sentry Core online. Servicing interface on http://127.0.0.1:9090")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()

if __name__ == "__main__":
    main()