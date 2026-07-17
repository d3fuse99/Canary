import socket
import json
from config import siem_host, siem_port

def send_siem_log(event_data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = json.dumps(event_data).encode("utf-8")
        sock.sendto(payload, (siem_host, siem_port))
        sock.close()
    except Exception:
        pass