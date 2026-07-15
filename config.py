import os

version = "1.4.0"
dir_path = os.path.dirname(os.path.abspath(__file__))

decoy_dir = r"C:\ProgramData\CanarySentry\Decoys"
db_path = r"C:\ProgramData\CanarySentry\canary_v2.db"

if os.name == "nt":
    try:
        os.makedirs(decoy_dir, exist_ok=True)
    except Exception:
        decoy_dir = os.path.join(dir_path, "CanarySentryDecoys")
        db_path = os.path.join(dir_path, "canary_v2.db")
else:
    decoy_dir = os.path.join(dir_path, "CanarySentryDecoys")
    db_path = os.path.join(dir_path, "canary_v2.db")

decoys = [
    os.path.join(decoy_dir, "_critical_ledger.docx"),
    os.path.join(decoy_dir, "00_database_backup.db"),
    os.path.join(decoy_dir, "0_auth_vault.txt")
]

default_trusted_processes = ("explorer.exe", "searchindexer.exe", "python.exe", "taskmgr.exe")

max_events_to_keep = 200
monitor_interval_sec = 0.05

server_host = "127.0.0.1"
server_port = 9090