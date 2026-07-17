import os

version = "1.6.0"
dir_path = os.path.dirname(os.path.abspath(__file__))

home_dir = os.path.expanduser("~")
documents_decoys = os.path.join(home_dir, "Documents", "CanaryDecoys")
desktop_decoys = os.path.join(home_dir, "Desktop", "CanaryDecoys")
programdata_decoys = r"C:\ProgramData\CanarySentry\Decoys"

monitored_dirs = []
if os.name == "nt":
    try:
        os.makedirs(programdata_decoys, exist_ok=True)
        monitored_dirs.append(programdata_decoys)
    except Exception:
        pass
    try:
        os.makedirs(documents_decoys, exist_ok=True)
        monitored_dirs.append(documents_decoys)
    except Exception:
        pass
    try:
        os.makedirs(desktop_decoys, exist_ok=True)
        monitored_dirs.append(desktop_decoys)
    except Exception:
        pass
else:
    local_decoys = os.path.join(dir_path, "CanarySentryDecoys")
    try:
        os.makedirs(local_decoys, exist_ok=True)
        monitored_dirs.append(local_decoys)
    except Exception:
        pass

decoy_names = ["_critical_ledger.docx", "00_database_backup.db", "0_auth_vault.txt"]
decoys = []
for d_dir in monitored_dirs:
    for name in decoy_names:
        decoys.append(os.path.join(d_dir, name))

db_path = r"C:\ProgramData\CanarySentry\canary_v4.db"
if os.name == "nt":
    try:
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    except Exception:
        db_path = os.path.join(dir_path, "canary_v4.db")
else:
    db_path = os.path.join(dir_path, "canary_v4.db")

default_trusted_processes = ("explorer.exe", "searchindexer.exe", "python.exe", "taskmgr.exe")

max_events_to_keep = 200
monitor_interval_sec = 0.05

server_host = "127.0.0.1"
server_port = 9090

siem_host = "127.0.0.1"
siem_port = 514