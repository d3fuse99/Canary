import os
import time
import psutil
import random
import string
from config import decoys, decoy_dir, monitor_interval_sec
import db

file_states = {}
on_trigger = None

def recreate_decoy(path):
    try:
        words = ["private", "ledger", "backup", "vault", "credentials"]
        content = "\n".join(" ".join(random.choices(words, k=4)) for _ in range(20))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

def setup_decoys():
    os.makedirs(decoy_dir, exist_ok=True)
    for path in decoys:
        if not os.path.exists(path):
            recreate_decoy(path)
        file_states[path] = {
            "mtime": os.path.getmtime(path) if os.path.exists(path) else 0.0,
            "size": os.path.getsize(path) if os.path.exists(path) else 0,
            "exists": os.path.exists(path)
        }

def find_process(target_path):
    target_lower = target_path.lower()
    procs = []
    for p in psutil.process_iter(['pid', 'create_time', 'name', 'exe', 'cmdline']):
        try:
            procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass
    procs.sort(key=lambda x: x.info.get('create_time', 0), reverse=True)
    
    for p in procs:
        try:
            for f in p.open_files():
                if f.path.lower() == target_lower:
                    return p
                if target_lower in f.path.lower():
                    return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass
            
    for p in procs:
        try:
            exe = p.info.get('exe')
            if exe and target_lower in exe.lower():
                return p
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        except Exception:
            pass
    return None

def monitor_loop():
    setup_decoys()
    while True:
        time.sleep(monitor_interval_sec)
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
                proc = find_process(path)
                handle_threat(proc, path, event_type)
                recreate_decoy(path)
                file_states[path] = {
                    "mtime": os.path.getmtime(path) if os.path.exists(path) else 0.0,
                    "size": os.path.getsize(path) if os.path.exists(path) else 0,
                    "exists": os.path.exists(path)
                }

def handle_threat(proc, path, event_type):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    pid = -1
    ppid = -1
    exe = "Unknown"
    cmdline = "Unknown"
    status = "Logged"
    score = 50
    
    if proc:
        try:
            pid = proc.pid
            ppid = proc.ppid()
            exe = proc.exe()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else proc.name()
            proc_name = proc.name()
            
            if db.is_whitelisted(proc_name):
                status = "Bypassed (Trusted)"
                score = 20
            else:
                proc.terminate()
                status = "Terminated"
                score = 90
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            status = "Failed (Access Denied)"
        except Exception as e:
            status = f"Failed: {str(e)}"
    
    db.log_event(timestamp, os.path.basename(path), event_type, pid, ppid, exe, cmdline, status, score)
    
    if on_trigger:
        on_trigger({
            "timestamp": timestamp,
            "decoy_file": os.path.basename(path),
            "event_type": event_type,
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "cmdline": cmdline,
            "status": status,
            "threat_score": score
        })