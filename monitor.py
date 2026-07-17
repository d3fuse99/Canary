import os
import time
import math
import psutil
import random
import string
from config import decoys, monitored_dirs, monitor_interval_sec
import db
import siem

file_states = {}
on_trigger = None

def calculate_shannon_entropy(path):
    try:
        if not os.path.exists(path):
            return 0.0
        with open(path, "rb") as f:
            data = f.read(1024)
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 2)
    except Exception:
        return 0.0

def recreate_decoy(path):
    try:
        words = ["private", "ledger", "backup", "vault", "credentials"]
        content = "\n".join(" ".join(random.choices(words, k=4)) for _ in range(20))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        pass

def setup_decoys():
    for d_dir in monitored_dirs:
        try:
            os.makedirs(d_dir, exist_ok=True)
            if os.name == "nt":
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(d_dir, 2)
        except Exception:
            pass

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
                entropy = calculate_shannon_entropy(path)
                proc = find_process(path)
                handle_threat(proc, path, event_type, entropy)
                recreate_decoy(path)
                file_states[path] = {
                    "mtime": os.path.getmtime(path) if os.path.exists(path) else 0.0,
                    "size": os.path.getsize(path) if os.path.exists(path) else 0,
                    "exists": os.path.exists(path)
                }

def handle_threat(proc, path, event_type, entropy):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    pid = -1
    ppid = -1
    exe = "Unknown"
    cmdline = "Unknown"
    status = "Logged"
    score = 50
    sha256 = "None"
    
    if proc:
        try:
            pid = proc.pid
            ppid = proc.ppid()
            exe = proc.exe()
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else proc.name()
            proc_name = proc.name()
            
            sha256 = db.get_file_hash(exe)
            
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
            
    if entropy > 7.2 and status == "Terminated":
        score = 100
        status = "Blocked (Ransomware Confirmed)"
            
    db.log_event(timestamp, os.path.basename(path), event_type, pid, ppid, exe, cmdline, status, score, entropy, sha256)
    
    event_data = {
        "timestamp": timestamp,
        "decoy_file": os.path.basename(path),
        "event_type": event_type,
        "pid": pid,
        "ppid": ppid,
        "exe": exe,
        "cmdline": cmdline,
        "status": status,
        "threat_score": score,
        "entropy": entropy,
        "sha256": sha256
    }
    
    siem.send_siem_log(event_data)
    
    if on_trigger:
        on_trigger(event_data)