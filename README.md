Canary
======
<img width="2559" height="1320" alt="image" src="https://github.com/user-attachments/assets/6f94f5d8-967d-4d4c-9804-defede3d60f2" />

Deceptive active defense and automated process mitigation system.

Overview
--------
Canary is a lightweight, modular, and deceptive endpoint security utility designed to monitor filesystem integrity, analyze system telemetry, and neutralize cryptographic threats (ransomware) in real-time. By deploying high-priority filesystem decoys (canaries) in strategic system paths, it intercepts unauthorized encryption attempts and immediately terminates the offending process space.

The interface is built with an ultra-minimalist, flat, high-contrast terminal design that occupies 100% of the screen height, presenting critical indicators without unnecessary overhead.


<img width="292" height="139" alt="image" src="https://github.com/user-attachments/assets/735eed21-ce9f-4358-a836-4787ee95d701" />

Key Features
------------
* Alpha-Priority Decoy Ingestion: Provisions strategically named decoy structures (_critical_ledger.docx, 00_database_backup.db, 0_auth_vault.txt) designed to be processed first alphabetically by automated directory traversal scripts.
* Full-Screen Diagnostic Console: A low-overhead, screen-adaptive operations interface featuring instant system metrics, connection monitoring, and raw live log feeds.
* Active Isolation Countermeasures: Instantly evaluates active process spaces on file modification and executes kernel-level terminations (proc.terminate()) to block cascading encryption routines.
* Forensic Event Ledger: Logs comprehensive alert payloads (PIDs, parent PIDs, execution contexts, CLI parameters, and mitigation states) in a thread-safe SQLite database.

Installation and Execution
--------------------------
1. Install the process monitoring library:
   pip install psutil

2. Execute the telemetry server with Administrative privileges (required to terminate hostile process handles):
   python server.py

3. Open the diagnostics console in your browser:
   http://127.0.0.1:9090
