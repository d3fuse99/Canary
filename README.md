Canary-Sentry
=============
<img width="2559" height="1318" alt="image" src="https://github.com/user-attachments/assets/56d9535d-ae65-4048-a11d-ab0faabcc36f" />

Deceptive active defense and automated ransomware mitigation system for Windows.

CANARY-SENTRY is a lightweight, modular, and powerful deceptive security system designed to monitor, identify, and neutralize suspicious filesystem transactions in real-time. Instead of evaluating static file signatures, it deploys high-priority filesystem decoys (canaries), continuously monitors their structural integrity via an asynchronous low-level threat detection loop, and automatically isolates threats using active process-termination countermeasures.

Features
--------

* Deceptive Filesystem Decoys: Dynamically provisions strategically-named canary files (_critical_ledger.docx, 00_database_backup.db, 0_auth_vault.txt) inside hidden Windows directories designed to be processed first alphabetically by automated directory traversal scripts.

* Asynchronous Telemetry Loop: Continuously audits decoy file metadata (timestamps, file sizes, existence states) utilizing a high-frequency polling thread to capture early-stage cryptographic alterations.

* Multi-Vector Process Auditing: Instantly scans active process spaces upon decoy modification, checking open file handles, execution paths, and launch contexts via psutil to isolate the source of filesystem disruption.

* Active Mitigation Countermeasures: Terminates offending processes immediately (proc.terminate(), cascading to forced termination if necessary) to halt potential cascading encryption routines across user directories.

* Automated Canary Re-provisioning: Automatically regenerates modified or deleted canary structures with randomized mock text strings, ensuring persistent protection barriers during multi-stage or concurrent attacks.

* Forensic Ledger Database: Appends comprehensive incident metadata (PIDs, parent PIDs, execution contexts, command-line parameters, and mitigation states) to a thread-safe local database (canary_sentry.db).

* Server-Sent Events (SSE) Stream: Emits real-time forensic event payloads to connected analytical consoles over a persistent, low-overhead HTTP connection.

* Tactical HUD Console: Serves a highly responsive cyber operations console featuring system diagnostic readouts, dynamic mitigation counters, and glowing real-time threat alerts representing blocked activities.

How to run
----------

1. Administrative Access: Open PowerShell (or Windows Terminal) as an Administrator to ensure complete access to system-level process spaces and handle audits.

2. Clone the Repository: Clone or download the project files into your local workspace.

3. Install Dependencies: Ensure Python 3.7+ and the process telemetry library are installed:

   pip install psutil

4. Launch the Engine: Start the telemetry orchestrator and local server:

   python server.py

Configuration
-------------

The engine is preconfigured to function out of the box. Decoy pathways and target paths are resolved automatically based on host OS parameters, utilizing standardized fallbacks in non-Windows testing environments.
