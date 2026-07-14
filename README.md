Canary Active Defense
=====================

Self-healing EDR-simulator and deceptive ransomware mitigation engine for Windows.

Overview
--------
Canary is an industrial-grade deceptive endpoint security utility designed to monitor filesystem integrity, analyze system telemetry, and neutralize cryptographic threats (ransomware) in real-time. By deploying high-priority filesystem decoys (canaries) in strategic system paths, it intercepts unauthorized encryption attempts and immediately terminates the offending process space.

The interface is built with an ultra-minimalist, flat, high-contrast terminal design that occupies 100% of the screen height, presenting critical indicators, dynamic metrics, and an animated system diagnostic boot feed.

Project Structure
-----------------
* run.bat          - Double-click Windows launcher (handles environment checks and auto-dependency installation).
* config.py        - Centralized configuration (network parameters, intervals, whitelisted exceptions).
* db.py            - SQLite transaction manager (includes automatic disk footprint compression via VACUUM).
* monitor.py       - Active threat detection loop, handle analysis, and process mitigation.
* server.py        - Event stream (SSE) orchestrator and local HTTP static server.
* index.html       - Full-screen, responsive, SAST-compliant HTML5 diagnostic console (includes animated boot logs).
* requirements.txt - Declared library dependencies.
* Dockerfile       - Lightweight containerization config.
* .gitignore       - Standard repository safety rules.

Key Features
------------
* Alpha-Priority Decoy Ingestion: Provisions strategically named decoy structures (_critical_ledger.docx, 00_database_backup.db, 0_auth_vault.txt) in hidden system paths to guarantee first-read priority by directory traversal scripts.
* Active Isolation Countermeasures: Instantly evaluates active process spaces on file modification and executes kernel-level terminations (proc.terminate()) to block cascading encryption routines.
* Self-Healing Fallbacks: If standard execution fails due to write-protection or access-denied exceptions on native paths (C:\ProgramData), the engine dynamically falls back to local storage pathing.
* Secure DOM Generation (SAST Zero-Findings): Node rendering utilizes safe web DOM elements (document.createElement and textContent) instead of .innerHTML to enforce absolute client-side protection against XSS and HTML injection.
* Forensic Event Ledger: Logs comprehensive alert payloads (PIDs, parent PIDs, execution contexts, and mitigation states) in a thread-safe SQLite database, with automatic record truncation and database vacuuming.
* Interactive Simulation Mode: Includes an on-demand "Run Threat Simulation" test trigger to verify EDR telemetry pipeline stability without affecting real system files.

Installation and Execution
--------------------------
To launch Canary on Windows, simply double-click the run.bat launcher. It automatically verifies your environment, installs dependencies, and boots the console:

1. Execute the launcher:
   run.bat

2. Access the console (opens automatically):
   http://127.0.0.1:9090

Manual Execution
----------------
1. Install dependencies:
   pip install -r requirements.txt

2. Run server natively with Administrative privileges (required to terminate hostile process handles):
   python server.py
