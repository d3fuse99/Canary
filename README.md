<img width="2554" height="1351" alt="изображение" src="https://github.com/user-attachments/assets/0a254b98-b1d7-4564-bb0f-e5731779cc50" />

Canary Active Defense
=====================

Self-healing EDR-simulator and deceptive ransomware mitigation engine with dynamic trust policies and SIEM telemetry forwarding.

Overview
--------
Canary is an industrial-grade deceptive endpoint security utility designed to monitor filesystem integrity, analyze system telemetry, and neutralize cryptographic threats (ransomware) in real-time. By deploying high-priority filesystem decoys (canaries) in strategic system paths, it intercepts unauthorized encryption attempts and immediately terminates the offending process space.

The interface is built with an ultra-minimalist, flat, high-contrast terminal design that occupies 100% of the screen height, presenting critical indicators, dynamic metrics, and an interactive database-driven trust policy control panel.

Project Structure
-----------------
<img width="292" height="234" alt="изображение" src="https://github.com/user-attachments/assets/24700495-07d6-48b9-bf12-c7cb29f229fa" />

Key Features
------------
* Alpha-Priority Decoy Ingestion: Provisions strategically named decoy structures (_critical_ledger.docx, 00_database_backup.db, 0_auth_vault.txt) in hidden system paths to guarantee first-read priority by directory traversal scripts.
* Active Isolation Countermeasures: Instantly evaluates active process spaces on file modification and executes kernel-level terminations (proc.terminate()) to block cascading encryption routines.
* Self-Healing Fallbacks: If standard execution fails due to write-protection or access-denied exceptions on native paths (C:\ProgramData\), the engine dynamically falls back to local storage pathing.
* Interactive Database Whitelisting: Features a live, database-driven policy control loop. Administrators can dynamically authorize blocked processes directly from the UI using the "Trust & Whitelist Process" action, instantly updating global policies without restarting the engine.
* Shannon Entropy Parser: Calculates the real-time entropy of written data on decoy modification. Values near 8.00 bits per byte indicate high-density mathematical signatures (encryption), automatically triggering maximum threat alerts.
* Forensic SHA-256 Hashing: Automatically computes the SHA-256 cryptographic checksum of hostile binaries during active mitigation events for immediate IOC evaluation.
* SIEM Telemetry Streaming: Broadcasts structured JSON audit logs over standard UDP syslog pathways directly to Wazuh, Splunk, or ELK collectors.
* Raw JSON Audit Export: Exposes a direct, one-click export button in the HUD to download the entire SQLite ledger history as a standard JSON report.
* Secure DOM Generation (SAST Zero-Findings): Node rendering utilizes safe web DOM elements (document.createElement and textContent) instead of .innerHTML to enforce absolute client-side protection against XSS and HTML injection.

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
