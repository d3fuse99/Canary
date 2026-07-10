import os

dir_path = os.path.dirname(os.path.abspath(__file__))

if os.name == "nt":
    decoy_dir = r"C:\ProgramData\CanarySentry\Decoys"
    db_path = r"C:\ProgramData\CanarySentry\canary_sentry.db"
else:
    decoy_dir = os.path.join(dir_path, "CanarySentryDecoys")
    db_path = os.path.join(dir_path, "canary_sentry.db")

decoys = [
    os.path.join(decoy_dir, "_critical_ledger.docx"),
    os.path.join(decoy_dir, "00_database_backup.db"),
    os.path.join(decoy_dir, "0_auth_vault.txt")
]