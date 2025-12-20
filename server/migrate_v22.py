import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "instance", "shortener.db")
if not os.path.exists(DB_PATH):
    # Fallback to older path structure if instance not used
    DB_PATH = os.path.join(os.path.dirname(__file__), "shortener.db")

print(f"Migrating Database at: {DB_PATH}")

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

try:
    print("Adding 'scan_status' column...")
    cursor.execute("ALTER TABLE lead ADD COLUMN scan_status VARCHAR(20) DEFAULT 'idle'")
    print("SUCCESS.")
except Exception as e:
    print(f"Skipped (maybe exists): {e}")

try:
    print("Adding 'last_scan' column...")
    cursor.execute("ALTER TABLE lead ADD COLUMN last_scan DATETIME")
    print("SUCCESS.")
except Exception as e:
    print(f"Skipped (maybe exists): {e}")

conn.commit()
conn.close()
print("Migration Complete.")
