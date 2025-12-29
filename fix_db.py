import sqlite3
import os

DB_PATHS = [
    '/Users/mnbrain/my-dark-store/ulrTrack/server/instance/shortener.db',
    '/Users/mnbrain/my-dark-store/ulrTrack/instance/ulrtrack.db',
    '/Users/mnbrain/my-dark-store/ulrTrack/server/shortener.db'
]

def add_column(cursor, table, col_def):
    try:
        col_name = col_def.split()[0]
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        print(f"Added {col_name} to {table}")
    except Exception as e:
        # Ignore duplicate column or no such table errors usually
        msg = str(e).lower()
        if 'duplicate column' in msg:
            pass
        elif 'no such table' in msg:
            pass # Table might not exist in this DB version
        else:
            print(f"Error adding {col_def} to {table}: {e}")

def fix_db():
    print("Starting DB migration check...")
    found = False
    for db_path in DB_PATHS:
        if not os.path.exists(db_path):
            continue
        
        found = True
        print(f"Migrating {db_path}...")
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Visits
            add_column(cursor, 'visit', 'screen_res VARCHAR(32)')
            add_column(cursor, 'visit', 'timezone VARCHAR(64)')
            add_column(cursor, 'visit', 'browser_bot BOOLEAN DEFAULT 0')
            add_column(cursor, 'visit', 'browser_language VARCHAR(10)')
            add_column(cursor, 'visit', 'adblock BOOLEAN DEFAULT 0')
            add_column(cursor, 'visit', 'ai_summary VARCHAR(512)')
            add_column(cursor, 'visit', 'canvas_hash VARCHAR(64)')
            add_column(cursor, 'visit', 'webgl_renderer VARCHAR(256)')
            add_column(cursor, 'visit', 'email VARCHAR(256)')
            add_column(cursor, 'visit', 'battery_level VARCHAR(20)')
            add_column(cursor, 'visit', 'cpu_cores INTEGER')
            add_column(cursor, 'visit', 'ram_gb FLOAT')
            add_column(cursor, 'visit', 'etag VARCHAR(64)')
            add_column(cursor, 'visit', 'fpjs_confidence FLOAT')
            add_column(cursor, 'visit', 'detected_sessions TEXT')
            add_column(cursor, 'visit', 'is_vpn BOOLEAN DEFAULT 0')
            add_column(cursor, 'visit', 'is_proxy BOOLEAN DEFAULT 0')
            add_column(cursor, 'visit', 'is_hosting BOOLEAN DEFAULT 0')
            add_column(cursor, 'visit', 'is_mobile BOOLEAN DEFAULT 0')

            # Links
            add_column(cursor, 'link', 'schedule_start_hour INTEGER')
            add_column(cursor, 'link', 'schedule_end_hour INTEGER')
            add_column(cursor, 'link', 'schedule_timezone VARCHAR(32) DEFAULT "UTC"')
            add_column(cursor, 'link', 'block_adblock BOOLEAN DEFAULT 0')
            add_column(cursor, 'link', 'allowed_countries VARCHAR(50)')
            add_column(cursor, 'link', 'public_masked_url VARCHAR(512)')
            add_column(cursor, 'link', 'require_email BOOLEAN DEFAULT 0')
            add_column(cursor, 'link', 'email_policy VARCHAR(20) DEFAULT "all"')

            conn.commit()
            conn.close()
            print(f"Done migrating {db_path}")
        except Exception as e:
            print(f"Failed migrating {db_path}: {e}")
            
    if not found:
        print("No databases found in known paths!")

if __name__ == '__main__':
    fix_db()
