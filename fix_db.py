import sqlite3
import os

# Use relative paths generally, but also check absolute paths for PA
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Potential relative paths to check
POTENTIAL_PATHS = [
    'instance/ulrtrack.db',
    'server/instance/shortener.db',
    'server/shortener.db',
    'instance/shortener.db',
    'shortener.db'
]

# Absolute paths for PythonAnywhere explicitly
PA_PATHS = [
    '/home/mncompany/mysite/server/instance/shortener.db',
    '/home/mncompany/mysite/instance/shortener.db'
]

def get_db_paths():
    paths = set()
    
    # Check relative
    for p in POTENTIAL_PATHS:
        full_p = os.path.join(BASE_DIR, p)
        if os.path.exists(full_p):
            paths.add(full_p)
            
    # Check absolute
    for p in PA_PATHS:
        if os.path.exists(p):
            paths.add(p)
            
    return list(paths)

def add_column(cursor, table, col_def):
    try:
        col_name = col_def.split()[0]
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
        print(f"Added {col_name} to {table}")
    except Exception as e:
        msg = str(e).lower()
        if 'duplicate column' in msg:
            pass
        elif 'no such table' in msg:
            pass 
        else:
            print(f"Error adding {col_def} to {table}: {e}")

def fix_db():
    print(f"Searching databases in {BASE_DIR}...")
    paths = get_db_paths()
    
    if not paths:
        print("No database files found!")
        print("Please run this script from the project root directory.")
        return

    for db_path in paths:
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
            add_column(cursor, 'visit', 'country_code VARCHAR(2)')

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

if __name__ == '__main__':
    fix_db()
