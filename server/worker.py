import threading
import os
from .extensions import log_queue, db
from .models import Visit, Lead
from .config import Config
from datetime import datetime
import json

def start_worker(app):
    """Starts the background worker thread with app context."""
    def worker():
        while True:
            task = log_queue.get()
            try:
                with app.app_context():
                    if task['type'] == 'log_visit':
                        visit = Visit(**task['data'])
                        db.session.add(visit)
                        db.session.commit()
                        print(f"ASYNC LOG: Visit Saved ID={visit.id}")
                    
                    elif task['type'] == 'osint':
                        email = task['email']
                        print(f"ASYNC OSINT: Starting scan for {email}")
                        
                        try:
                            cmd = Config.HOLEHE_CMD
                            # Auto-detect holehe in common locations if default
                            if cmd == 'holehe':
                                possible_paths = [
                                    os.path.join(os.path.dirname(app.root_path), '.venv', 'bin', 'holehe'),
                                    os.path.join(os.path.dirname(app.root_path), 'venv', 'bin', 'holehe'),
                                    '/usr/local/bin/holehe',
                                    '/home/mncompany/.local/bin/holehe' # PythonAnywhere user path
                                ]
                                for p in possible_paths:
                                    if os.path.exists(p):
                                        cmd = p
                                        break
                                        
                            print(f"ASYNC OSINT: Running {cmd} for {email}")
                            import subprocess
                            # Increased timeout to 180s for slow networks
                            result = subprocess.run([cmd, email, '--only-used', '--no-color'], capture_output=True, text=True, timeout=180)
                            
                            if result.returncode != 0:
                                print(f"Holehe Error (RC={result.returncode}): {result.stderr}")
                            
                            output = result.stdout
                            found_sites = []
                            for line in output.split('\n'):
                                line = line.strip()
                                if '[+]' in line:
                                    parts = line.split(']')
                                    if len(parts) > 1: found_sites.append(parts[1].strip())
                            
                            lead = Lead.query.filter_by(email=email).first()
                            if lead:
                                lead.holehe_data = json.dumps(found_sites)
                                lead.scan_status = 'completed'
                                lead.last_scan = datetime.utcnow()
                                db.session.commit()
                                print(f"ASYNC OSINT: Success for {email}. Found {len(found_sites)} sites.")
                                
                        except Exception as e:
                            print(f"ASYNC OSINT ERROR: {e}")
                            lead = Lead.query.filter_by(email=email).first()
                            if lead:
                                lead.scan_status = 'failed'
                                db.session.commit()
                    
                    elif task['type'] == 'ai_analyze':
                        v_id = task['visit_id']
                        ua = task['ua']
                        screen = task['screen']
                        visit = Visit.query.get(v_id)
                        if visit and Config.GEMINI_API_KEY:
                            try:
                                from google import genai
                                client = genai.Client(api_key=Config.GEMINI_API_KEY)
                                prompt = f"Identify device from UA: '{ua}' and Screen: '{screen}'. Return ONLY device name."
                                response = client.models.generate_content(model=Config.GEMINI_MODEL, contents=prompt)
                                visit.ai_summary = response.text.strip()
                                db.session.commit()
                                print(f"AI ANALYSIS: {visit.ai_summary}")
                            except Exception as e:
                                print(f"AI Error: {e}")

            except Exception as e:
                print(f"Worker Error: {e}")
            finally:
                log_queue.task_done()

    threading.Thread(target=worker, daemon=True).start()
