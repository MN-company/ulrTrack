import threading
import os
from .extensions import log_queue, db
from .models import Visit, Lead
from .config import Config
from datetime import datetime
import json

def start_worker(app):
    """Starts the background worker thread with app context."""
    print("Worker started...")
    
    def handle_task(task):
        """Core logic for processing a single task."""
        try:
            with app.app_context():
                if task['type'] == 'enrich_visit':
                    visit_id = task.get('visit_id')
                    ip = task.get('ip')
                    
                    visit = Visit.query.get(visit_id)
                    if visit:
                        # slow reverse dns
                        from .utils import get_reverse_dns
                        hostname = get_reverse_dns(ip)
                        if hostname:
                            visit.hostname = hostname
                            
                        # Ghost Correlation
                        if not visit.email and visit.canvas_hash:
                            ch = visit.canvas_hash
                            match = Visit.query.filter(Visit.canvas_hash == ch, Visit.email != None).order_by(Visit.timestamp.desc()).first()
                            if match:
                                visit.email = match.email
                                print(f"👻 GHOST CORRELATION: Anonymous user identified as {match.email}")
                                
                        db.session.commit()





                # V33: AI Auto-Tagging
                elif task['type'] == 'ai_auto_tag':
                    lead_id = task.get('lead_id')
                    lead = Lead.query.get(lead_id)
                    if lead and Config.GEMINI_API_KEY:
                        try:
                            email = lead.email
                            visits = Visit.query.filter_by(email=email).all()
                            
                            # Gather context
                            countries = list(set([v.country for v in visits if v.country]))
                            devices = list(set([v.device_type for v in visits if v.device_type]))
                            orgs = list(set([v.org for v in visits if v.org]))
                            hostnames = [v.hostname for v in visits if v.hostname]
                            
                            # Check email domain
                            domain = email.split('@')[1] if '@' in email else ''
                            is_corporate = not any(x in domain for x in ['gmail', 'yahoo', 'hotmail', 'outlook', 'icloud', 'proton'])
                            
                            from .services.ai_service import AIService
                            
                            prompt = f"""You are a lead classification AI. Based on this data, suggest 2-4 short tags (one word each, comma separated).

EMAIL: {email}
CORPORATE EMAIL: {is_corporate}
COUNTRIES: {countries}
DEVICES: {devices}
ORGANIZATIONS: {orgs}
HOSTNAMES: {hostnames[:3]}
CURRENT TAGS: {lead.tags or 'none'}

Suggest tags like: VIP, Corporate, Mobile, Italian, US, TechUser, Suspicious, Anonymous, HighValue, Returning, etc.
Output ONLY the tags, comma separated, nothing else."""

                            new_tags = AIService.generate(prompt)
                            
                            # Parse and merge tags
                            new_tags = new_tags.strip()
                            existing = set([t.strip() for t in (lead.tags or '').split(',') if t.strip()])
                            suggested = set([t.strip() for t in new_tags.split(',') if t.strip()])
                            merged = existing.union(suggested)
                            
                            lead.tags = ', '.join(sorted(merged))
                            db.session.commit()
                            print(f"AI AUTO-TAG: {email} -> {lead.tags}")
                            
                        except Exception as e:
                            print(f"AI Auto-Tag Error: {e}")



        except Exception as e:
            print(f"Worker Error: {e}")
            
    def worker():
        while True:
            try:
                task = log_queue.get()
                if task is None:
                    break
                
                # Heavy Task Check
                is_heavy = task.get('type') in ['ai_analyze', 'ai_auto_tag']
                
                if is_heavy:
                    threading.Thread(target=handle_task, args=(task,)).start()
                else:
                    handle_task(task)
                    
                log_queue.task_done()
            except Exception as e:
                print(f"Worker Loop Error: {e}")

    threading.Thread(target=worker, daemon=True).start()
