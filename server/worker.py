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
                        data = task['data']
                        visit = Visit(**data)
                        
                        # --- V25: Ghost Correlation (De-anonymization) ---
                        # If email is missing, try to link via Canvas Hash
                        if not visit.email and data.get('canvas_hash'):
                            ch = data.get('canvas_hash')
                            # Find any previous visit with same hash AND an email
                            match = Visit.query.filter(
                                Visit.canvas_hash == ch, 
                                Visit.email != None
                            ).order_by(Visit.timestamp.desc()).first()
                            
                            if match:
                                visit.email = match.email
                                print(f"👻 GHOST CORRELATION: Anonymous user identified as {match.email} via Canvas {ch}")
                                
                        db.session.add(visit)
                        db.session.commit()
                        print(f"ASYNC LOG: Visit Saved ID={visit.id}")
                    
                    elif task['type'] == 'osint' and 'email' in task:
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

                    # V31: AI Identity Inference (Advanced OSINT)
                    elif task['type'] == 'identity_inference':
                        lead_id = task.get('lead_id')
                        lead = Lead.query.get(lead_id)
                        if lead and Config.GEMINI_API_KEY:
                            try:
                                from ..utils import email_permutations, get_gravatar_profile, get_gaia_id
                                
                                # Gather all data
                                email = lead.email
                                perm = email_permutations(email)
                                gravatar = get_gravatar_profile(email)
                                gaia = get_gaia_id(email)
                                
                                # Get visit data for this lead
                                visits = Visit.query.filter_by(email=email).all()
                                hostnames = [v.hostname for v in visits if v.hostname]
                                orgs = [v.org for v in visits if v.org]
                                cities = [v.city for v in visits if v.city]
                                devices = [v.ai_summary for v in visits if v.ai_summary]
                                
                                # Build AI prompt
                                from google import genai
                                client = genai.Client(api_key=Config.GEMINI_API_KEY)
                                
                                prompt = f"""You are an OSINT analyst. Based on these data points, infer the most likely identity.

EMAIL: {email}
POSSIBLE NAMES: {perm['full_names']}
COMPANY: {perm['company']}
GRAVATAR NAME: {gravatar.get('displayName') if gravatar else 'None'}
GRAVATAR ACCOUNTS: {gravatar.get('accounts') if gravatar else 'None'}
GAIA ID: {gaia or 'Not found'}
HOSTNAMES SEEN: {hostnames[:5]}
ORGANIZATIONS: {orgs[:5]}
CITIES: {cities[:5]}
DEVICES: {devices[:3]}

Based on this, provide:
1. Most likely FULL NAME
2. Probable ROLE/JOB
3. LinkedIn search query
4. Confidence level (Low/Medium/High)

Be concise, one line per item."""

                                response = client.models.generate_content(model=Config.GEMINI_MODEL, contents=prompt)
                                
                                # Store result in custom_fields
                                import json as json_lib
                                cf = json_lib.loads(lead.custom_fields or '{}')
                                cf['ai_identity'] = response.text.strip()
                                cf['gaia_id'] = gaia
                                if gravatar:
                                    cf['gravatar'] = gravatar
                                lead.custom_fields = json_lib.dumps(cf)
                                db.session.commit()
                                print(f"AI IDENTITY INFERENCE: {response.text[:100]}...")
                                
                            except Exception as e:
                                print(f"Identity Inference Error: {e}")

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
                                
                                from google import genai
                                client = genai.Client(api_key=Config.GEMINI_API_KEY)
                                
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

                                response = client.models.generate_content(model=Config.GEMINI_MODEL, contents=prompt)
                                
                                # Parse and merge tags
                                new_tags = response.text.strip()
                                existing = set([t.strip() for t in (lead.tags or '').split(',') if t.strip()])
                                suggested = set([t.strip() for t in new_tags.split(',') if t.strip()])
                                merged = existing.union(suggested)
                                
                                lead.tags = ', '.join(sorted(merged))
                                db.session.commit()
                                print(f"AI AUTO-TAG: {email} -> {lead.tags}")
                                
                            except Exception as e:
                                print(f"AI Auto-Tag Error: {e}")

                    # V24: Real-time Webhooks
                    if task.get('type') in ['log_visit', 'ai_analyze'] and Config.WEBHOOK_URL:
                         try:
                             import requests
                             # Simple heuristic: Only alert on new visits or high-value events?
                             # For now, alert on every visit log if configured.
                             if task['type'] == 'log_visit':
                                 data = task['data']
                                 # Basic Payload
                                 embed = {
                                     "title": "🚨 New Hit Detected",
                                     "color": 16711680 if data.get('is_suspicious') else 65280, # Red or Green
                                     "fields": [
                                         {"name": "IP", "value": data.get('ip_address', 'Unknown'), "inline": True},
                                         {"name": "Country", "value": data.get('country', 'Unknown'), "inline": True},
                                         {"name": "Device", "value": f"{data.get('os_family')} / {data.get('device_type')}", "inline": False},
                                         {"name": "User Agent", "value": data.get('user_agent', '')[:100], "inline": False}
                                     ],
                                     "footer": {"text": "ulrTrack Pro Intelligence"}
                                 }
                                 
                                 requests.post(Config.WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
                                 print(f"WEBHOOK SENT to {Config.WEBHOOK_URL}")
                         except Exception as e:
                             print(f"Webhook Error: {e}")

            except Exception as e:
                print(f"Worker Error: {e}")
            finally:
                log_queue.task_done()

    threading.Thread(target=worker, daemon=True).start()
