from flask import jsonify
import re
import json
from ..models import Lead, Visit, db
from ..config import Config

class AIService:
    """
    Service for handling AI interactions and Context Parsing.
    """
    
    @staticmethod
    def build_context(message: str) -> str:
        """
        Parses the user message for @mentions and builds context.
        """
        context_data = ""
        
        # @email:xxx
        email_match = re.search(r'@email:(\S+)', message)
        if email_match:
            email = email_match.group(1)
            lead = Lead.query.filter_by(email=email).first()
            if lead:
                visits = Visit.query.filter_by(email=email).all()
                countries = list(set([v.country for v in visits if v.country]))
                devices = list(set([v.device_type for v in visits if v.device_type]))
                
                context_data += f"""
\n=== LEAD CONTEXT: {email} ===
Name: {lead.name or 'Unknown'}
Tags: {lead.tags or 'None'}
Total Visits: {len(visits)}
Countries: {', '.join(countries) or 'None'}
Devices: {', '.join(devices) or 'None'}

Custom Fields: {lead.custom_fields or 'None'}
"""
            else:
                context_data += f"\n⚠️ Email {email} not found in database.\n"
        
        # @hash:xxx
        hash_match = re.search(r'@hash:(\S+)', message)
        if hash_match:
            hash_id = hash_match.group(1)
            visits = Visit.query.filter(
                db.or_(
                    Visit.canvas_hash == hash_id,
                    Visit.etag == hash_id
                )
            ).all()
            
            if visits:
                emails = list(set([v.email for v in visits if v.email]))
                ips = list(set([v.ip_address for v in visits if v.ip_address]))
                
                context_data += f"""
\n=== FINGERPRINT CONTEXT: {hash_id} ===
Total Visits: {len(visits)}
Emails Used: {', '.join(emails) or 'Anonymous'}
IP Addresses: {', '.join(ips)}
First Seen: {visits[0].timestamp if visits else 'N/A'}
"""
            else:
                context_data += f"\n⚠️ Fingerprint {hash_id} not found.\n"
        
        # @visit:xxx
        visit_match = re.search(r'@visit:(\d+)', message)
        if visit_match:
            visit_id = int(visit_match.group(1))
            visit = Visit.query.get(visit_id)
            if visit:
                context_data += f"""
\n=== VISIT CONTEXT: #{visit_id} ===
IP: {visit.ip_address}
Location: {visit.city or 'Unknown'}, {visit.country or 'Unknown'}
Device: {visit.device_type}, OS: {visit.os_family}
Email: {visit.email or 'Anonymous'}
Organization: {visit.org or 'Unknown'}
Canvas Hash: {visit.canvas_hash or 'None'}
Timestamp: {visit.timestamp}
"""
            else:
                context_data += f"\n⚠️ Visit #{visit_id} not found.\n"
        
        # @db:xxx - WARNING
        if '@db:' in message:
             context_data += """
⚠️ SECURITY NOTICE: The @db command has been disabled for production security.
"""
        
        return context_data

    client = None
    mode = 'disabled'
    genai_module = None

    @classmethod
    def initialize(cls):
        """Initialize the AI Client with fallback strategy."""
        if cls.client or cls.genai_module: return

        api_key = Config.GEMINI_API_KEY
        if not api_key:
             print("AI Service: No API_KEY found.")
             return

        try:
            # Strategy A: New SDK
            from google import genai
            try:
                cls.client = genai.Client(api_key=api_key)
                cls.mode = 'new_sdk'
            except Exception:
                raise ImportError("Fallback")
        except ImportError:
            try:
                # Strategy B: Old SDK
                import google.generativeai as genai_old
                genai_old.configure(api_key=api_key)
                cls.genai_module = genai_old
                cls.mode = 'old_sdk'
            except Exception as e:
                print(f"AI Service: CRITICAL - No GenAI libs. Error: {e}")

    @classmethod
    def generate(cls, prompt: str, model: str = None) -> str:
        """Generic generation method with fallback."""
        cls.initialize()
        if cls.mode == 'disabled': return "AI Error: Not Configured"
        
        target_model = model or Config.GEMINI_MODEL
        
        try:
            if cls.mode == 'new_sdk':
                response = cls.client.models.generate_content(
                    model=target_model,
                    contents=prompt
                )
                return response.text.strip() if hasattr(response, 'text') else str(response)
            
            elif cls.mode == 'old_sdk':
                model_instance = cls.genai_module.GenerativeModel(target_model)
                response = model_instance.generate_content(prompt)
                return response.text.strip() if hasattr(response, 'text') else str(response)
                
        except Exception as e:
            return f"AI Error: {str(e)}"



    @staticmethod
    def generate_response(message: str) -> dict:
        """
        Generates AI response using Gemini with Context.
        """
        AIService.initialize()
        
        # Custom Context Parsing
        context = AIService.build_context(message)
        
        # General Database Stats (Always Included)
        total_visits = Visit.query.count()
        total_leads = Lead.query.count()
        recent_visits = Visit.query.order_by(Visit.timestamp.desc()).limit(5).all()
        recent_v_text = "\n".join([f"- {v.ip_address} ({v.country or '?'}) on {v.timestamp.strftime('%H:%M')}" for v in recent_visits])
        
        system_context = f"""You are a cybersecurity intelligence analyst expert.
I have access to the live database:
- Total Intercepts: {total_visits}
- Total Leads: {total_leads}
- Recent Activity:
{recent_v_text}

Help analyze data and identify patterns. Be concise but insightful."""
        
        full_prompt = f"{system_context}\n{context}\n\nUser Question: {message}"
        
        response_text = AIService.generate(full_prompt)
        
        return {
            'response': response_text,
            'model': Config.GEMINI_MODEL,
            'context_used': bool(context)
        }
