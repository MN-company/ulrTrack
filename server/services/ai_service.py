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
OSINT Data: {lead.holehe_data or 'None'}
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

    @staticmethod
    def generate_response(message: str) -> dict:
        """
        Generates AI response using Gemini.
        """
        if not Config.GEMINI_API_KEY:
            raise ValueError("GEMINI_API_KEY not configured")

        try:
            from google import genai
            client = genai.Client(api_key=Config.GEMINI_API_KEY)
            
            context = AIService.build_context(message)
            system_context = """You are a cybersecurity intelligence analyst expert. 
Help analyze data and identify patterns. Be concise but insightful."""
            
            full_prompt = f"{system_context}\n{context}\n\nUser Question: {message}"
            
            response = client.models.generate_content(
                model=Config.GEMINI_MODEL,
                contents=full_prompt
            )
            
            return {
                'response': response.text,
                'model': Config.GEMINI_MODEL,
                'context_used': bool(context)
            }
        except Exception as e:
            raise e
