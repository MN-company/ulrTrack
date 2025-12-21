import os
import sys
from .config import Config

class AIEngine:
    """
    Robust AI Engine handling both new (google.genai) and old (google.generativeai) SDKs.
    Solves 'Model not found' and 'Value error' issues by abstracting the client.
    """
    def __init__(self):
        self.api_key = Config.GEMINI_API_KEY
        # Fallback model if config is empty
        self.model_name = Config.GEMINI_MODEL or "gemini-1.5-flash"
        self.client = None
        self.mode = 'disabled'
        self.genai_module = None
        
        if not self.api_key:
            print("AI Engine: No API_KEY found in Config. Disabled.")
            return

        # Attempt Import Strategy
        try:
            # Strategy A: New SDK (v1.0+)
            from google import genai
            try:
                self.client = genai.Client(api_key=self.api_key)
                self.mode = 'new_sdk'
                print("AI Engine: Initialized with NEW SDK (google.genai)")
            except Exception as e:
                print(f"AI Engine: New SDK found but init failed: {e}")
                raise ImportError("Fallback to old")
        except ImportError:
            try:
                # Strategy B: Old SDK
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self.genai_module = genai
                self.mode = 'old_sdk'
                print("AI Engine: Initialized with OLD SDK (google.generativeai)")
            except ImportError:
                print("AI Engine: CRITICAL - No Google GenAI libraries installed.")

    def generate(self, prompt, model=None):
        if self.mode == 'disabled':
            return "AI Error: API Key missing or Libraries not installed."
        
        target_model = model or self.model_name
        
        # V42: Safety Settings (BLOCK_NONE) for Red Teaming
        # This allows the AI to analyze malware/phishing contexts without refusal.
        safety_settings_old = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]
        
        try:
            if self.mode == 'new_sdk':
                # New SDK Usage (google.genai)
                # Note: Config structure varies by version, using safe default if possible or omitting if known issues.
                # Currently, new SDK V1 often ignores old style safety settings or uses different format.
                # We will try to pass config if supported, otherwise rely on prompt engineering.
                
                # Attempt to pass config for safety
                from google.genai import types
                # Approximate config for new SDK (v1.0+)
                config = types.GenerateContentConfig(
                    safety_settings=[
                        types.SafetySetting(
                            category='HARM_CATEGORY_DANGEROUS_CONTENT',
                            threshold='BLOCK_NONE'
                        ),
                         types.SafetySetting(
                            category='HARM_CATEGORY_HARASSMENT',
                            threshold='BLOCK_NONE'
                        ),
                         types.SafetySetting(
                            category='HARM_CATEGORY_HATE_SPEECH',
                            threshold='BLOCK_NONE'
                        ),
                         types.SafetySetting(
                            category='HARM_CATEGORY_SEXUALLY_EXPLICIT',
                            threshold='BLOCK_NONE'
                        )
                    ]
                )
                
                response = self.client.models.generate_content(
                    model=target_model,
                    contents=prompt,
                    config=config
                )
                if hasattr(response, 'text'):
                    return response.text.strip()
                return str(response)
            
            elif self.mode == 'old_sdk':
                # Old SDK Usage (google.generativeai)
                m = self.genai_module.GenerativeModel(target_model)
                response = m.generate_content(prompt, safety_settings=safety_settings_old)
                if hasattr(response, 'text'):
                    return response.text.strip()
                return str(response)
                
        except Exception as e:
            err_str = str(e)
            print(f"AI Generate Error: {err_str}")
            # Fallback retry without safety settings if it failed due to config error (not refusal)
            if "argument" in err_str or "parameter" in err_str:
                 try:
                     if self.mode == 'new_sdk':
                         response = self.client.models.generate_content(model=target_model, contents=prompt)
                         return response.text.strip()
                 except: pass
            
            return f"AI Generation Failed: {err_str}"

    def query_db(self, query):
        """Execute Read-Only SQL Query for Agentic AI."""
        from .extensions import db
        from sqlalchemy import text
        try:
            # Basic Safety: Read-only heuristic
            q_lower = query.lower().strip()
            if q_lower.startswith(("drop", "delete", "update", "insert", "alter", "create", "truncate")):
                 return "Security Error: Read-only access allowed."
            
            result = db.session.execute(text(query))
            if result.returns_rows:
                rows = [dict(row) for row in result.mappings()]
                return str(rows[:50]) # Limit output
            return "Query Executed (No Rows)"
        except Exception as e:
            return f"SQL Error: {e}"

    def run_agentic_loop(self, user_prompt, model=None):
        """
        Two-step Agentic Loop:
        1. AI decides if it needs data.
        2. If SQL generated, execute and feed back.
        """
        # System Prompt with Schema Context
        schema_context = """
        SYSTEM: You have READ-ONLY SQL access.
        Schema:
        - Lead(id, email, name, holehe_data, custom_fields, tags, created_at)
        - Link(id, slug, destination, visit_count)
        - Visit(id, link_id, ip_address, country, city, user_agent, timestamp, org, isp, canvas_hash, system_data)
        
        To query, output ONLY:
        ```sql
        SELECT ...
        ```
        If no query needed, just answer directly.
        """
        
        # Turn 1
        full_prompt = f"{schema_context}\n\nUser: {user_prompt}"
        response_1 = self.generate(full_prompt, model)
        
        # Check for SQL Block
        import re
        sql_match = re.search(r"```sql\n(.*?)\n```", response_1, re.DOTALL)
        if not sql_match:
             # Try variant without newline
             sql_match = re.search(r"```sql(.*?)```", response_1, re.DOTALL)

        if sql_match:
            sql_query = sql_match.group(1).strip()
            # print(f"AI AGENT: Executing SQL: {sql_query}") # Debug
            db_result = self.query_db(sql_query)
            
            # Turn 2: Feed result back
            follow_up = f"{full_prompt}\n\nAI Proposal: {response_1}\n\nSYSTEM: Query Result: {db_result}\n\nUser: Now answer the original question based on this data."
            final_response = self.generate(follow_up, model)
            return final_response
            
        return response_1

    def generate_dorks(self, email):
        prompt = f"""Target: {email}
Action: Generate 5 advanced Google Dorks to find exposed documents, logs, or passwords.
Include site searches for pastebin, s3, github, trello.
Return ONLY raw dorks, one per line."""
        return self.generate(prompt)

# Singleton Instance
ai = AIEngine()
