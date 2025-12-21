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
        
        try:
            if self.mode == 'new_sdk':
                # New SDK Usage
                # Verify model name format. New SDK often prefers 'gemini-1.5-flash'
                response = self.client.models.generate_content(
                    model=target_model,
                    contents=prompt
                )
                if hasattr(response, 'text'):
                    return response.text.strip()
                return str(response)
            
            elif self.mode == 'old_sdk':
                # Old SDK Usage
                m = self.genai_module.GenerativeModel(target_model)
                response = m.generate_content(prompt)
                if hasattr(response, 'text'):
                    return response.text.strip()
                return str(response)
                
        except Exception as e:
            err_str = str(e)
            print(f"AI Generate Error: {err_str}")
            return f"AI Generation Failed: {err_str}"

    def generate_dorks(self, email):
        prompt = f"""Target: {email}
Action: Generate 5 advanced Google Dorks to find exposed documents, logs, or passwords.
Include site searches for pastebin, s3, github, trello.
Return ONLY raw dorks, one per line."""
        return self.generate(prompt)

# Singleton Instance
ai = AIEngine()
