import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
api_key = os.getenv('GEMINI_API_KEY')

if not api_key:
    print("ERROR: No GEMINI_API_KEY found in .env")
    exit(1)

genai.configure(api_key=api_key)

print("--- AVAILABLE MODELS ---")
try:
    for m in genai.list_models():
        if 'generateContent' in m.supported_generation_methods:
            print(f"Model: {m.name} | Display: {m.display_name}")
except Exception as e:
    print(f"ERROR: {e}")
