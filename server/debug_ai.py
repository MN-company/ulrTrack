import os
import sys
from dotenv import load_dotenv

# Try importing the library used in flask_app
try:
    from google import genai
    import google.generativeai as old_genai
except ImportError:
    print("ERROR: Librerie non trovate.")
    sys.exit(1)

# Load env
load_dotenv()

# Check Key
api_key = os.getenv('GEMINI_API_KEY')
if not api_key:
    print("WARNING: GEMINI_API_KEY non trovata in .env")
    # Try to grab from args for testing
    if len(sys.argv) > 1:
        api_key = sys.argv[1]
        print(f"Usando chiave da argomenti: {api_key[:5]}...")
    else:
        print("FAIL: Nessuna chiave disponibile.")
        sys.exit(1)

print(f"Testando con chiave: {api_key[:5]}*****")

# Test 1: Old SDK (Listed functionality)
try:
    print("\n--- TEST OLD SDK (google.generativeai) ---")
    old_genai.configure(api_key=api_key)
    models = old_genai.list_models()
    print("Models found:")
    for m in models:
        print(f"- {m.name}")
except Exception as e:
    print(f"OLD SDK ERROR: {e}")

# Test 2: New SDK (google.genai)
try:
    print("\n--- TEST NEW SDK (google.genai) ---")
    client = genai.Client(api_key=api_key)
    
    # Try the problematic call
    print("Tentativo chiamata a gemini-1.5-flash...")
    response = client.models.generate_content(
        model='gemini-1.5-flash',
        contents="Say Hello"
    )
    print(f"SUCCESS! Response: {response.text}")

except Exception as e:
    print(f"NEW SDK ERROR: {e}")
    # Analyize 404
    if "404" in str(e):
        print("DIAGNOSI: Errore 404 confermato. Il modello 'gemini-1.5-flash' non è trovato o la chiave non ha accesso.")
