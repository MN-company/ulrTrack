import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add current directory to path
path = os.path.expanduser('~/mysite') # PythonAnywhere default usually matches repo name or setup
if path not in sys.path:
    sys.path.append(path)

# Load environment variables
project_folder = os.path.expanduser('~/mysite')  # adjust as appropriate
load_dotenv(os.path.join(project_folder, '.env'))

# Import FastAPI app
from main import app as application
