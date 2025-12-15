import sys
import os
from dotenv import load_dotenv

# 1. Add your project directory to the sys.path
# We point DIRECTLY to the inner folder where 'server' package resides
project_home = '/home/mncompany/mysite/url_shortener'
if project_home not in sys.path:
    sys.path.append(project_home)

# 2. Load .env file explicitly
load_dotenv(os.path.join(project_home, '.env'))

# 3. Import Flask app
# Now we can import from 'server.flask_app' since we are IN the root folder
from server.flask_app import app as application
