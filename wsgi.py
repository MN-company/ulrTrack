import sys
import os
from dotenv import load_dotenv

# 1. Add your project directory to the sys.path
# We point DIRECTLY to the inner folder where 'server' package resides

# Get the directory containing this file (e.g., /home/mncompany/mysite/ulrTrack)
# IMPORTANT: This must point to the folder that CONTAINS the 'server' folder.
# It should NOT point to inside the 'server' folder itself.
project_home = '/home/mncompany/mysite/ulrTrack'

if project_home not in sys.path:
    sys.path.append(project_home)

# 2. Load .env file explicitly
load_dotenv(os.path.join(project_home, '.env'))

# 3. Import Flask app
from server import create_app

app = create_app()
# PythonAnywhere looks for a variable named 'application' by default
application = app

if __name__ == '__main__':
    app.run()
