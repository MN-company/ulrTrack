import sys
import os
# 1. Point to your actual server folder
project_home = '/home/mncompany/mysite/server'
if project_home not in sys.path:
    sys.path = [project_home] + sys.path
# 2. Switch to that directory so .env and database are found
os.chdir(project_home)
# 3. Import your app (flask_app.py)
from flask_app import app as application