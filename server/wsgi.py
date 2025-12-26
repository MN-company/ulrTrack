import sys
import os
# Aggiungi il percorso del progetto
path = '/home/mncompany/ulrTrack'
if path not in sys.path:
    sys.path.append(path)
# IMPORTANTE: Carica la nuova App Factory
from server import create_app
from server.worker import start_worker

application = create_app()

# Start Background Worker (OSINT, AI, Enrichment)
start_worker(application)