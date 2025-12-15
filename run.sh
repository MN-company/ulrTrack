#!/bin/bash
# Universal Launcher (Self-Contained)

# Ensure venv exists locally
if [ ! -d "venv" ]; then
    echo "❌ Virtual Environment missing! Creating local venv..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r server/requirements.txt
    ./venv/bin/pip install -r client/requirements.txt
fi

# Determine mode
if [ "$1" == "server" ]; then
    echo "🚀 Starting Flask Server..."
    export FLASK_APP=server/flask_app.py
    ./venv/bin/flask run --host=0.0.0.0 --port=8080
    
elif [ "$1" == "client" ]; then
    echo "💻 Starting Client CLI..."
    ./venv/bin/python client/cli.py
    
else
    echo "Usage: ./run.sh [server|client]"
fi
