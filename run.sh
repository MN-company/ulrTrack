#!/bin/bash
# Universal Launcher (Self-Contained)

# Resolve absolute path to avoid CWD issues
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR" || exit

# Ensure venv exists locally
if [ ! -d "venv" ]; then
    echo "❌ Virtual Environment missing! Creating local venv..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -r server/requirements.txt
    ./venv/bin/pip install -r client/requirements.txt
fi

# Determine mode
# Determine mode
if [ "$1" = "server" ]; then
    echo "🚀 Starting Flask Server..."
    
    APP_PATH="$SCRIPT_DIR/server/flask_app.py"
    
    if [ ! -f "$APP_PATH" ]; then
        echo "❌ Error: Cannot find $APP_PATH"
        exit 1
    fi
    
    export FLASK_APP="$APP_PATH"
    export FLASK_ENV=development
    "$SCRIPT_DIR/venv/bin/flask" run --host=127.0.0.1 --port=8080
    
else
    echo "Usage: ./run.sh server"
fi
