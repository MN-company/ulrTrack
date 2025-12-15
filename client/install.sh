#!/bin/bash

echo "🚀 Installing URL Shortener Client..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install it first."
    exit 1
fi

# Create Virtual Environment if not exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Install Dependencies
echo "⬇️ Installing libraries..."
./venv/bin/pip install -r client/requirements.txt &> /dev/null

# Create Alias/Launch Script
echo "🔗 Creating launch shortcut..."
PWD=$(pwd)
cat <<EOF > pyshort
#!/bin/bash
"$PWD/venv/bin/python" "$PWD/client/cli.py" "\$@"
EOF

chmod +x pyshort

echo "✅ Installation Complete!"
echo "👉 Run './pyshort setup' to configure."
echo "👉 Then run './pyshort' to use."
