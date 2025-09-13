#!/bin/bash

# Activate virtual environment if it exists
if [ -d "ransomware_env" ]; then
    source ransomware_env/bin/activate
fi

echo "🚀 Starting Ransomware Detection Web Server..."
echo "📊 Web interface will be available at: http://localhost:5000"
echo "⏹️  Press Ctrl+C to stop"

python web_server.py