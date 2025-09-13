#!/bin/bash

echo "🔧 Setting up Ransomware Detection System..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv ransomware_env
source ransomware_env/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p logs
mkdir -p models
mkdir -p reports
mkdir -p test_data
mkdir -p templates

# Generate test data
echo "Generating test data..."
python test_data_generator.py

# Set permissions
chmod +x run_server.sh
chmod +x run_tests.sh

echo "✅ Setup complete!"
echo ""
echo "To start the system:"
echo "1. Activate virtual environment: source ransomware_env/bin/activate"
echo "2. Start web server: python web_server.py"
echo "3. Open browser: http://localhost:5000"
echo ""
echo "For command-line usage:"
echo "python ransomware_detector.py"
