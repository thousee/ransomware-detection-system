#!/bin/bash

echo "🚀 Deploying Ransomware Detection System..."

# Configuration
DEPLOY_TYPE=${1:-local}  # local, docker, production
VERSION=${2:-latest}

case $DEPLOY_TYPE in
    ("local")
        echo "📦 Local deployment..."
        
        # Check if virtual environment exists
        if [ ! -d "ransomware_env" ]; then
            echo "Creating virtual environment..."
            python3 -m venv ransomware_env
        fi
        
        # Activate and install
        source ransomware_env/bin/activate
        pip install -r requirements.txt
        
        # Generate test data if needed
        if [ ! -f "test_data/training_dataset.csv" ]; then
            echo "Generating test data..."
            python test_data_generator.py
        fi
        
        # Start server
        echo "Starting server..."
        python web_server.py
        ;;
        
    ("docker")
        echo "🐳 Docker deployment..."
        
        # Build image
        docker build -t ransomware-detector:$VERSION .
        
        # Run container
        docker run -d \
            --name ransomware-detector \
            -p 5000:5000 \
            -v $(pwd)/logs:/app/logs \
            -v $(pwd)/models:/app/models \
            -v $(pwd)/reports:/app/reports \
            ransomware-detector:$VERSION
            
        echo "✅ Container started. Access at http://localhost:5000"
        ;;
        
    ("production")
        echo "🏭 Production deployment with Docker Compose..."
        
        # Generate SSL certificates if needed
        if [ ! -f "ssl/cert.pem" ]; then
            echo "Generating SSL certificates..."
            mkdir -p ssl
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout ssl/key.pem -out ssl/cert.pem \
                -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"
        fi
        
        # Start with production profile
        docker-compose --profile production up -d
        
        echo "✅ Production deployment complete. Access at https://localhost"
        ;;
        
    (*)
        echo "❌ Invalid deployment type. Use: local, docker, or production"
        exit 1
        ;;
esac

echo "🎉 Deployment complete!"