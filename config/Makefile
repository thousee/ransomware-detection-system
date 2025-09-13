.PHONY: help install test clean run docker-build docker-run deploy

# Default target
help:
	@echo "🛡️  Ransomware Detection System - Available Commands:"
	@echo ""
	@echo "📦 Setup & Installation:"
	@echo "  make install          Install dependencies and setup environment"
	@echo "  make install-dev      Install with development dependencies"
	@echo "  make clean           Clean temporary files and caches"
	@echo ""
	@echo "🚀 Running the System:"
	@echo "  make run             Start the web server"
	@echo "  make run-cli         Run command-line detector"
	@echo "  make generate-data   Generate test datasets"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  make test            Run all tests"
	@echo "  make test-core       Test core detection engine"
	@echo "  make test-web        Test web interface"
	@echo "  make test-integration Run integration tests"
	@echo "  make coverage        Generate test coverage report"
	@echo ""
	@echo "🐳 Docker:"
	@echo "  make docker-build    Build Docker image"
	@echo "  make docker-run      Run Docker container"
	@echo "  make docker-compose  Run with Docker Compose"
	@echo ""
	@echo "🚀 Deployment:"
	@echo "  make deploy-local    Deploy locally"
	@echo "  make deploy-docker   Deploy with Docker"
	@echo "  make deploy-prod     Deploy to production"
	@echo ""
	@echo "🔧 Development:"
	@echo "  make lint            Run code linting"
	@echo "  make format          Format code with black"
	@echo "  make security-scan   Run security vulnerability scan"
	@echo "  make docs            Generate documentation"

# Installation targets
install:
	@echo "📦 Installing Ransomware Detection System..."
	python3 -m venv ransomware_env
	. ransomware_env/bin/activate && pip install --upgrade pip
	. ransomware_env/bin/activate && pip install -r requirements.txt
	chmod +x scripts/*.sh
	mkdir -p logs models reports data/training data/test
	@echo "✅ Installation complete!"

install-dev:
	@echo "📦 Installing with development dependencies..."
	python3 -m venv ransomware_env
	. ransomware_env/bin/activate && pip install --upgrade pip
	. ransomware_env/bin/activate && pip install -r requirements.txt
	. ransomware_env/bin/activate && pip install -r requirements-dev.txt
	chmod +x scripts/*.sh
	mkdir -p logs models reports data/training data/test
	@echo "✅ Development installation complete!"

clean:
	@echo "🧹 Cleaning temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name "*.log" -delete
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/
	@echo "✅ Cleanup complete!"

# Running targets
run:
	@echo "🚀 Starting web server..."
	. ransomware_env/bin/activate && python src/web_server.py

run-cli:
	@echo "🚀 Starting CLI detector..."
	. ransomware_env/bin/activate && python src/ransomware_detector.py

generate-data:
	@echo "📊 Generating test data..."
	. ransomware_env/bin/activate && python src/test_data_generator.py

# Testing targets
test:
	@echo "🧪 Running all tests..."
	. ransomware_env/bin/activate && python -m pytest tests/ -v

test-core:
	@echo "🧪 Testing core detection engine..."
	. ransomware_env/bin/activate && python -m pytest tests/test_detector.py -v

test-web:
	@echo "🧪 Testing web interface..."
	. ransomware_env/bin/activate && python -m pytest tests/test_web_server.py -v

test-integration:
	@echo "🧪 Running integration tests..."
	. ransomware_env/bin/activate && python tests/test_integration.py

coverage:
	@echo "📊 Generating test coverage report..."
	. ransomware_env/bin/activate && python -m pytest --cov=src --cov-report=html --cov-report=term

# Docker targets
docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t ransomware-detector:latest .

docker-run:
	@echo "🐳 Running Docker container..."
	docker run -d -p 5000:5000 --name ransomware-detector ransomware-detector:latest

docker-compose:
	@echo "🐳 Starting with Docker Compose..."
	docker-compose up -d

docker-stop:
	@echo "🐳 Stopping Docker containers..."
	docker-compose down

# Deployment targets
deploy-local:
	@echo "🚀 Deploying locally..."
	./scripts/deploy.sh local

deploy-docker:
	@echo "🚀 Deploying with Docker..."
	./scripts/deploy.sh docker

deploy-prod:
	@echo "🚀 Deploying to production..."
	./scripts/deploy.sh production

# Development targets
lint:
	@echo "🔍 Running code linting..."
	. ransomware_env/bin/activate && flake8 src/ tests/
	. ransomware_env/bin/activate && pylint src/

format:
	@echo "🎨 Formatting code..."
	. ransomware_env/bin/activate && black src/ tests/ --line-length 88
	. ransomware_env/bin/activate && isort src/ tests/

security-scan:
	@echo "🔒 Running security scan..."
	. ransomware_env/bin/activate && bandit -r src/
	. ransomware_env/bin/activate && safety check

docs:
	@echo "📚 Generating documentation..."
	. ransomware_env/bin/activate && sphinx-build -b html docs/ docs/_build/

# Monitoring and maintenance
monitor:
	@echo "👁️  Starting system monitor..."
	./scripts/monitor.sh watch

backup:
	@echo "💾 Creating system backup..."
	./scripts/backup.sh

update:
	@echo "🔄 Updating system..."
	git pull origin main
	. ransomware_env/bin/activate && pip install -r requirements.txt --upgrade