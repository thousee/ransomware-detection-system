from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ransomware-detection-system",
    version="1.0.0",
    author="Ransomware Detection Team",
    description="Real-time explainable ransomware detection system for resource-constrained environments",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Flask>=2.3.0",
        "Flask-SocketIO>=5.3.0",
        "scikit-learn>=1.3.0",
        "numpy>=1.24.0",
        "pandas>=1.5.0",
        "psutil>=5.9.0",
        "watchdog>=3.0.0",
        "shap>=0.42.0",
        "joblib>=1.3.0",
        "python-socketio>=5.8.0",
        "eventlet>=0.33.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "viz": [
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
            "plotly>=5.15.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "ransomware-detector=ransomware_detector:main",
            "ransomware-webui=web_server:main",
            "generate-test-data=test_data_generator:main",
        ],
    },
)