import os
from pathlib import Path

class Config:
    """Configuration settings for the ransomware detection system"""
    
    # Paths
    BASE_DIR = Path(__file__).resolve().parents[1]
    DATA_DIR = BASE_DIR / "data"
    MODELS_DIR = BASE_DIR / "models"
    LOGS_DIR = BASE_DIR / "logs"
    REPORTS_DIR = BASE_DIR / "reports"
    
    # Database
    DATABASE_PATH = BASE_DIR / "ransomware_detection.db"
    
    # Model settings
    DEFAULT_MODEL_PATH = MODELS_DIR / "ransomware_model.joblib"
    FEATURE_SCALER_PATH = MODELS_DIR / "feature_scaler.joblib"
    TRAINING_DATASET_PATH = BASE_DIR / "src" / "test_data" / "training_dataset.csv"
    
    # Monitoring settings
    # FILE_MONITOR_PATHS = ["/home", "/Documents", "/Desktop"]  # Adjust for your system
    FILE_MONITOR_PATHS = ["D:\\testing123",]
    MONITORING_INTERVAL = 20  # seconds
    MAX_ALERTS = 1000
    MAX_DETECTIONS = 10000

    # Suspicious activity patterns
    SUSPICIOUS_EXTENSIONS = {
        '.encrypted', '.locked', '.crypto', '.crypt', '.xxx',
        '.zzz', '.locky', '.cerber', '.vault', '.petya'
    }

    # Detection thresholds
    HIGH_RISK_THRESHOLD = 0.5
    MEDIUM_RISK_THRESHOLD = 0.3
    
    # Performance settings
    MAX_PROCESSES_TO_MONITOR = 100
    FILE_OPERATION_WINDOW = 60  # seconds
    CPU_USAGE_WINDOW = 30  # seconds
    
    # Web interface
    WEB_HOST = "0.0.0.0"
    WEB_PORT = 5000
    WEB_DEBUG = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "your-secret-key-change-in-production")
    
    # Logging
    LOG_LEVEL = "WARNING"
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Resource constraints (for resource-constrained environments)
    MAX_CPU_USAGE = 20  # Max CPU usage percentage for the detector itself
    MAX_MEMORY_USAGE = 200  # Max memory usage in MB

    # Process Monitoring Thresholds
    PROCESS_CPU_THRESHOLD = 80
    PROCESS_MEMORY_THRESHOLD = 70
    PROCESS_THREADS_THRESHOLD = 100
    PROCESS_CONNECTIONS_THRESHOLD = 50

    @classmethod
    def create_directories(cls):
        """Create necessary directories"""
        for dir_path in [cls.DATA_DIR, cls.MODELS_DIR, cls.LOGS_DIR, cls.REPORTS_DIR]:
            dir_path.mkdir(exist_ok=True)
            
    @classmethod
    def get_model_config(cls):
        """Get machine learning model configuration"""
        return {
            'random_forest': {
                'n_estimators': 30,  # Reduced for resource constraints
                'max_depth': 6,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'random_state': 42,
                'n_jobs': 2  # Limited parallel processing
            },
            'feature_selection': {
                'max_features': 12,  # Limit features for efficiency
                'feature_importance_threshold': 0.01
            }
        }