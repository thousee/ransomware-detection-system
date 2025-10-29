import os
import psutil
import time
import threading
import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from pathlib import Path
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pandas as pd # Added for reading CSV
import joblib
import shap
import logging
from typing import Dict, List, Tuple, Any
import hashlib
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ransomware_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class FileSystemMonitor(FileSystemEventHandler):
    """Monitor file system events for ransomware patterns"""
    
    def __init__(self, detector):
        self.detector = detector
        self.file_operations = deque(maxlen=200)
        self.suspicious_extensions = Config.SUSPICIOUS_EXTENSIONS
        
    def on_created(self, event):
        if not event.is_directory:
            self._record_operation('created', event.src_path)
            # Immediately check for suspicious extension on creation
            if Path(event.src_path).suffix.lower() in self.suspicious_extensions:
                self.detector.add_alert("Suspicious file created with ransomware extension",
                                      severity="high",
                                      details=f"File: {event.src_path}")
            
    def on_deleted(self, event):
        if not event.is_directory:
            self._record_operation('deleted', event.src_path)
            
    def on_modified(self, event):
        if not event.is_directory:
            self._record_operation('modified', event.src_path)
            
    def on_moved(self, event):
        if not event.is_directory:
            self._record_operation('renamed', f"{event.src_path} -> {event.dest_path}")
            
    def _record_operation(self, operation, path):
        timestamp = datetime.now()
        self.file_operations.append({
            'timestamp': timestamp,
            'operation': operation,
            'path': path,
            'extension': Path(path).suffix.lower()
        })
        
        # Check for suspicious patterns
        self._check_suspicious_activity()
        
    def _check_suspicious_activity(self):
        """Check for suspicious file system patterns"""
        if len(self.file_operations) < 10:
            return
            
        recent_ops = [op for op in self.file_operations 
                     if datetime.now() - op['timestamp'] < timedelta(seconds=30)]
        
        # Check for rapid file operations
        if len(recent_ops) > 50:
            self.detector.add_alert("High file operation rate detected", 
                                  severity="medium", 
                                  details=f"{len(recent_ops)} operations in 30 seconds")
        
        # Check for suspicious extensions
        suspicious_files = [op for op in recent_ops 
                          if op['extension'] in self.suspicious_extensions]
        if len(suspicious_files) > 0:
            self.detector.add_alert("Suspicious file extensions detected", 
                                  severity="high", 
                                  details=f"Files with suspicious extensions: {len(suspicious_files)}")

class ProcessMonitor:
    """Monitor process behavior for ransomware patterns"""
    
    def __init__(self, detector):
        self.detector = detector
        self.process_stats = {}
        self.suspicious_processes = set()
        self.monitoring = False
        
    def start_monitoring(self):
        """Start continuous process monitoring"""
        self.monitoring = True
        monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        monitor_thread.start()
        
    def stop_monitoring(self):
        """Stop process monitoring"""
        self.monitoring = False
        
    def _monitor_processes(self):
        """Main monitoring loop for processes"""
        while self.monitoring:
            try:
                current_processes = {}
                
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 
                                               'memory_percent', 'num_threads', 
                                               'connections']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Get detailed process info
                        process_data = {
                            'name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent'],
                            'num_threads': proc_info['num_threads'],
                            'connections': len(proc_info['connections'] or []),
                            'timestamp': datetime.now()
                        }
                        
                        current_processes[pid] = process_data
                        
                        # Check for suspicious behavior
                        if self._is_suspicious_process(process_data):
                            self.suspicious_processes.add(pid)
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
                self.process_stats = current_processes
                self._analyze_process_patterns()
                
                time.sleep(Config.MONITORING_INTERVAL)  # Monitor every Config.MONITORING_INTERVAL seconds
                
            except Exception as e:
                logger.error(f"Error in process monitoring: {e}")
                
    def _is_suspicious_process(self, process_data):
        """Check if a process exhibits suspicious behavior"""
        suspicious_patterns = [
            process_data['cpu_percent'] > Config.PROCESS_CPU_THRESHOLD,  # High CPU usage
            process_data['memory_percent'] > Config.PROCESS_MEMORY_THRESHOLD,  # High memory usage
            process_data['num_threads'] > Config.PROCESS_THREADS_THRESHOLD,  # Too many threads
            process_data['connections'] > Config.PROCESS_CONNECTIONS_THRESHOLD,  # Too many connections
        ]
        
        return sum(suspicious_patterns) >= 2
        
    def _analyze_process_patterns(self):
        """Analyze patterns across all processes"""
        if len(self.suspicious_processes) > 3:
            self.detector.add_alert("Multiple suspicious processes detected", 
                                  severity="high", 
                                  details=f"{len(self.suspicious_processes)} suspicious processes")

class FeatureExtractor:
    """Extract features for machine learning model"""
    
    def __init__(self):
        self.feature_names = [
            'file_ops_per_minute', 'unique_extensions_accessed', 'suspicious_extensions',
            'process_cpu_mean', 'process_cpu_max', 'process_memory_mean', 
            'process_memory_max', 'active_processes', 'network_connections',
            'file_creation_rate', 'file_deletion_rate', 'file_modification_rate'
        ]
        
    def extract_features(self, file_monitor, process_monitor):
        """Extract features from current system state"""
        features = {}
        
        # File system features
        recent_ops = [op for op in file_monitor.file_operations 
                     if datetime.now() - op['timestamp'] < timedelta(minutes=1)]
        
        features['file_ops_per_minute'] = len(recent_ops)
        
        extensions = set(op['extension'] for op in recent_ops if op['extension'])
        features['unique_extensions_accessed'] = len(extensions)
        
        suspicious_ext_count = sum(1 for ext in extensions 
                                 if ext in file_monitor.suspicious_extensions)
        features['suspicious_extensions'] = suspicious_ext_count
        
        # Operation type counts
        op_counts = defaultdict(int)
        for op in recent_ops:
            op_counts[op['operation']] += 1
            
        features['file_creation_rate'] = op_counts['created']
        features['file_deletion_rate'] = op_counts['deleted']
        features['file_modification_rate'] = op_counts['modified']
        
        # Process features
        if process_monitor.process_stats:
            cpu_values = [p['cpu_percent'] for p in process_monitor.process_stats.values() 
                         if p['cpu_percent'] is not None]
            memory_values = [p['memory_percent'] for p in process_monitor.process_stats.values() 
                           if p['memory_percent'] is not None]
            
            features['process_cpu_mean'] = np.mean(cpu_values) if cpu_values else 0
            features['process_cpu_max'] = max(cpu_values) if cpu_values else 0
            features['process_memory_mean'] = np.mean(memory_values) if memory_values else 0
            features['process_memory_max'] = max(memory_values) if memory_values else 0
            features['active_processes'] = len(process_monitor.process_stats)
            
            total_connections = sum(p['connections'] for p in process_monitor.process_stats.values())
            features['network_connections'] = total_connections
        else:
            features.update({
                'process_cpu_mean': 0, 'process_cpu_max': 0,
                'process_memory_mean': 0, 'process_memory_max': 0,
                'active_processes': 0, 'network_connections': 0
            })
        
        return [features.get(name, 0) for name in self.feature_names]

class RansomwareDetector:
    """Main ransomware detection system"""
    
    def __init__(self, model_path=None):
        self.file_monitor = FileSystemMonitor(self)
        self.process_monitor = ProcessMonitor(self)
        self.feature_extractor = FeatureExtractor()
        
        self.alerts = deque(maxlen=1000)
        self.detection_history = deque(maxlen=1000)
        
        # Initialize ML components
        self.model = None
        self.scaler = StandardScaler()
        self.explainer = None
        
        # Load or create model
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
        else:
            self._create_default_model()

        # Database for logging
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database for logging"""
        self.db_path = Config.DATABASE_PATH
        conn = sqlite3.connect(self.db_path)

        conn.execute('''
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                risk_score REAL,
                prediction TEXT,
                features TEXT,
                explanation TEXT
            )
        ''')

        conn.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                severity TEXT,
                message TEXT,
                details TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def train_model(self, data_path: Path):
        """Train the ransomware detection model using the provided dataset."""
        logger.info(f"Loading training data from {data_path}...")
        try:
            df = pd.read_csv(data_path)
        except FileNotFoundError:
            logger.error(f"Training data file not found at {data_path}")
            return

        # Separate features (X) and labels (y)
        X = df[self.feature_extractor.feature_names].values
        y = df['label'].values

        logger.info(f"Training model with {len(X)} samples...")

        # Scale features
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)

        # Train model
        model_config = Config.get_model_config()['random_forest']
        self.model = RandomForestClassifier(
            n_estimators=model_config['n_estimators'],
            max_depth=model_config['max_depth'],
            min_samples_split=model_config['min_samples_split'],
            min_samples_leaf=model_config['min_samples_leaf'],
            random_state=model_config['random_state'],
            n_jobs=model_config['n_jobs']
        )
        self.model.fit(X_scaled, y)

        # Create explainer
        self.explainer = shap.TreeExplainer(self.model)

        # Save the trained model and scaler
        joblib.dump(self.model, Config.DEFAULT_MODEL_PATH)
        joblib.dump(self.scaler, Config.FEATURE_SCALER_PATH)
        logger.info(f"Model saved to {Config.DEFAULT_MODEL_PATH}")
        logger.info(f"Feature scaler saved to {Config.FEATURE_SCALER_PATH}")

        logger.info("Model training completed successfully.")

    def _create_default_model(self):
        """Create a default model, attempting to train with generated data."""
        logger.info("Attempting to create/train default model...")
        Config.MODELS_DIR.mkdir(exist_ok=True)

        if Config.TRAINING_DATASET_PATH.exists():
            self.train_model(Config.TRAINING_DATASET_PATH)
        else:
            logger.warning("Training dataset not found. Creating a minimal synthetic model for startup.")
            # Fallback to minimal synthetic data if no training_dataset.csv exists
            X_train, y_train = self._generate_synthetic_data_fallback(100)
            self.scaler.fit(X_train)
            X_train_scaled = self.scaler.transform(X_train)
            model_config = Config.get_model_config()['random_forest']
            self.model = RandomForestClassifier(
                n_estimators=model_config['n_estimators'],
                max_depth=model_config['max_depth'],
                random_state=model_config['random_state'],
                n_jobs=model_config['n_jobs']
            )
            self.model.fit(X_train_scaled, y_train)
            self.explainer = shap.TreeExplainer(self.model)
            joblib.dump(self.model, Config.DEFAULT_MODEL_PATH)
            joblib.dump(self.scaler, Config.FEATURE_SCALER_PATH)
            logger.info("Minimal synthetic model created and saved.")

    def _generate_synthetic_data(self, n_samples):
        """Generate synthetic training data"""
        X = []
        y = []
        
        for _ in range(n_samples):
            if np.random.random() < 0.3:  # 30% ransomware samples
                # Ransomware-like features
                features = [
                    np.random.exponential(100),  # High file ops
                    np.random.poisson(20),       # Many extensions
                    np.random.poisson(5),        # Suspicious extensions
                    np.random.normal(70, 15),    # High CPU mean
                    np.random.normal(90, 10),    # High CPU max
                    np.random.normal(60, 20),    # High memory mean
                    np.random.normal(80, 15),    # High memory max
                    np.random.poisson(50),       # Many processes
                    np.random.poisson(20),       # Many connections
                    np.random.exponential(50),   # High creation rate
                    np.random.exponential(30),   # High deletion rate
                    np.random.exponential(80),   # High modification rate
                ]
                y.append(1)  # Ransomware
            else:
                # Benign features
                features = [
                    np.random.exponential(10),   # Low file ops
                    np.random.poisson(5),        # Few extensions
                    0,                           # No suspicious extensions
                    np.random.normal(20, 10),    # Low CPU mean
                    np.random.normal(40, 15),    # Moderate CPU max
                    np.random.normal(30, 15),    # Low memory mean
                    np.random.normal(50, 20),    # Moderate memory max
                    np.random.poisson(20),       # Normal processes
                    np.random.poisson(5),        # Few connections
                    np.random.poisson(5),        # Low creation rate
                    np.random.poisson(2),        # Low deletion rate
                    np.random.poisson(10),       # Normal modification rate
                ]
                y.append(0)  # Benign
                
            X.append(features)
            
        return np.array(X), np.array(y)

    def _generate_synthetic_data_fallback(self, n_samples):
        """Generate minimal synthetic training data for fallback scenario"""
        X = []
        y = []
        for _ in range(n_samples):
            if np.random.random() < 0.5:  # 50% ransomware samples
                features = [
                    np.random.exponential(50), np.random.poisson(10), np.random.poisson(3),
                    np.random.normal(50, 10), np.random.normal(70, 10), np.random.normal(40, 15),
                    np.random.normal(60, 15), np.random.poisson(30), np.random.poisson(10),
                    np.random.exponential(20), np.random.exponential(10), np.random.exponential(40),
                ]
                y.append(1)  # Ransomware
            else:
                features = [
                    np.random.exponential(5), np.random.poisson(2), 0,
                    np.random.normal(10, 5), np.random.normal(20, 10), np.random.normal(15, 5),
                    np.random.normal(25, 10), np.random.poisson(10), np.random.poisson(2),
                    np.random.poisson(2), np.random.poisson(1), np.random.poisson(5),
                ]
                y.append(0)  # Benign
            X.append(features)
        return np.array(X), np.array(y)
        
    def start_monitoring(self):
        """Start the ransomware detection system"""
        logger.info("Starting ransomware detection system...")
        
        # Start file system monitoring
        observer = Observer()
        for path in Config.FILE_MONITOR_PATHS:
            observer.schedule(self.file_monitor, path=path, recursive=True)
        observer.start()
        
        # Start process monitoring
        self.process_monitor.start_monitoring()
        
        # Start main detection loop
        detection_thread = threading.Thread(target=self._detection_loop, daemon=True)
        detection_thread.start()
        
        logger.info("Ransomware detection system started")
        return observer
        
    def _detection_loop(self):
        """Main detection loop"""
        while True:
            try:
                # Extract features
                features = self.feature_extractor.extract_features(
                    self.file_monitor, self.process_monitor
                )
                
                # Make prediction
                features_array = np.array(features).reshape(1, -1)
                features_scaled = self.scaler.transform(features_array)
                
                prediction = self.model.predict(features_scaled)[0]
                risk_score = self.model.predict_proba(features_scaled)[0][1]
                
                # Generate explanation
                explanation = self._generate_explanation(features_scaled[0])
                
                # Log detection
                detection_result = {
                    'timestamp': datetime.now(),
                    'risk_score': float(risk_score),
                    'prediction': 'Ransomware' if prediction == 1 else 'Benign',
                    'features': features,
                    'explanation': explanation
                }
                
                self.detection_history.append(detection_result)
                self._log_detection_to_db(detection_result)
                
                # Generate alerts if necessary
                if risk_score > 0.7:
                    self.add_alert(
                        f"High ransomware risk detected (score: {risk_score:.2f})",
                        severity="high" if risk_score > 0.9 else "medium",
                        details=f"Top suspicious features: {explanation['top_features']}"
                    )
                
                time.sleep(Config.MONITORING_INTERVAL)  # Check every Config.MONITORING_INTERVAL seconds
                
            except Exception as e:
                logger.error(f"Error in detection loop: {e}")
                
    def _generate_explanation(self, features):
        """Generate explanation for the prediction"""
        if self.explainer is None:
            return {"error": "No explainer available"}
            
        try:
            shap_values = self.explainer.shap_values(features.reshape(1, -1))
            
            if len(shap_values) > 1:  # Multi-class
                shap_values = shap_values[1]  # Use values for ransomware class
            
            feature_importance = list(zip(
                self.feature_extractor.feature_names,
                shap_values[0] if len(shap_values.shape) > 1 else shap_values,
                features
            ))
            
            # Sort by absolute importance
            feature_importance.sort(key=lambda x: abs(x[1]), reverse=True)
            
            top_features = []
            for name, importance, value in feature_importance[:5]:
                top_features.append({
                    'feature': name,
                    'value': float(value),
                    'importance': float(importance),
                    'impact': 'Increases risk' if importance > 0 else 'Decreases risk'
                })
                
            return {
                'top_features': top_features,
                'total_features': len(feature_importance)
            }
            
        except Exception as e:
            logger.error(f"Error generating explanation: {e}")
            return {"error": str(e)}
            
    def add_alert(self, message, severity="medium", details=""):
        """Add an alert to the system"""
        alert = {
            'timestamp': datetime.now(),
            'severity': severity,
            'message': message,
            'details': details
        }
        
        self.alerts.append(alert)
        logger.warning(f"ALERT [{severity.upper()}]: {message}")
        
        # Log to database
        self._log_alert_to_db(alert)
        
    def _log_detection_to_db(self, detection):
        """Log detection result to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO detections (timestamp, risk_score, prediction, features, explanation)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                detection['timestamp'].isoformat(),
                detection['risk_score'],
                detection['prediction'],
                json.dumps(detection['features']),
                json.dumps(detection['explanation'])
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging detection to database: {e}")
            
    def _log_alert_to_db(self, alert):
        """Log alert to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute('''
                INSERT INTO alerts (timestamp, severity, message, details)
                VALUES (?, ?, ?, ?)
            ''', (
                alert['timestamp'].isoformat(),
                alert['severity'],
                alert['message'],
                alert['details']
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error logging alert to database: {e}")
            
    def get_system_status(self):
        """Get current system status"""
        return {
            'active_alerts': len([a for a in self.alerts 
                                if datetime.now() - a['timestamp'] < timedelta(hours=1)]),
            'total_detections': len(self.detection_history),
            'recent_risk_scores': [d['risk_score'] for d in list(self.detection_history)[-10:]],
            'suspicious_processes': len(self.process_monitor.suspicious_processes),
            'file_operations_last_minute': len([
                op for op in self.file_monitor.file_operations 
                if datetime.now() - op['timestamp'] < timedelta(minutes=1)
            ])
        }
        
    def save_model(self, path):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_extractor.feature_names
        }
        joblib.dump(model_data, path)
        logger.info(f"Model saved to {path}")
        
    def load_model(self, path):
        """Load a trained model"""
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        
        if self.model:
            self.explainer = shap.TreeExplainer(self.model)
            
        logger.info(f"Model loaded from {path}")

# Example usage
if __name__ == "__main__":
    detector = RansomwareDetector()
    observer = detector.start_monitoring()
    
    try:
        while True:
            status = detector.get_system_status()
            print(f"System Status: {status}")
            time.sleep(30)
    except KeyboardInterrupt:
        print("Stopping ransomware detection system...")
        detector.process_monitor.stop_monitoring()
        observer.stop()
        observer.join()