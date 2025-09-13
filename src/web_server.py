from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit
import json
import threading
import time
import os
from datetime import datetime, timedelta
import sqlite3
from ransomware_detector import RansomwareDetector  # Import our detector
import psutil
import random
from config import Config

# Calculate the absolute path to the template directory
TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'template'))

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config['SECRET_KEY'] = Config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*")

# Global detector instance
detector = None
monitoring_thread = None
is_monitoring = False

class WebRansomwareDetector(RansomwareDetector):
    """Extended detector with web interface capabilities"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.socketio = None
        
    def set_socketio(self, socketio_instance):
        self.socketio = socketio_instance
        
    def add_alert(self, message, severity="medium", details=""):
        """Override to emit alerts via websocket"""
        alert = super().add_alert(message, severity, details)
        
        if self.socketio:
            self.socketio.emit('new_alert', {
                'message': message,
                'severity': severity,
                'details': details,
                'timestamp': datetime.now().isoformat()
            })
            
        return alert
        
    def emit_detection_update(self, detection_result):
        """Emit real-time detection updates"""
        if self.socketio:
            self.socketio.emit('detection_update', {
                'risk_score': detection_result['risk_score'],
                'prediction': detection_result['prediction'],
                'features': dict(zip(
                    self.feature_extractor.feature_names,
                    detection_result['features']
                )),
                'explanation': detection_result['explanation'],
                'timestamp': detection_result['timestamp'].isoformat()
            })

def monitoring_worker():
    """Background thread for continuous monitoring"""
    global detector, is_monitoring
    
    while is_monitoring:
        try:
            if detector:
                # Get current system status
                status = detector.get_system_status()
                
                # Get latest detection if available
                if detector.detection_history:
                    latest_detection = detector.detection_history[-1]
                    detector.emit_detection_update(latest_detection)
                
                # Emit system status
                socketio.emit('system_status', status)

            time.sleep(5)  # Update every 5 seconds

        except Exception as e:
            print(f"Error in monitoring worker: {e}")
            time.sleep(10)

@app.route('/')
def index():
    """Serve the main monitoring interface"""
    return render_template('index.html')

@app.route('/api/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start the ransomware detection monitoring"""
    global detector, monitoring_thread, is_monitoring
    
    try:
        if not detector:
            detector = WebRansomwareDetector()
            detector.set_socketio(socketio)
            
        if not is_monitoring:
            is_monitoring = True
            
            # Start the detector's internal monitoring
            observer = detector.start_monitoring()
            
            # Start web monitoring thread
            monitoring_thread = threading.Thread(target=monitoring_worker, daemon=True)
            monitoring_thread.start()
            
            return jsonify({
                'status': 'success',
                'message': 'Monitoring started successfully'
            })
        else:
            return jsonify({
                'status': 'info',
                'message': 'Monitoring already active'
            })
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to start monitoring: {str(e)}'
        })

@app.route('/api/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop the ransomware detection monitoring"""
    global is_monitoring
    
    try:
        is_monitoring = False
        
        if detector:
            detector.process_monitor.stop_monitoring()
            
        return jsonify({
            'status': 'success',
            'message': 'Monitoring stopped successfully'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to stop monitoring: {str(e)}'
        })

@app.route('/api/system_status')
def get_system_status():
    """Get current system status"""
    if detector:
        status = detector.get_system_status()
        
        # Add additional system information
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        status.update({
            'system_cpu': cpu_percent,
            'system_memory': memory.percent,
            'system_disk': disk.percent,
            'monitoring_active': is_monitoring,
            'timestamp': datetime.now().isoformat()
        })
        
        return jsonify(status)
    else:
        return jsonify({
            'error': 'Detector not initialized',
            'monitoring_active': False
        })

@app.route('/api/alerts')
def get_alerts():
    """Get recent alerts"""
    if detector:
        alerts = [
            {
                'message': alert['message'],
                'severity': alert['severity'],
                'details': alert['details'],
                'timestamp': alert['timestamp'].isoformat()
            }
            for alert in detector.alerts
        ]
        return jsonify(alerts)
    else:
        return jsonify([])

@app.route('/api/detections')
def get_detections():
    """Get recent detection results"""
    if detector and detector.detection_history:
        detections = [
            {
                'risk_score': d['risk_score'],
                'prediction': d['prediction'],
                'timestamp': d['timestamp'].isoformat(),
                'features': dict(zip(
                    detector.feature_extractor.feature_names,
                    d['features']
                )),
                'explanation': d['explanation']
            }
            for d in detector.detection_history
        ]
        return jsonify(detections[-50:])  # Last 50 detections
    else:
        return jsonify([])

@app.route('/api/generate_test_scenario', methods=['POST'])
def generate_test_scenario():
    """Generate a test ransomware scenario"""
    scenario_type = request.json.get('type', 'ransomware')
    
    if not detector:
        return jsonify({
            'status': 'error',
            'message': 'Detector not initialized'
        })
    
    try:
        if scenario_type == 'ransomware':
            # Simulate ransomware detection
            detector.add_alert(
                "TEST: Ransomware simulation activated",
                severity="high",
                details="Simulating file encryption patterns, process injection, and network communication"
            )
            
            # Create fake high-risk detection
            test_detection = {
                'timestamp': datetime.now(),
                'risk_score': 0.95,
                'prediction': 'Ransomware',
                'features': [150, 25, 8, 85, 98, 75, 90, 45, 30, 80, 60, 120],  # High-risk feature values
                'explanation': {
                    'top_features': [
                        {'feature': 'file_modification_rate', 'value': 120, 'importance': 0.8, 'impact': 'Increases risk'},
                        {'feature': 'process_cpu_max', 'value': 98, 'importance': 0.7, 'impact': 'Increases risk'},
                        {'feature': 'suspicious_extensions', 'value': 8, 'importance': 0.6, 'impact': 'Increases risk'}
                    ]
                }
            }
            
            detector.detection_history.append(test_detection)
            detector.emit_detection_update(test_detection)
            
        elif scenario_type == 'normal_high_activity':
            detector.add_alert(
                "TEST: High system activity simulation",
                severity="medium",
                details="Simulating legitimate high system activity (software installation, file backup, etc.)"
            )
            
        return jsonify({
            'status': 'success',
            'message': f'Test scenario "{scenario_type}" generated successfully'
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to generate test scenario: {str(e)}'
        })

@app.route('/api/export_report')
def export_report():
    """Export detection report"""
    try:
        if not detector:
            return jsonify({'error': 'Detector not initialized'})
            
        # Gather report data
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'monitoring_duration': 'N/A',  # Could track this
            'total_detections': len(detector.detection_history),
            'total_alerts': len(detector.alerts),
            'system_status': detector.get_system_status(),
            'recent_detections': [
                {
                    'timestamp': d['timestamp'].isoformat(),
                    'risk_score': d['risk_score'],
                    'prediction': d['prediction'],
                    'features': dict(zip(detector.feature_extractor.feature_names, d['features']))
                }
                for d in detector.detection_history[-100:]  # Last 100
            ],
            'recent_alerts': [
                {
                    'timestamp': a['timestamp'].isoformat(),
                    'severity': a['severity'],
                    'message': a['message'],
                    'details': a['details']
                }
                for a in detector.alerts
            ]
        }
        
        # Save to file
        filename = f"ransomware_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = Config.REPORTS_DIR / filename

        # Create reports directory if it doesn't exist
        Config.REPORTS_DIR.mkdir(exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2)
            
        return send_file(filepath, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Failed to export report: {str(e)}'
        })

@app.route('/api/database_stats')
def get_database_stats():
    """Get database statistics"""
    if not detector:
        return jsonify({'error': 'Detector not initialized'})
        
    try:
        conn = sqlite3.connect(detector.db_path)
        
        # Get detection counts
        detection_counts = conn.execute('''
            SELECT prediction, COUNT(*) as count 
            FROM detections 
            GROUP BY prediction
        ''').fetchall()
        
        # Get alert counts by severity
        alert_counts = conn.execute('''
            SELECT severity, COUNT(*) as count 
            FROM alerts 
            GROUP BY severity
        ''').fetchall()
        
        # Get recent activity
        recent_detections = conn.execute('''
            SELECT timestamp, risk_score, prediction 
            FROM detections 
            ORDER BY timestamp DESC 
            LIMIT 10
        ''').fetchall()
        
        conn.close()
        
        return jsonify({
            'detection_counts': dict(detection_counts),
            'alert_counts': dict(alert_counts),
            'recent_detections': [
                {
                    'timestamp': r[0],
                    'risk_score': r[1],
                    'prediction': r[2]
                } for r in recent_detections
            ]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)})

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print('Client connected')
    
    # Send initial status
    if detector:
        status = detector.get_system_status()
        emit('system_status', status)

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('request_update')
def handle_update_request():
    """Handle manual update requests from client"""
    if detector:
        status = detector.get_system_status()
        emit('system_status', status)
        
        if detector.detection_history:
            latest_detection = detector.detection_history[-1]
            detector.emit_detection_update(latest_detection)

if __name__ == '__main__':
    print("Starting Ransomware Detection Web Server...")
    print(f"Visit http://{Config.WEB_HOST}:{Config.WEB_PORT} to access the monitoring interface")
    socketio.run(app, debug=Config.WEB_DEBUG, host=Config.WEB_HOST, port=Config.WEB_PORT)