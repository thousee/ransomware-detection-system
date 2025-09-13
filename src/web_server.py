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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
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
                
                # Simulate some realistic system activity
                simulate_system_activity()
                
            time.sleep(5)  # Update every 5 seconds
            
        except Exception as e:
            print(f"Error in monitoring worker: {e}")
            time.sleep(10)

def simulate_system_activity():
    """Simulate realistic system activity for demo purposes"""
    # Occasionally generate test scenarios
    if random.random() < 0.02:  # 2% chance per cycle
        scenario_type = random.choice(['normal_high_activity', 'suspicious_activity', 'potential_ransomware'])
        
        if scenario_type == 'normal_high_activity':
            # Simulate normal but high system activity
            socketio.emit('simulation_event', {
                'type': 'normal_high_activity',
                'message': 'High system activity detected - likely normal operations',
                'timestamp': datetime.now().isoformat()
            })
            
        elif scenario_type == 'suspicious_activity':
            # Simulate suspicious but not necessarily malicious activity
            detector.add_alert(
                "Suspicious process behavior detected",
                severity="medium",
                details="Process accessing multiple files rapidly"
            )
            
        elif scenario_type == 'potential_ransomware':
            # Simulate potential ransomware activity
            detector.add_alert(
                "Potential ransomware behavior detected!",
                severity="high",
                details="Multiple file extensions changed, high CPU usage, suspicious process spawning"
            )

@app.route('/')
def index():
    """Serve the main monitoring interface"""
    return send_file('templates/index.html')

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
        filepath = os.path.join('reports', filename)
        
        # Create reports directory if it doesn't exist
        os.makedirs('reports', exist_ok=True)
        
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

# Create templates directory and save the HTML file
def setup_templates():
    """Setup templates directory and save HTML file"""
    os.makedirs('templates', exist_ok=True)
    
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ransomware Detection System</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            min-height: 100vh;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .header h1 {
            color: #2d3748;
            font-size: 2.5em;
            margin-bottom: 10px;
            background: linear-gradient(45deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-bar {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }

        .status-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
            transition: transform 0.3s ease;
        }

        .status-card:hover {
            transform: translateY(-5px);
        }

        .status-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .status-normal { color: #38a169; }
        .status-warning { color: #d69e2e; }
        .status-danger { color: #e53e3e; }

        .controls {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .control-button {
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .control-button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.5);
        }

        .main-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 25px;
            margin-bottom: 25px;
        }

        .chart-container, .alerts-container, .details-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(31, 38, 135, 0.37);
            border: 1px solid rgba(255, 255, 255, 0.18);
        }

        .alerts-container {
            max-height: 500px;
            overflow-y: auto;
        }

        .alert-item {
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 10px;
            border-left: 4px solid;
            animation: slideIn 0.5s ease-out;
        }

        .alert-high {
            background: rgba(254, 178, 178, 0.3);
            border-left-color: #e53e3e;
        }

        .alert-medium {
            background: rgba(251, 211, 141, 0.3);
            border-left-color: #d69e2e;
        }

        .alert-low {
            background: rgba(154, 230, 180, 0.3);
            border-left-color: #38a169;
        }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }

        .prediction-display {
            text-align: center;
            padding: 30px;
            border-radius: 15px;
            margin: 20px 0;
            font-size: 1.2em;
            font-weight: bold;
            text-transform: uppercase;
        }

        .prediction-benign {
            background: linear-gradient(45deg, #48bb78, #38a169);
            color: white;
        }

        .prediction-ransomware {
            background: linear-gradient(45deg, #f56565, #e53e3e);
            color: white;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
        }

        .feature-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid rgba(0,0,0,0.1);
        }

        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 25px;
            color: white;
            font-weight: bold;
            z-index: 1000;
        }

        .connected { background-color: #38a169; }
        .disconnected { background-color: #e53e3e; }
    </style>
</head>
<body>
    <div class="connection-status" id="connectionStatus">Connecting...</div>
    
    <div class="container">
        <div class="header">
            <h1>🛡️ Ransomware Detection System</h1>
            <p>Real-time explainable ransomware detection for resource-constrained environments</p>
            <div class="prediction-display" id="currentPrediction">
                System Status: Initializing...
            </div>
        </div>

        <div class="controls">
            <button class="control-button" onclick="startMonitoring()">Start Monitoring</button>
            <button class="control-button" onclick="stopMonitoring()">Stop Monitoring</button>
            <button class="control-button" onclick="generateTestData()">Generate Test Data</button>
            <button class="control-button" onclick="exportReport()">Export Report</button>
        </div>

        <div class="status-bar">
            <div class="status-card">
                <h3>Risk Score</h3>
                <div class="status-value" id="riskScore">0.00</div>
            </div>
            
            <div class="status-card">
                <h3>Active Alerts</h3>
                <div class="status-value status-normal" id="activeAlerts">0</div>
                <small>Last hour</small>
            </div>
            
            <div class="status-card">
                <h3>File Operations</h3>
                <div class="status-value status-normal" id="fileOps">0</div>
                <small>Per minute</small>
            </div>
            
            <div class="status-card">
                <h3>System CPU</h3>
                <div class="status-value status-normal" id="systemCpu">0%</div>
            </div>
        </div>

        <div class="main-grid">
            <div class="chart-container">
                <h3>Risk Score Timeline</h3>
                <canvas id="riskChart" width="400" height="200"></canvas>
            </div>
            
            <div class="alerts-container">
                <h3>Real-time Alerts</h3>
                <div id="alertsList">
                    <div class="alert-item alert-low">
                        <strong>System Initialized</strong><br>
                        <small>Ransomware detection system ready</small>
                    </div>
                </div>
            </div>
        </div>

        <div class="details-grid">
            <div class="details-card">
                <h3>Current Features</h3>
                <div id="currentFeatures">
                    <div class="feature-item">
                        <span>File Operations/Min</span>
                        <span id="feat-fileOps">0</span>
                    </div>
                    <div class="feature-item">
                        <span>Process CPU Max</span>
                        <span id="feat-cpuMax">0%</span>
                    </div>
                    <div class="feature-item">
                        <span>Memory Usage</span>
                        <span id="feat-memory">0%</span>
                    </div>
                    <div class="feature-item">
                        <span>Network Connections</span>
                        <span id="feat-network">0</span>
                    </div>
                </div>
            </div>
            
            <div class="details-card">
                <h3>Feature Explanations</h3>
                <div id="explanations">
                    <p>Start monitoring to see feature explanations...</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Initialize Socket.IO
        const socket = io();
        let riskChart;
        let riskData = [];

        // Connection status
        socket.on('connect', function() {
            document.getElementById('connectionStatus').textContent = 'Connected';
            document.getElementById('connectionStatus').className = 'connection-status connected';
        });

        socket.on('disconnect', function() {
            document.getElementById('connectionStatus').textContent = 'Disconnected';
            document.getElementById('connectionStatus').className = 'connection-status disconnected';
        });

        // Initialize risk chart
        function initializeChart() {
            const ctx = document.getElementById('riskChart').getContext('2d');
            riskChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Risk Score',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4,
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 1
                        }
                    }
                }
            });
        }

        // Socket event handlers
        socket.on('system_status', function(data) {
            updateSystemStatus(data);
        });

        socket.on('detection_update', function(data) {
            updateDetection(data);
        });

        socket.on('new_alert', function(data) {
            addAlert(data);
        });

        // Update functions
        function updateSystemStatus(status) {
            if (status.system_cpu !== undefined) {
                document.getElementById('systemCpu').textContent = status.system_cpu.toFixed(1) + '%';
            }
            
            if (status.file_operations_last_minute !== undefined) {
                document.getElementById('fileOps').textContent = status.file_operations_last_minute;
            }
            
            if (status.active_alerts !== undefined) {
                document.getElementById('activeAlerts').textContent = status.active_alerts;
            }
        }

        function updateDetection(detection) {
            // Update risk score
            const riskScore = detection.risk_score;
            document.getElementById('riskScore').textContent = riskScore.toFixed(2);
            
            // Update risk score class
            const riskElement = document.getElementById('riskScore');
            if (riskScore > 0.7) {
                riskElement.className = 'status-value status-danger';
            } else if (riskScore > 0.4) {
                riskElement.className = 'status-value status-warning';
            } else {
                riskElement.className = 'status-value status-normal';
            }
            
            // Update prediction display
            const predictionElement = document.getElementById('currentPrediction');
            if (detection.prediction === 'Ransomware') {
                predictionElement.textContent = 'RANSOMWARE DETECTED!';
                predictionElement.className = 'prediction-display prediction-ransomware';
            } else {
                predictionElement.textContent = 'SYSTEM SECURE';
                predictionElement.className = 'prediction-display prediction-benign';
            }
            
            // Update features
            if (detection.features) {
                document.getElementById('feat-fileOps').textContent = 
                    detection.features.file_ops_per_minute || 0;
                document.getElementById('feat-cpuMax').textContent = 
                    (detection.features.process_cpu_max || 0).toFixed(1) + '%';
                document.getElementById('feat-memory').textContent = 
                    (detection.features.process_memory_max || 0).toFixed(1) + '%';
                document.getElementById('feat-network').textContent = 
                    detection.features.network_connections || 0;
            }
            
            // Update explanations
            updateExplanations(detection.explanation);
            
            // Update chart
            updateChart(riskScore);
        }

        function updateChart(riskScore) {
            const now = new Date().toLocaleTimeString();
            
            if (riskChart.data.labels.length > 20) {
                riskChart.data.labels.shift();
                riskChart.data.datasets[0].data.shift();
            }
            
            riskChart.data.labels.push(now);
            riskChart.data.datasets[0].data.push(riskScore);
            riskChart.update();
        }

        function updateExplanations(explanation) {
            const explanationsDiv = document.getElementById('explanations');
            
            if (explanation && explanation.top_features) {
                let html = '<h4>Top Risk Factors:</h4>';
                explanation.top_features.forEach(feature => {
                    const impactClass = feature.importance > 0 ? 'status-danger' : 'status-normal';
                    html += `
                        <div class="feature-item">
                            <span>${feature.feature}</span>
                            <span class="${impactClass}">${feature.importance.toFixed(2)}</span>
                        </div>
                    `;
                });
                explanationsDiv.innerHTML = html;
            }
        }

        function addAlert(alert) {
            const alertsList = document.getElementById('alertsList');
            const alertItem = document.createElement('div');
            alertItem.className = `alert-item alert-${alert.severity}`;
            alertItem.innerHTML = `
                <strong>${alert.message}</strong><br>
                <small>${alert.details}</small><br>
                <em>${new Date(alert.timestamp).toLocaleTimeString()}</em>
            `;
            
            alertsList.insertBefore(alertItem, alertsList.firstChild);
            
            // Keep only last 10 alerts
            while (alertsList.children.length > 10) {
                alertsList.removeChild(alertsList.lastChild);
            }
        }

        // Control functions
        async function startMonitoring() {
            try {
                const response = await fetch('/api/start_monitoring', { method: 'POST' });
                const result = await response.json();
                addAlert({
                    message: result.message,
                    severity: result.status === 'success' ? 'low' : 'medium',
                    details: '',
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Error starting monitoring:', error);
            }
        }

        async function stopMonitoring() {
            try {
                const response = await fetch('/api/stop_monitoring', { method: 'POST' });
                const result = await response.json();
                addAlert({
                    message: result.message,
                    severity: 'low',
                    details: '',
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Error stopping monitoring:', error);
            }
        }

        async function generateTestData() {
            try {
                const response = await fetch('/api/generate_test_scenario', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ type: 'ransomware' })
                });
                const result = await response.json();
                console.log('Test scenario generated:', result);
            } catch (error) {
                console.error('Error generating test data:', error);
            }
        }

        async function exportReport() {
            try {
                const response = await fetch('/api/export_report');
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `ransomware_report_${Date.now()}.json`;
                a.click();
                window.URL.revokeObjectURL(url);
            } catch (error) {
                console.error('Error exporting report:', error);
            }
        }

        // Initialize when page loads
        document.addEventListener('DOMContentLoaded', function() {
            initializeChart();
        });
    </script>
</body>
</html>'''
    
    with open('templates/index.html', 'w') as f:
        f.write(html_content)

if __name__ == '__main__':
    setup_templates()
    print("Starting Ransomware Detection Web Server...")
    print("Visit http://localhost:5000 to access the monitoring interface")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)