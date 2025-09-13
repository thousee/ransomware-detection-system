#!/bin/bash

# System monitoring script for the ransomware detector

echo "🔍 Ransomware Detection System Monitor"
echo "======================================"

# Function to check system status
check_system() {
    echo "📊 System Status:"
    echo "  CPU Usage: $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1"%"}')"
    echo "  Memory Usage: $(free | grep Mem | awk '{printf("%.2f%%", $3/$2 * 100.0)}')"
    echo "  Disk Usage: $(df -h / | awk 'NR==2{printf "%s", $5}')"
    echo "  Load Average: $(uptime | awk -F'load average:' '{ print $2 }')"
}

# Function to check detector status
check_detector() {
    echo "🛡️  Detector Status:"
    
    # Check if web server is running
    if pgrep -f "web_server.py" > /dev/null; then
        echo "  Web Server: ✅ Running"
        
        # Check API response
        if curl -s -f http://localhost:5000/api/system_status > /dev/null; then
            echo "  API Endpoint: ✅ Responsive"
        else
            echo "  API Endpoint: ❌ Not responding"
        fi
    else
        echo "  Web Server: ❌ Not running"
    fi
    
    # Check Docker container if applicable
    if docker ps | grep ransomware-detector > /dev/null; then
        echo "  Docker Container: ✅ Running"
    fi
}

# Function to show recent alerts
show_alerts() {
    echo "🚨 Recent Alerts:"
    
    if [ -f "ransomware_detection.db" ]; then
        sqlite3 ransomware_detection.db "
        SELECT severity, message, datetime(timestamp) as time 
        FROM alerts 
        ORDER BY timestamp DESC 
        LIMIT 5;" 2>/dev/null || echo "  No alerts database found"
    else
        echo "  No alerts database found"
    fi
}

# Function to show performance metrics
show_performance() {
    echo "📈 Performance Metrics:"
    
    # CPU usage of detector process
    DETECTOR_PID=$(pgrep -f "web_server.py")
    if [ ! -z "$DETECTOR_PID" ]; then
        DETECTOR_CPU=$(ps -p $DETECTOR_PID -o %cpu --no-headers)
        DETECTOR_MEM=$(ps -p $DETECTOR_PID -o %mem --no-headers)
        echo "  Detector CPU: ${DETECTOR_CPU}%"
        echo "  Detector Memory: ${DETECTOR_MEM}%"
    else
        echo "  Detector process not found"
    fi
}

# Function to restart services
restart_services() {
    echo "🔄 Restarting services..."
    
    # Stop existing processes
    pkill -f "web_server.py"
    
    # Wait a moment
    sleep 2
    
    # Restart
    if [ -f "docker-compose.yml" ]; then
        docker-compose restart
    else
        nohup python web_server.py > logs/server.log 2>&1 &
    fi
    
    echo "✅ Services restarted"
}

# Main monitoring loop
case "${1:-status}" in
    ("status")
        check_system
        echo ""
        check_detector
        echo ""
        show_alerts
        echo ""
        show_performance
        ;;
        
    ("watch")
        echo "👁️  Watching system (Ctrl+C to stop)..."
        while true; do
            clear
            check_system
            echo ""
            check_detector
            echo ""
            show_performance
            sleep 10
        done
        ;;
        
    ("restart")
        restart_services
        ;;
        
    ("logs")
        echo "📋 Recent logs:"
        if [ -f "logs/ransomware_detector.log" ]; then
            tail -50 logs/ransomware_detector.log
        else
            echo "No log file found"
        fi
        ;;
        
    (*)
        echo "Usage: $0 [status|watch|restart|logs]"
        echo "  status  - Show current system status (default)"
        echo "  watch   - Continuously monitor system"
        echo "  restart - Restart detector services"
        echo "  logs    - Show recent log entries"
        ;;
esac