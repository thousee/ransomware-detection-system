#!/usr/bin/env python3

"""
Comprehensive integration test for the ransomware detection system
"""

import time
import threading
import requests
import json
import subprocess
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from pathlib import Path
from config import Config # Import Config

class IntegrationTester:
    def __init__(self):
        self.base_url = "http://localhost:5000"
        self.passed_tests = 0
        self.failed_tests = 0
        self.server_process = None
        
    def start_server(self):
        """Start the web server for testing"""
        try:
            self.server_process = subprocess.Popen(
                [sys.executable, "web_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(5)  # Wait for server to start
            return True
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            return False
            
    def stop_server(self):
        """Stop the web server"""
        if self.server_process:
            self.server_process.terminate()
            self.server_process.wait()
            
    def test_api_endpoint(self, endpoint, method="GET", data=None, expected_status=200):
        """Test an API endpoint"""
        try:
            url = f"{self.base_url}{endpoint}"
            
            if method == "GET":
                response = requests.get(url, timeout=10)
            elif method == "POST":
                response = requests.post(url, json=data, timeout=10)
            else:
                raise ValueError(f"Unsupported method: {method}")
                
            if response.status_code == expected_status:
                print(f"✅ {method} {endpoint} - Status: {response.status_code}")
                self.passed_tests += 1
                return response
            else:
                print(f"❌ {method} {endpoint} - Expected: {expected_status}, Got: {response.status_code}")
                self.failed_tests += 1
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ {method} {endpoint} - Connection error: {e}")
            self.failed_tests += 1
            return None
            
    def test_web_interface(self):
        """Test web interface accessibility"""
        print("🌐 Testing Web Interface...")
        
        # Test main page
        response = self.test_api_endpoint("/")
        if response and "Ransomware Detection System" in response.text:
            print("✅ Main page loads correctly")
            self.passed_tests += 1
        else:
            print("❌ Main page content incorrect")
            self.failed_tests += 1
            
    def test_api_endpoints(self):
        """Test all API endpoints"""
        print("🔌 Testing API Endpoints...")
        
        # Test system status
        response = self.test_api_endpoint("/api/system_status")
        if response:
            data = response.json()
            if "monitoring_active" in data:
                print("✅ System status contains expected fields")
                self.passed_tests += 1
            else:
                print("❌ System status missing fields")
                self.failed_tests += 1
                
        # Test start monitoring
        self.test_api_endpoint("/api/start_monitoring", "POST")
        
        # Test stop monitoring
        self.test_api_endpoint("/api/stop_monitoring", "POST")
        
        # Test alerts endpoint
        self.test_api_endpoint("/api/alerts")
        
        # Test detections endpoint
        self.test_api_endpoint("/api/detections")
        
        # Test generate test scenario
        self.test_api_endpoint(
            "/api/generate_test_scenario", 
            "POST", 
            {"type": "ransomware"}
        )
        
    def test_core_detection(self):
        """Test core detection engine"""
        print("🔍 Testing Core Detection Engine...")
        
        try:
            # Import and test detector
            from ransomware_detector import RansomwareDetector
            
            detector = RansomwareDetector()
            print("✅ Detector initialization")
            self.passed_tests += 1
            
            # Test feature extraction
            features = detector.feature_extractor.extract_features(
                detector.file_monitor,
                detector.process_monitor
            )
            
            if len(features) == len(detector.feature_extractor.feature_names):
                print("✅ Feature extraction")
                self.passed_tests += 1
            else:
                print("❌ Feature extraction - wrong number of features")
                self.failed_tests += 1
                
            # Test model prediction
            import numpy as np
            test_features = np.array(features).reshape(1, -1)
            scaled_features = detector.scaler.transform(test_features)
            prediction = detector.model.predict(scaled_features)
            risk_score = detector.model.predict_proba(scaled_features)[0][1]
            
            if 0 <= risk_score <= 1:
                print("✅ Model prediction")
                self.passed_tests += 1
            else:
                print("❌ Model prediction - invalid risk score")
                self.failed_tests += 1
                
        except Exception as e:
            print(f"❌ Core detection engine error: {e}")
            self.failed_tests += 1
            
    def test_data_generation(self):
        """Test data generation functionality"""
        print("📊 Testing Data Generation...")
        
        try:
            from test_data_generator import TestDataGenerator
            
            generator = TestDataGenerator("test_output")
            print("✅ Data generator initialization")
            self.passed_tests += 1
            
            # Test ransomware sample generation
            ransomware_data = generator.generate_ransomware_sample("WannaCry", 5, 2)
            if len(ransomware_data) > 0 and all(sample['label'] == 1 for sample in ransomware_data):
                print("✅ Ransomware sample generation")
                self.passed_tests += 1
            else:
                print("❌ Ransomware sample generation")
                self.failed_tests += 1
                
            # Test normal sample generation
            normal_data = generator.generate_normal_sample("idle", 5, 2)
            if len(normal_data) > 0 and all(sample['label'] == 0 for sample in normal_data):
                print("✅ Normal sample generation")
                self.passed_tests += 1
            else:
                print("❌ Normal sample generation")
                self.failed_tests += 1
                
        except Exception as e:
            print(f"❌ Data generation error: {e}")
            self.failed_tests += 1
            
    def test_file_operations(self):
        """Test file operations and monitoring"""
        print("📁 Testing File Operations...")
        
        try:
            # Test database creation
            if Config.DATABASE_PATH.exists():
                print("✅ Database file creation")
                self.passed_tests += 1
            else:
                print("❌ Database file not found")
                self.failed_tests += 1
                
            # Test log file creation
            if Path("ransomware_detector.log").exists():
                print("✅ Logs directory creation")
                self.passed_tests += 1
            else:
                print("❌ Logs directory not found")
                self.failed_tests += 1
                
            # Test model directory
            if Config.MODELS_DIR.exists():
                print("✅ Models directory creation")
                self.passed_tests += 1
            else:
                print("❌ Models directory not found")
                self.failed_tests += 1
                
        except Exception as e:
            print(f"❌ File operations error: {e}")
            self.failed_tests += 1
            
    def run_all_tests(self):
        """Run all integration tests"""
        print("🧪 Starting Integration Tests...")
        print("=" * 50)
        
        # Start server
        if not self.start_server():
            print("❌ Cannot start server, aborting tests")
            return False
            
        try:
            # Run tests
            self.test_core_detection()
            self.test_data_generation()
            self.test_file_operations()
            self.test_web_interface()
            self.test_api_endpoints()
            
            # Wait a bit for any async operations
            time.sleep(2)
            
        finally:
            # Stop server
            self.stop_server()
            
        # Print results
        print("\n" + "=" * 50)
        print("📊 Test Results:")
        print(f"✅ Passed: {self.passed_tests}")
        print(f"❌ Failed: {self.failed_tests}")
        print(f"📈 Success Rate: {self.passed_tests/(self.passed_tests + self.failed_tests)*100:.1f}%")
        
        if self.failed_tests == 0:
            print("\n🎉 All tests passed! System is ready for use.")
            return True
        else:
            print(f"\n⚠️  {self.failed_tests} tests failed. Please check the issues above.")
            return False

def main():
    """Main function to run integration tests"""
    tester = IntegrationTester()
    success = tester.run_all_tests()
    
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()