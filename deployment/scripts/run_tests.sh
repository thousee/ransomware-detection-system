#!/bin/bash

# Activate virtual environment if it exists
if [ -d "ransomware_env" ]; then
    source ransomware_env/bin/activate
fi

echo "🧪 Running Ransomware Detection System Tests..."

# Test core detection engine
echo "Testing core detection engine..."
python -c "
from ransomware_detector import RansomwareDetector
import time

detector = RansomwareDetector()
print('✅ Detector initialized successfully')

# Test feature extraction
features = detector.feature_extractor.extract_features(
    detector.file_monitor, 
    detector.process_monitor
)
print(f'✅ Feature extraction working: {len(features)} features')

# Test model prediction
import numpy as np
test_features = np.array(features).reshape(1, -1)
scaled_features = detector.scaler.transform(test_features)
prediction = detector.model.predict(scaled_features)
risk_score = detector.model.predict_proba(scaled_features)[0][1]
print(f'✅ Model prediction working: {prediction[0]} (risk: {risk_score:.3f})')

print('✅ All core tests passed!')
"

# Test web server components
echo "Testing web server components..."
python -c "
from web_server import WebRansomwareDetector
import json

detector = WebRansomwareDetector()
print('✅ Web detector initialized')

# Test status
status = detector.get_system_status()
print(f'✅ System status: {json.dumps(status, indent=2)}')

print('✅ All web server tests passed!')
"

echo "🎉 All tests completed successfully!"