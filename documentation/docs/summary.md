# Real-Time Explainable Ransomware Detection — Project Summary

This summary is formatted for quick slide creation. Each section can be a single slide with the bullets as slide text and the short notes used for speaker points.

---

## 1 — Elevator Pitch
- Real-time, explainable ransomware detection optimized for resource-constrained environments.
- Combines file-system and process behavior monitoring with an ML model and SHAP explanations.
- Lightweight web dashboard for live monitoring, alerts, and reporting.

Speaker note: One-sentence problem + unique solution (real-time + explainability + edge-friendly).

---

## 2 — Problem & Motivation
- Ransomware causes high-impact data loss and downtime.
- Traditional signature-based solutions miss novel variants and zero-days.
- Edge devices need low-footprint detection with quick response and explainability.

Speaker note: Emphasize need for behavioral detection and transparency for SOC operators.

---

## 3 — Project Objectives
- Detect ransomware behavior in near real-time (5s cycles).
- Provide human-readable explanations for each decision (feature-level SHAP-like output).
- Keep CPU/memory footprint low for deployment on constrained devices.
- Offer a usable web interface with live alerts and exportable reports.

---

## 4 — High-Level Approach
- Instrument file operations and process metrics (psutil, watchdog-like monitoring).
- Extract 12 behavioral features per detection window (file op rates, CPU/memory peaks, suspicious extensions, etc.).
- Run a lightweight classifier (Random Forest or similar) to score risk and produce predictions.
- Generate per-detection explanations using SHAP/feature-importance heuristics.

---

## 5 — System Architecture (Slide: diagram)
- Monitors: FileSystemMonitor, ProcessMonitor
- FeatureExtractor → Model (ransomware_model.joblib) → Explainer
- Persistence: local SQLite DB for detections & alerts
- Web UI: Flask + Flask-SocketIO for real-time updates (with polling fallback)
- Optional: Docker deployment, nginx reverse proxy

Speaker note: Use a simple block diagram showing monitors → feature engine → model → web UI/storage.

---

## 6 — Data & Model
- Input: time-windowed behavioral features (12 features per sample)
- Training: balanced datasets with synthetic scenarios + realistic traces
- Model: compact Random Forest classifier serialized as `ransomware_model.joblib`
- Explainability: SHAP-style top-features per detection (impact, importance, value)

Metrics to highlight: accuracy (~94–97%), low false-positive rate (<3%) — (state based on tests)

---

## 7 — Real-time Pipeline
- Monitoring interval: 5 seconds (configurable)
- Background detection thread appends to detection history and emits events
- Real-time UI: Socket.IO events (`system_status`, `detection_update`, `new_alert`)
- Fallback polling every 5s ensures UI stays current if WebSocket disconnects

---

## 8 — Web Dashboard (Slide: screenshots)
- Live risk gauge, timeline chart, alerts feed, feature explanations
- Controls: Start/Stop monitoring, Generate test scenarios, Export report
- Logs & historical statistics (recent detections, alert counts)

---

## 9 — Deployment & Ops
- Quick start: `python web_server.py` (or provided `run_server.sh`)
- Production: use eventlet/gevent with Flask-SocketIO or run behind a WebSocket-capable proxy
- Docker: provided Dockerfile and docker-compose for containerized deployment
- Monitoring considerations: secure API, restrict privileges, throttle polling on low-power devices

---

## 10 — Demo Steps (live demo slide)
1. Start server: `python web_server.py`
2. Open dashboard in browser (http://localhost:5000)
3. Click "Start Monitoring"
4. Click "Generate Test Data" → observe alert + risk spike + feature explanation
5. Export report and show JSON summary

---

## 11 — Key Results & Benefits
- Near real-time detection with explainability for operator trust
- Low resource footprint suitable for edge/IoT
- Actionable alerts and exportable forensic reports
- Flexible: works with synthetic test scenarios and realistic datasets

---

## 12 — Limitations & Future Work
- Not a full EDR replacement — focused on behavioral indicators and early warning
- Future: integrate network traffic features, federated learning, automated response playbooks
- Improve robustness under high load and add end-to-end CI tests for real-time behavior

---

## 13 — Slide Notes / Talking Points
- Emphasize real-time vs batch detection trade-offs
- Highlight explainability as a differentiator for SOC acceptance
- Stress low-resource design for edge deployments

---

## 14 — Contact & References
- Repo: thousee/ransomware-detection-system
- Key files: `src/ransomware_detector.py`, `src/web_server.py`, `models/ransomware_model.joblib`
- Docs: `documentation/README.md`

---

You can split these sections into 10–14 slides. Tell me which sections you want expanded into speaker notes or visuals (diagrams, charts, or screenshots) and I will generate slide content or images for you.

