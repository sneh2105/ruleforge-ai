from zeek_feature_extractor import extract_features
from ml_log_detector import MLLogDetector
from anomaly_detector import AnomalyDetector
from ml_correlator import MLCorrelator
from rule_generator import generate_snort_rule
import numpy as np

print("[*] Initializing ML components...")

log_detector = MLLogDetector()
anomaly_detector = AnomalyDetector()
correlator = MLCorrelator()

print("[*] Training models...")

log_detector.train(
    log_batches=[
        ["Failed password", "authentication failure"],
        ["normal traffic", "connection established"]
    ],
    labels=["attack", "normal"]
)

anomaly_detector.train([
    [10, 200, 0.1, 2, 1.2],
    [2, 50, 0.0, 1, 0.4]
])

X = [
    [0.8, 0.7, 30, 120, 0.3],
    [0.2, 0.1, 5, 30, 0.9]
]
y = [1, 0]
correlator.train(X, y)

print("[✓] Training complete")

# ==============================
# Zeek → ML
# ==============================

features = extract_features("conn.log")

log_conf = 0.6  # placeholder until Zeek-text classifier is added

signals = {
    "log_conf": log_conf,
    "anomaly_conf": features["failed_ratio"],
    "event_rate": features["event_rate"],
    "duration": features["avg_duration"],
    "log_entropy": -(
        log_conf * np.log(log_conf + 1e-6) +
        (1 - log_conf) * np.log(1 - log_conf + 1e-6)
    )
}

final_alert = correlator.correlate(signals, source="zeek")

print("\nFINAL ALERT:", final_alert)

if final_alert["confidence"] >= 0.7:
    rule = generate_snort_rule(
        attack_type="zeek_behavioral_attack",
        confidence=final_alert["confidence"]
    )
    print("\n🚨 GENERATED RULE:\n", rule)
else:
    print("\n[+] ML decided: no rule generated")
