"""
Unsupervised Anomaly Detection (Isolation Forest)
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime

class AnomalyDetector:
    def __init__(self, contamination=0.05):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42
        )
        self.trained = False

    def train(self, benign_samples):
        X = np.array(benign_samples)
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self.trained = True

    def detect(self, sample):
        if not self.trained:
            raise RuntimeError("AnomalyDetector not trained")

        Xs = self.scaler.transform([sample])
        score = self.model.score_samples(Xs)[0]
        prob = 1 - (1 / (1 + abs(score)))

        return {
            "attack_type": "behavioral_anomaly",
            "confidence": float(prob),
            "source": "network",
            "detection_layer": "anomaly",
            "timestamp": datetime.now().isoformat()
        }
