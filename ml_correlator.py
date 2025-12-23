"""
ML-based Correlation Engine
RandomForest + Probability Calibration + SHAP
"""

import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
import shap


class MLCorrelator:
    def __init__(self):
        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=6,
            min_samples_leaf=5,
            random_state=42
        )

        self.model = None
        self.explainer = None
        self.trained = False

    def train(self, X, y):
        X = np.array(X)
        y = np.array(y)

        # 1️⃣ Fit RandomForest FIRST
        self.rf_model.fit(X, y)

        # 2️⃣ Calibrate probabilities on top of fitted RF
        self.model = CalibratedClassifierCV(
            self.rf_model,
            method="sigmoid",
            cv=2
        )
        self.model.fit(X, y)

        # 3️⃣ SHAP on FITTED RandomForest
        self.explainer = shap.TreeExplainer(self.rf_model)

        self.trained = True

    def correlate(self, signals, source="unknown", explain=False):
        if not self.trained:
            raise RuntimeError("MLCorrelator not trained")

        X = np.array([[ 
            signals["log_conf"],
            signals["anomaly_conf"],
            signals["event_rate"],
            signals["duration"],
            signals["log_entropy"]
        ]])

        prob = self.model.predict_proba(X)[0][1]

        result = {
            "attack_type": "correlated_attack",
            "confidence": float(prob),
            "source": source,
            "detection_layer": "correlation",
            "timestamp": datetime.now().isoformat()
        }

        if explain:
            shap_values = self.explainer.shap_values(X)[1]
            result["shap_explanation"] = {
                "log_conf": float(shap_values[0][0]),
                "anomaly_conf": float(shap_values[0][1]),
                "event_rate": float(shap_values[0][2]),
                "duration": float(shap_values[0][3]),
                "log_entropy": float(shap_values[0][4]),
            }

        return result
