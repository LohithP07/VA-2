import json
import os
import numpy as np
from sklearn.ensemble import IsolationForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "events.json")

model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)


def extract_features(events):
    """
    Features:
    - requests per minute
    - event type (upload=1, verify=2)
    """
    features = []
    for e in events:
        features.append([
            e["details"].get("count", 1),
            1 if e["event_type"] == "upload" else 2
        ])
    return np.array(features)


def detect_anomaly():
    if not os.path.exists(LOG_PATH):
        return {"anomaly": False}

    with open(LOG_PATH, "r") as f:
        events = json.load(f)

    if len(events) < 10:
        return {"anomaly": False}

    X = extract_features(events)

    model.fit(X)
    predictions = model.predict(X)

    # Last event
    if predictions[-1] == -1:
        return {
            "anomaly": True,
            "reason": "Abnormal behavioral pattern detected"
        }

    return {"anomaly": False}
