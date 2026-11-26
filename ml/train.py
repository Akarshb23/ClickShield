"""Fit a regularized binary logistic regression using Python's standard library."""
import csv
import json
import math
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NAMES = dict(F="FAKE_CAPTCHA", I="SUSPICIOUS_INSTRUCTION", C="CLIPBOARD_MANIPULATION",
             E="EXECUTION_INSTRUCTION", D="SUSPICIOUS_DOMAIN", B="DOMAIN_IMPERSONATION")
terms = list(combinations(NAMES, 1)) + list(combinations(NAMES, 2))
with (ROOT / "ml/scenarios.csv").open() as source:
    rows = list(csv.DictReader(source))

seen = set()
train, test = [], []
for row in rows:
    signals = frozenset(row["signals"].split())
    if signals in seen or not signals <= NAMES.keys():
        raise ValueError(f"Duplicate or invalid input in {row['case']}")
    seen.add(signals)
    features = [1] + [int(signals.issuperset(term)) for term in terms]
    target = {"train": train, "test": test}[row["split"]]
    target.append((features, int(row["label"])))

weights = [0.0] * (1 + len(terms))


def predict(features):
    return 1 / (1 + math.exp(-sum(x*w for x, w in zip(features, weights))))


for _ in range(3000):
    gradient = [0.0] * len(weights)
    for features, label in train:
        error = predict(features) - label
        for i, value in enumerate(features):
            gradient[i] += error * value
    for i in range(len(weights)):
        penalty = 0.002 * weights[i] if i else 0
        weights[i] -= 0.5 * (gradient[i] / len(train) + penalty)

artifact = {
    "intercept": round(weights[0], 9),
    "terms": [
        {"signals": [NAMES[key] for key in term], "coefficient": round(weight, 9)}
        for term, weight in zip(terms, weights[1:])
    ]
}
(ROOT / "src/engine/model.json").write_text(json.dumps(artifact, indent=2) + "\n")
counts = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}
for features, label in test:
    positive = math.floor(predict(features) * 100 + 0.5) >= 60
    counts[("T" if positive == bool(label) else "F") + ("P" if positive else "N")] += 1
print(f"{len(train)} training cases, {len(test)} held-out cases at warning threshold:", counts)
