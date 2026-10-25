#!/usr/bin/env python3
"""
ssh_threat_detector.py
======================
Train, evaluate and export an ML detector for SSH brute-force activity, using the
per-IP window features engineered by `ssh_bruteforce_features.py`.

Models (both wrapped in sklearn Pipelines with StandardScaler):
  * Isolation Forest   - unsupervised; never sees labels.
  * Random Forest      - supervised; trained on labeled (synthetic) attack data.

Risk score (0-100 %):
  * IF risk     = calibrated, rescaled isolation score.
  * RF risk     = expected risk over the 3 class probabilities.
  * Hybrid risk = 0.7 * RF + 0.3 * IF   (final score used for the verdict)

Classification from risk:
  < 50 %        -> "Normal"
  50 % - 79.99% -> "Anomalous Login"
  >= 80 %       -> "Brute-Force Attack"

Usage
-----
    python ssh_threat_detector.py                    # train on synthetic data, demo on sample log
    python ssh_threat_detector.py --log auth.log     # ...then score a real auth.log
    python ssh_threat_detector.py --n-samples 20000 --seed 7

Loading the exported model elsewhere
------------------------------------
    import joblib
    from ssh_threat_detector import score_features
    bundle = joblib.load("ssh_detector_model.joblib")
    scored = score_features(bundle, features_df)   # features_df has the 6 feature columns

The .joblib file is a plain dict of scikit-learn objects + metadata, so it loads
without needing any custom class to be importable.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
FEATURE_COLUMNS = [
    "failed_attempts_count",
    "failure_to_success_ratio",
    "unique_usernames_attempted",
    "request_rate_per_min",
    "off_peak_hour_flag",
    "root_attempt_flag",
]
CLASS_NAMES = ["Normal", "Anomalous Login", "Brute-Force Attack"]  # label 0, 1, 2

ANOMALOUS_THRESHOLD = 50.0  # risk >= 50  -> Anomalous Login
ATTACK_THRESHOLD = 80.0     # risk >= 80  -> Brute-Force Attack

# Risk "anchor" per class used to turn RF class probabilities into one 0-100 score.
# A window the RF is 100 % sure is "Anomalous" lands at 65 (mid anomalous band).
RF_CLASS_RISK = np.array([0.0, 65.0, 100.0])

HYBRID_WEIGHTS = {"rf": 0.7, "if": 0.3}

# Isolation Forest calibration: map raw score percentiles of the training data to
# 0 % (typical traffic) .. 100 % (most isolated traffic).
IF_LOW_PCT, IF_HIGH_PCT = 50, 99

MODEL_PATH = "ssh_detector_model.joblib"


# --------------------------------------------------------------------------- #
# 1. Synthetic labeled data (same 6 features the parser produces)
# --------------------------------------------------------------------------- #
def _finish(failed, success, unique, rate, off_peak, root, label) -> pd.DataFrame:
    failed = np.asarray(failed, dtype=int)
    success = np.asarray(success, dtype=int)
    # A window always contains at least one authentication outcome.
    success = np.where(failed + success == 0, 1, success)
    unique = np.clip(unique, 1, np.maximum(1, failed + success)).astype(int)
    return pd.DataFrame(
        {
            "failed_attempts_count": failed,
            "failure_to_success_ratio": failed / (success + 1),
            "unique_usernames_attempted": unique,
            "request_rate_per_min": np.round(rate, 4),
            "off_peak_hour_flag": off_peak.astype(int),
            "root_attempt_flag": root.astype(int),
            "label": label,
        }
    )


def generate_synthetic_dataset(n_samples: int = 6000, seed: int = 42) -> pd.DataFrame:
    """
    Simulate labeled per-IP windows.
        0 Normal             - occasional typo, successful logins, daytime
        1 Anomalous Login    - repeated failures / odd hours, but not a clear attack
        2 Brute-Force Attack - dictionary attacks, single-account (root) hammering,
                               and a slice of "low-and-slow" attacks that overlap class 1
    The classes deliberately overlap so the task is not trivially separable.
    """
    rng = np.random.default_rng(seed)
    counts = rng.multinomial(n_samples, [0.70, 0.15, 0.15])
    n0, n1, n2 = counts

    # --- Normal ---
    normal = _finish(
        failed=rng.poisson(0.5, n0),
        success=rng.poisson(1.0, n0),
        unique=1 + (rng.random(n0) < 0.06),
        rate=np.clip(rng.lognormal(np.log(1.0), 0.5, n0), 0.1, 4),
        off_peak=rng.random(n0) < 0.08,
        root=rng.random(n0) < 0.02,
        label=0,
    )

    # --- Anomalous login ---
    anomalous = _finish(
        failed=3 + rng.poisson(2.5, n1),
        success=rng.poisson(0.6, n1),
        unique=1 + rng.poisson(1.0, n1),
        rate=np.clip(rng.lognormal(np.log(2.5), 0.5, n1), 0.3, 8),
        off_peak=rng.random(n1) < 0.35,
        root=rng.random(n1) < 0.30,
        label=1,
    )

    # --- Brute-force attack ---
    dictionary = rng.random(n2) < 0.60  # many usernames vs. one account hammered
    slow = rng.random(n2) < 0.15        # low-and-slow variant
    # Heavy-tailed volume: many attacks are bursts of ~6-15 failures, some are floods.
    flood = 6 + np.round(rng.lognormal(np.log(12), 0.8, n2)).astype(int)
    failed = np.where(slow, 8 + rng.poisson(6, n2), flood)
    rate = np.where(
        slow,
        np.clip(rng.lognormal(np.log(2.5), 0.4, n2), 1.0, 6),
        np.clip(rng.lognormal(np.log(12), 0.6, n2), 3, 60),
    )
    unique = np.where(dictionary, 3 + rng.poisson(7, n2), 1 + rng.poisson(0.4, n2))
    attack = _finish(
        failed=failed,
        success=(rng.random(n2) < 0.04).astype(int),
        unique=unique,
        rate=rate,
        off_peak=rng.random(n2) < 0.55,
        root=rng.random(n2) < np.where(dictionary, 0.5, 0.9),
        label=2,
    )

    df = pd.concat([normal, anomalous, attack], ignore_index=True)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


# --------------------------------------------------------------------------- #
# 2. Pipelines
# --------------------------------------------------------------------------- #
def build_rf_pipeline(seed: int = 42) -> Pipeline:
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "clf",
                RandomForestClassifier(
                    n_estimators=300,
                    min_samples_leaf=2,
                    class_weight="balanced",
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )


def build_if_pipeline(seed: int = 42) -> Pipeline:
    return Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "iforest",
                IsolationForest(
                    n_estimators=300,
                    max_samples="auto",
                    contamination="auto",
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )


# --------------------------------------------------------------------------- #
# 3. Risk scoring
# --------------------------------------------------------------------------- #
def fit_if_calibration(if_pipe: Pipeline, X_train: pd.DataFrame) -> dict:
    """Learn the raw-score range (from unlabeled training data) used to scale IF risk."""
    raw = -if_pipe.score_samples(X_train)  # higher = more anomalous
    lo, hi = np.percentile(raw, [IF_LOW_PCT, IF_HIGH_PCT])
    return {"lo": float(lo), "hi": float(hi)}


def if_risk(if_pipe: Pipeline, X: pd.DataFrame, calib: dict) -> np.ndarray:
    raw = -if_pipe.score_samples(X)
    return np.clip((raw - calib["lo"]) / (calib["hi"] - calib["lo"]), 0, 1) * 100


def rf_risk(rf_pipe: Pipeline, X: pd.DataFrame) -> np.ndarray:
    proba = rf_pipe.predict_proba(X)  # columns follow classes_ == [0, 1, 2]
    return proba @ RF_CLASS_RISK


def hybrid_risk(rf: np.ndarray, iso: np.ndarray, weights: dict = HYBRID_WEIGHTS) -> np.ndarray:
    return weights["rf"] * rf + weights["if"] * iso


def risk_to_label(risk: np.ndarray) -> np.ndarray:
    """0 Normal / 1 Anomalous Login / 2 Brute-Force Attack from 0-100 risk."""
    return np.select([risk >= ATTACK_THRESHOLD, risk >= ANOMALOUS_THRESHOLD], [2, 1], default=0)


def risk_to_name(risk: np.ndarray) -> np.ndarray:
    return np.array(CLASS_NAMES)[risk_to_label(risk)]


# --------------------------------------------------------------------------- #
# 4. Evaluation
# --------------------------------------------------------------------------- #
def evaluate(name: str, y_true: np.ndarray, risk: np.ndarray) -> dict:
    y_pred = risk_to_label(risk)
    p, r, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    print(f"\n{'=' * 72}\n{name}\n{'=' * 72}")
    print(
        classification_report(
            y_true, y_pred, labels=[0, 1, 2], target_names=CLASS_NAMES,
            digits=3, zero_division=0,
        )
    )
    cm = pd.DataFrame(
        confusion_matrix(y_true, y_pred, labels=[0, 1, 2]),
        index=[f"true: {c}" for c in CLASS_NAMES],
        columns=[f"pred: {c}" for c in CLASS_NAMES],
    )
    print("Confusion matrix (rows = actual, columns = predicted):")
    print(cm.to_string())
    return {"model": name, "precision_macro": p, "recall_macro": r, "f1_macro": f1}


# --------------------------------------------------------------------------- #
# 5. Training, export, inference
# --------------------------------------------------------------------------- #
def train_and_evaluate(n_samples: int = 6000, seed: int = 42, model_path: str = MODEL_PATH) -> dict:
    data = generate_synthetic_dataset(n_samples, seed)
    X, y = data[FEATURE_COLUMNS], data["label"].to_numpy()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.30, stratify=y, random_state=seed
    )
    print(f"Synthetic dataset: {len(data)} windows | train={len(X_train)} test={len(X_test)}")
    print("Class balance:", dict(zip(CLASS_NAMES, np.bincount(y))))

    # --- Random Forest (supervised) ---
    rf_pipe = build_rf_pipeline(seed)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    cv_f1 = cross_val_score(rf_pipe, X_train, y_train, cv=cv, scoring="f1_macro", n_jobs=-1)
    print(f"RF 5-fold CV macro-F1 (train only): {cv_f1.mean():.3f} +/- {cv_f1.std():.3f}")
    rf_pipe.fit(X_train, y_train)

    # --- Isolation Forest (unsupervised: fit on features only, labels never used) ---
    if_pipe = build_if_pipeline(seed).fit(X_train)
    calib = fit_if_calibration(if_pipe, X_train)

    # --- Risk scores on the held-out test set ---
    r_rf = rf_risk(rf_pipe, X_test)
    r_if = if_risk(if_pipe, X_test, calib)
    r_hy = hybrid_risk(r_rf, r_if)

    results = [
        evaluate("Isolation Forest (unsupervised)", y_test, r_if),
        evaluate("Random Forest (supervised)", y_test, r_rf),
        evaluate("HYBRID 0.7*RF + 0.3*IF (final detector)", y_test, r_hy),
    ]
    print("\nSummary (macro average on test set)")
    print(pd.DataFrame(results).set_index("model").round(3).to_string())

    importances = pd.Series(
        rf_pipe.named_steps["clf"].feature_importances_, index=FEATURE_COLUMNS
    ).sort_values(ascending=False)
    print("\nRandom Forest feature importances:")
    print(importances.round(3).to_string())

    # --- Export: plain dict of sklearn objects + metadata ---
    bundle = {
        "rf_pipeline": rf_pipe,
        "if_pipeline": if_pipe,
        "if_calibration": calib,
        "feature_columns": FEATURE_COLUMNS,
        "class_names": CLASS_NAMES,
        "rf_class_risk": RF_CLASS_RISK.tolist(),
        "hybrid_weights": HYBRID_WEIGHTS,
        "thresholds": {"anomalous": ANOMALOUS_THRESHOLD, "attack": ATTACK_THRESHOLD},
    }
    joblib.dump(bundle, model_path, compress=3)
    print(f"\nModel exported -> {Path(model_path).resolve()}")
    return bundle


def score_features(bundle: dict, features: pd.DataFrame) -> pd.DataFrame:
    """Score a feature DataFrame (from build_features) with a loaded model bundle."""
    X = features[bundle["feature_columns"]].astype(float)
    rf = bundle["rf_pipeline"].predict_proba(X) @ np.asarray(bundle["rf_class_risk"])
    calib = bundle["if_calibration"]
    raw = -bundle["if_pipeline"].score_samples(X)
    iso = np.clip((raw - calib["lo"]) / (calib["hi"] - calib["lo"]), 0, 1) * 100
    w = bundle["hybrid_weights"]
    risk = w["rf"] * rf + w["if"] * iso
    t = bundle["thresholds"]
    labels = np.select([risk >= t["attack"], risk >= t["anomalous"]], [2, 1], default=0)
    return features.assign(
        risk_if=np.round(iso, 1),
        risk_rf=np.round(rf, 1),
        risk_score=np.round(risk, 1),
        classification=np.array(bundle["class_names"])[labels],
    )


def demo_on_log(bundle: dict, log_path: str | None) -> None:
    """Score a real auth.log (or the embedded 25-line sample) with the saved model."""
    try:
        from ssh_bruteforce_features import (
            SAMPLE_AUTH_LOG, build_features, load_auth_log, parse_auth_log,
        )
    except ImportError:
        print("\n(ssh_bruteforce_features.py not found next to this script - skipping log demo.)")
        return

    events = load_auth_log(log_path) if log_path else parse_auth_log(SAMPLE_AUTH_LOG, 2026)
    feats = build_features(events, window_minutes=5)
    scored = score_features(bundle, feats)

    cols = ["source_ip", "window_start", *FEATURE_COLUMNS, "risk_if", "risk_rf",
            "risk_score", "classification"]
    pd.set_option("display.width", 250)
    pd.set_option("display.max_columns", None)
    src = log_path or "embedded sample auth.log"
    print(f"\n{'=' * 72}\nScoring {src} with the saved model\n{'=' * 72}")
    print(scored[cols].to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser(description="Train/evaluate the SSH threat detector")
    ap.add_argument("--n-samples", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--model-out", default=MODEL_PATH)
    ap.add_argument("--log", help="optional auth.log to score after training")
    args = ap.parse_args()

    train_and_evaluate(args.n_samples, args.seed, args.model_out)
    bundle = joblib.load(args.model_out)  # prove the exported file round-trips
    demo_on_log(bundle, args.log)


if __name__ == "__main__":
    main()
