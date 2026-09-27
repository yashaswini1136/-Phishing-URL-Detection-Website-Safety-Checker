import csv
import json
import os
import sys
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# Ensure backend directory is in python path
current_dir = Path(__file__).resolve().parent
if str(current_dir) not in sys.path:
    sys.path.insert(0, str(current_dir))

from config import DATASET_PATH, MODEL_PATH, SCALER_PATH
from detection.feature_extractor import extract_all_features, normalize_url
from detection.classifier import FEATURE_NAMES, extract_feature_vector


def train(dataset_file: str = DATASET_PATH, model_output_file: str = MODEL_PATH):
    print("=" * 65)
    print("PHISHING URL DETECTION - MACHINE LEARNING TRAINING PIPELINE")
    print("=" * 65)
    print(f"[1/5] Loading labeled dataset: {dataset_file}")

    if not os.path.exists(dataset_file):
        print(f"Error: Dataset file '{dataset_file}' not found.")
        sys.exit(1)

    urls = []
    labels = []

    with open(dataset_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            raw_url = row.get("url", "").strip()
            raw_label = row.get("label", "").strip()
            if raw_url and raw_label in ("0", "1"):
                urls.append(raw_url)
                labels.append(int(raw_label))

    legit_count = labels.count(0)
    phish_count = labels.count(1)
    print(f"      Total samples: {len(urls)} ({legit_count} Legitimate, {phish_count} Phishing).")
    print("      Class Balance: {:.1f}% Legitimate / {:.1f}% Phishing".format(
        legit_count / len(urls) * 100, phish_count / len(urls) * 100
    ))

    print("\n[2/5] Extracting multi-layer features across dataset...")
    X = []
    y = []

    for raw_url, label in zip(urls, labels):
        orig, norm, valid, _ = normalize_url(raw_url)
        target_url = norm if valid else raw_url
        features = extract_all_features(target_url, original_url=orig)
        vec = extract_feature_vector(features)
        X.append(vec)
        y.append(label)

    print(f"      Extracted {len(FEATURE_NAMES)} numerical features per URL.")

    print("\n[3/5] Performing stratified train/test split (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"      Training size: {len(X_train)} | Test size: {len(X_test)}")

    print("\n[4/5] Training Random Forest Classifier (n_estimators=100, class_weight='balanced')...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train_scaled, y_train)

    # 5. Evaluate on Holdout Test Split
    y_pred = clf.predict(X_test_scaled)
    y_probs = clf.predict_proba(X_test_scaled)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    roc_auc = roc_auc_score(y_test, y_probs)
    cm = confusion_matrix(y_test, y_pred)

    print("\n[5/5] Holdout Test Split Evaluation Metrics:")
    print("-" * 55)
    print(f"  Accuracy       : {acc * 100:.2f}%")
    print(f"  Precision      : {prec * 100:.2f}% (Phishing class)")
    print(f"  Recall         : {rec * 100:.2f}% (Phishing class)")
    print(f"  F1 Score       : {f1 * 100:.2f}%")
    print(f"  ROC-AUC Score  : {roc_auc:.4f}")
    print("-" * 55)
    print("\nConfusion Matrix [TN, FP / FN, TP]:")
    print(f"  True Negatives (Legitimate): {cm[0][0]} | False Positives: {cm[0][1]}")
    print(f"  False Negatives (Missed)   : {cm[1][0]} | True Positives (Phishing): {cm[1][1]}")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (0)", "Phishing (1)"]))

    # Save model artifacts
    output_dir = Path(model_output_file).parent
    output_dir.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": clf,
        "scaler": scaler,
        "feature_names": FEATURE_NAMES,
        "metadata": {
            "algorithm": "RandomForestClassifier",
            "samples_trained": len(X_train),
            "test_accuracy": round(float(acc), 4),
            "test_precision": round(float(prec), 4),
            "test_recall": round(float(rec), 4),
            "test_f1": round(float(f1), 4),
            "test_roc_auc": round(float(roc_auc), 4),
            "dataset_note": "Calibrated dataset balancing legitimate authentication URLs and phishing patterns."
        }
    }

    joblib.dump(bundle, model_output_file)
    print(f"\nTrained model artifact successfully saved to: {model_output_file}")
    print("=" * 65)
    return bundle


if __name__ == "__main__":
    train()
