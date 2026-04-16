# ============================================
# AI-Based Malicious Extension Detector
# Step 1: Load Data + Train Model
# ============================================

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

# ── 1. LOAD DATASET (manual parser — handles corrupt/encoded files) ───────────
print("Loading dataset...")

svm_files = [f for f in os.listdir('.') if f.endswith('.svm')]
if not svm_files:
    print("ERROR: No .svm file found! Make sure JS_DATASET.svm is in this folder.")
    exit()

# Pick the original file, not cleaned_dataset.svm
svm_path = next((f for f in svm_files if 'cleaned' not in f), svm_files[0])
print(f"Reading: {svm_path}")

data_rows = []
labels = []
skipped = 0

with open(svm_path, 'rb') as f:
    for line_num, raw_line in enumerate(f, 1):
        try:
            # Decode, strip BOM and whitespace
            line = raw_line.decode('utf-8', errors='ignore').strip()
            line = line.replace('\ufeff', '').replace('\ufffd', '')

            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if not parts:
                continue

            # First token is the label
            label = float(parts[0])

            # Remaining tokens are index:value pairs
            features = {}
            for token in parts[1:]:
                token = token.strip()
                if ':' not in token:
                    continue
                idx_str, val_str = token.split(':', 1)
                idx_str = ''.join(c for c in idx_str if c.isdigit())
                val_str = ''.join(c for c in val_str if c in '0123456789.-e+')
                if idx_str and val_str:
                    features[int(idx_str)] = float(val_str)

            labels.append(label)
            data_rows.append(features)

        except Exception:
            skipped += 1
            continue

print(f"Parsed {len(data_rows)} valid samples. Skipped {skipped} bad lines.")

if len(data_rows) == 0:
    print("ERROR: No valid data found. Check your .svm file.")
    exit()

# Find max feature index to build matrix
max_idx = max(max(row.keys(), default=0) for row in data_rows)
print(f"Number of features: {max_idx}")

# Build dense matrix
X = np.zeros((len(data_rows), max_idx + 1), dtype=np.float32)
for i, row in enumerate(data_rows):
    for idx, val in row.items():
        if idx <= max_idx:
            X[i, idx] = val

y = np.array(labels)

# Normalize labels to 0 and 1
unique_labels = np.unique(y)
print(f"Labels found in dataset: {unique_labels}")
if set(unique_labels) != {0.0, 1.0}:
    # Remap: smallest = 0 (benign), largest = 1 (malicious)
    y = (y == unique_labels.max()).astype(float)
    print(f"Labels remapped → 0=Benign, 1=Malicious")

print(f"\nDataset ready!")
print(f"Total samples : {X.shape[0]}")
print(f"Total features: {X.shape[1]}")
print(f"Benign (0)    : {int(sum(y == 0))}")
print(f"Malicious (1) : {int(sum(y == 1))}")

# ── 2. SPLIT DATA ─────────────────────────────────────────────────────────────
print("\nSplitting into train/test sets (80/20)...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Training samples : {len(X_train)}")
print(f"Testing  samples : {len(X_test)}")

# ── 3. TRAIN MODEL ────────────────────────────────────────────────────────────
print("\nTraining Random Forest model... (takes ~30 seconds)")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)
print("Training complete!")

# ── 4. EVALUATE MODEL ─────────────────────────────────────────────────────────
print("\n========== MODEL RESULTS ==========")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Accuracy: {acc * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

# ── 5. CONFUSION MATRIX CHART ─────────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(7, 5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=["Benign", "Malicious"],
            yticklabels=["Benign", "Malicious"])
plt.title("Confusion Matrix — Malicious Extension Detector")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.show()
print("Saved: confusion_matrix.png")

# ── 6. FEATURE IMPORTANCE CHART ───────────────────────────────────────────────
importances = model.feature_importances_
top_n = 15
indices = np.argsort(importances)[::-1][:top_n]

plt.figure(figsize=(10, 6))
plt.bar(range(top_n), importances[indices], color='steelblue')
plt.xticks(range(top_n), [f"F{i}" for i in indices], rotation=45)
plt.title("Top 15 Most Important Features")
plt.ylabel("Importance Score")
plt.tight_layout()
plt.savefig("feature_importance.png")
plt.show()
print("Saved: feature_importance.png")

# ── 7. SAVE MODEL ─────────────────────────────────────────────────────────────
joblib.dump(model, "malicious_extension_model.pkl")
print("\nModel saved as: malicious_extension_model.pkl")
print("\n✅ All done! Your AI model is ready.")