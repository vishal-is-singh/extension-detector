# ============================================
# AI-Based Malicious Extension Detector
# Step 2: Scan a Real Extension Folder
# ============================================

import os
import json
import math
import re
import numpy as np
import joblib

# ── LOAD YOUR TRAINED MODEL ───────────────────────────────────
print("Loading trained model...")
if not os.path.exists("malicious_extension_model.pkl"):
    print("ERROR: malicious_extension_model.pkl not found!")
    print("Run train_model.py first.")
    exit()

model = joblib.load("malicious_extension_model.pkl")
print("Model loaded!\n")

# ── DANGEROUS PERMISSION LIST ─────────────────────────────────
DANGEROUS_PERMISSIONS = [
    "tabs", "cookies", "webRequest", "webRequestBlocking",
    "history", "bookmarks", "downloads", "management",
    "nativeMessaging", "clipboardRead", "clipboardWrite",
    "geolocation", "notifications", "storage", "identity",
    "debugger", "proxy", "privacy", "contentSettings",
    "browsingData", "declarativeNetRequest", "scripting",
    "<all_urls>", "http://*/*", "https://*/*"
]

SUSPICIOUS_JS_PATTERNS = [
    (r'\beval\s*\(',           "eval() usage"),
    (r'unescape\s*\(',         "unescape() usage"),
    (r'document\.cookie',      "cookie access"),
    (r'XMLHttpRequest',        "network request"),
    (r'fetch\s*\(',            "fetch() call"),
    (r'atob\s*\(',             "base64 decode"),
    (r'btoa\s*\(',             "base64 encode"),
    (r'localStorage',          "localStorage access"),
    (r'sessionStorage',        "sessionStorage access"),
    (r'window\.location',      "location manipulation"),
    (r'document\.write\s*\(',  "document.write usage"),
    (r'innerHTML\s*=',         "innerHTML manipulation"),
    (r'chrome\.tabs',          "tabs API access"),
    (r'chrome\.cookies',       "cookies API access"),
    (r'chrome\.webRequest',    "webRequest API access"),
    (r'chrome\.history',       "history API access"),
    (r'WebSocket\s*\(',        "WebSocket usage"),
    (r'new\s+Function\s*\(',   "dynamic Function creation"),
    (r'setTimeout\s*\(\s*["\']',"string-based setTimeout"),
    (r'setInterval\s*\(\s*["\']',"string-based setInterval"),
]

# ── HELPER: Shannon Entropy ────────────────────────────────────
def entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((v/length) * math.log2(v/length) for v in freq.values())

# ── FEATURE EXTRACTOR (matches training dataset: 77 features) ─
def extract_features(extension_path):
    features = np.zeros(77)
    manifest_data = {}
    all_js_code = ""
    js_files_found = []
    warnings = []

    # ── Read manifest.json ────────────────────────────────────
    manifest_path = os.path.join(extension_path, "manifest.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                manifest_data = json.load(f)
        except Exception as e:
            warnings.append(f"Could not read manifest.json: {e}")
    else:
        warnings.append("No manifest.json found!")

    # ── Extract permissions ────────────────────────────────────
    permissions = manifest_data.get("permissions", [])
    host_permissions = manifest_data.get("host_permissions", [])
    all_permissions = permissions + host_permissions

    dangerous_count = sum(1 for p in all_permissions if p in DANGEROUS_PERMISSIONS)
    features[0] = len(all_permissions)
    features[1] = dangerous_count
    features[2] = 1 if "<all_urls>" in all_permissions else 0
    features[3] = 1 if any("http" in p for p in all_permissions) else 0
    features[4] = 1 if "cookies" in all_permissions else 0
    features[5] = 1 if "tabs" in all_permissions else 0
    features[6] = 1 if "webRequest" in all_permissions else 0
    features[7] = 1 if "history" in all_permissions else 0
    features[8] = 1 if "nativeMessaging" in all_permissions else 0
    features[9] = 1 if "debugger" in all_permissions else 0

    # Manifest version and basic info
    features[10] = manifest_data.get("manifest_version", 0)
    features[11] = 1 if "content_scripts" in manifest_data else 0
    features[12] = 1 if "background" in manifest_data else 0
    features[13] = 1 if "web_accessible_resources" in manifest_data else 0
    features[14] = 1 if "externally_connectable" in manifest_data else 0
    features[15] = 1 if "update_url" in manifest_data else 0
    features[16] = len(str(manifest_data.get("description", "")))

    # ── Scan all JS files ─────────────────────────────────────
    for root, dirs, files in os.walk(extension_path):
        for fname in files:
            if fname.endswith('.js'):
                fpath = os.path.join(root, fname)
                js_files_found.append(fpath)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                        all_js_code += f.read() + "\n"
                except Exception:
                    pass

    features[17] = len(js_files_found)

    if all_js_code:
        features[18] = len(all_js_code)
        features[19] = entropy(all_js_code)
        features[20] = all_js_code.count('\n')

        # Suspicious pattern counts
        for i, (pattern, _) in enumerate(SUSPICIOUS_JS_PATTERNS):
            if 20 + i + 1 < 77:
                features[20 + i + 1] = len(re.findall(pattern, all_js_code))

        # Obfuscation signals
        features[50] = len(re.findall(r'[a-zA-Z0-9+/]{50,}={0,2}', all_js_code))  # base64 strings
        features[51] = len(re.findall(r'\\x[0-9a-fA-F]{2}', all_js_code))          # hex escapes
        features[52] = len(re.findall(r'\\u[0-9a-fA-F]{4}', all_js_code))          # unicode escapes
        features[53] = 1 if len(all_js_code) > 0 and (
            max(len(line) for line in all_js_code.split('\n') if line) > 5000
        ) else 0  # minified/obfuscated long lines
        features[54] = len(re.findall(r'https?://[^\s\'"]+', all_js_code))         # URLs in code
        features[55] = len(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', all_js_code)) # IP addresses

    return features, warnings, all_permissions, js_files_found

# ── MAIN SCANNER ──────────────────────────────────────────────
def scan_extension(extension_path):
    print(f"{'='*55}")
    print(f" SCANNING: {os.path.basename(extension_path)}")
    print(f"{'='*55}")

    if not os.path.isdir(extension_path):
        print("ERROR: Path is not a folder. Give the full path to the extension folder.")
        return

    features, warnings, permissions, js_files = extract_features(extension_path)

    # Predict
    features_input = features[:77].reshape(1, -1)

    # Pad to match training shape (78 features due to index 0)
    features_padded = np.zeros((1, 78))
    features_padded[0, 1:len(features)+1] = features[:77]

    prediction = model.predict(features_padded)[0]
    proba = model.predict_proba(features_padded)[0]

    risk_score = int(proba[1] * 100)

    # ── Print Report ──────────────────────────────────────────
    print(f"\n📁 Extension Path : {extension_path}")
    print(f"📄 JS Files Found : {len(js_files)}")
    print(f"🔑 Permissions    : {len(permissions)}")

    print(f"\n{'─'*40}")
    print(f" 🎯 RISK SCORE : {risk_score}/100")

    if prediction == 1:
        print(f" ❌ VERDICT    : MALICIOUS")
    else:
        print(f" ✅ VERDICT    : BENIGN (SAFE)")

    print(f" 📊 Confidence : Benign={proba[0]*100:.1f}%  Malicious={proba[1]*100:.1f}%")
    print(f"{'─'*40}")

    # Permissions report
    dangerous_found = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    if dangerous_found:
        print(f"\n⚠️  DANGEROUS PERMISSIONS DETECTED ({len(dangerous_found)}):")
        for p in dangerous_found:
            print(f"   → {p}")
    else:
        print(f"\n✅ No dangerous permissions found.")

    if warnings:
        print(f"\n⚠️  WARNINGS:")
        for w in warnings:
            print(f"   → {w}")

    print(f"\n{'='*55}\n")
    return risk_score, prediction

# ── RUN ───────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n🔍 AI-Based Malicious Browser Extension Detector")
    print("─" * 55)
    path = input("Enter the full path to the extension folder:\n> ").strip().strip('"')
    scan_extension(path)