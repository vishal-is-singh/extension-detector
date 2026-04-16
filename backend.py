from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import joblib
import os
import re
import math
import json
import zipfile
import shutil
import tempfile

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("malicious_extension_model.pkl")

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
    (r'\beval\s*\(',             "eval() usage"),
    (r'unescape\s*\(',           "unescape() usage"),
    (r'document\.cookie',        "Cookie access"),
    (r'XMLHttpRequest',          "Network request (XHR)"),
    (r'fetch\s*\(',              "fetch() call"),
    (r'atob\s*\(',               "Base64 decode"),
    (r'btoa\s*\(',               "Base64 encode"),
    (r'localStorage',            "localStorage access"),
    (r'chrome\.tabs',            "Tabs API access"),
    (r'chrome\.cookies',         "Cookies API access"),
    (r'chrome\.webRequest',      "WebRequest API access"),
    (r'chrome\.history',         "History API access"),
    (r'WebSocket\s*\(',          "WebSocket usage"),
    (r'new\s+Function\s*\(',     "Dynamic function creation"),
    (r'window\.location',        "Location manipulation"),
]

def entropy(text):
    if not text:
        return 0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((v/length) * math.log2(v/length) for v in freq.values())

def extract_features(extension_path):
    features = np.zeros(77)
    manifest_data = {}
    all_js_code = ""
    js_files_found = []
    warnings = []
    suspicious_patterns_found = []

    manifest_path = os.path.join(extension_path, "manifest.json")
    if not os.path.exists(manifest_path):
        for root, dirs, files in os.walk(extension_path):
            if "manifest.json" in files:
                manifest_path = os.path.join(root, "manifest.json")
                break

    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                manifest_data = json.load(f)
        except Exception as e:
            warnings.append(f"Could not read manifest.json: {e}")
    else:
        warnings.append("No manifest.json found")

    permissions = manifest_data.get("permissions", [])
    host_permissions = manifest_data.get("host_permissions", [])
    all_permissions = permissions + host_permissions
    dangerous_found = [p for p in all_permissions if p in DANGEROUS_PERMISSIONS]

    features[0] = len(all_permissions)
    features[1] = len(dangerous_found)
    features[2] = 1 if "<all_urls>" in all_permissions else 0
    features[3] = 1 if any("http" in p for p in all_permissions) else 0
    features[4] = 1 if "cookies" in all_permissions else 0
    features[5] = 1 if "tabs" in all_permissions else 0
    features[6] = 1 if "webRequest" in all_permissions else 0
    features[7] = 1 if "history" in all_permissions else 0
    features[8] = 1 if "nativeMessaging" in all_permissions else 0
    features[9] = 1 if "debugger" in all_permissions else 0
    features[10] = manifest_data.get("manifest_version", 0)
    features[11] = 1 if "content_scripts" in manifest_data else 0
    features[12] = 1 if "background" in manifest_data else 0
    features[13] = 1 if "web_accessible_resources" in manifest_data else 0
    features[14] = 1 if "externally_connectable" in manifest_data else 0
    features[15] = 1 if "update_url" in manifest_data else 0
    features[16] = len(str(manifest_data.get("description", "")))

    for root, dirs, files in os.walk(extension_path):
        for fname in files:
            if fname.endswith('.js'):
                fpath = os.path.join(root, fname)
                js_files_found.append(fname)
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
        for i, (pattern, label) in enumerate(SUSPICIOUS_JS_PATTERNS):
            count = len(re.findall(pattern, all_js_code))
            if 20 + i + 1 < 77:
                features[20 + i + 1] = count
            if count > 0:
                suspicious_patterns_found.append({"pattern": label, "count": count})
        features[50] = len(re.findall(r'[a-zA-Z0-9+/]{50,}={0,2}', all_js_code))
        features[51] = len(re.findall(r'\\x[0-9a-fA-F]{2}', all_js_code))
        features[52] = len(re.findall(r'\\u[0-9a-fA-F]{4}', all_js_code))
        features[54] = len(re.findall(r'https?://[^\s\'"]+', all_js_code))

    return features, warnings, dangerous_found, js_files_found, suspicious_patterns_found

def run_scan(extension_path, extension_name):
    features, warnings, dangerous_perms, js_files, suspicious_patterns = extract_features(extension_path)
    features_padded = np.zeros((1, 78))
    features_padded[0, 1:len(features)+1] = features[:77]
    prediction = int(model.predict(features_padded)[0])
    proba = model.predict_proba(features_padded)[0]
    risk_score = int(proba[1] * 100)
    return {
        "verdict": "MALICIOUS" if prediction == 1 else "BENIGN",
        "risk_score": risk_score,
        "confidence_benign": round(float(proba[0]) * 100, 1),
        "confidence_malicious": round(float(proba[1]) * 100, 1),
        "js_files": js_files,
        "dangerous_permissions": dangerous_perms,
        "suspicious_patterns": suspicious_patterns,
        "warnings": warnings,
        "extension_name": extension_name,
    }

@app.post("/scan-zip")
async def scan_zip(file: UploadFile = File(...)):
    tmp_dir = tempfile.mkdtemp()
    try:
        zip_path = os.path.join(tmp_dir, file.filename)
        with open(zip_path, 'wb') as f:
            content = await file.read()
            f.write(content)
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(extract_dir)
        extension_name = file.filename.replace('.zip', '').replace('.crx', '')
        result = run_scan(extract_dir, extension_name)
        return result
    except zipfile.BadZipFile:
        return {"error": "Invalid zip file. Please upload a valid .zip or .crx extension file."}
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

@app.get("/")
def root():
    return {"status": "Extension Detector API is running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)