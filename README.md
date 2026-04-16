# 🛡️ Extension Detector — AI-Based Malicious Browser Extension Identifier

An AI-powered web app that analyzes browser extensions and predicts whether they are **safe or malicious** before installation — using a Machine Learning model trained on 6,726 real-world JavaScript malware samples with **99.93% accuracy**.

---

## 🎯 What It Does

- Upload any browser extension as a `.zip` or `.crx` file
- AI model scans the JavaScript code and manifest permissions
- Instantly shows:
  - ✅ / ❌ Verdict (Benign or Malicious)
  - 🎯 Risk Score (0–100)
  - ⚠️ Dangerous permissions detected
  - 🔎 Suspicious code patterns found
  - 📄 All JS files scanned

---

## 🧠 How It Works
User uploads .zip extension
↓
Backend extracts & scans files
↓
77 security features extracted
(permissions + JS patterns)
↓
Random Forest ML Model predicts
↓
Risk Score + Verdict shown

---

## 🗂️ Project Structure
extension-detector/
├── train_model.py          # Train the ML model
├── backend.py              # FastAPI backend server
├── scan_extension.py       # CLI scanner (optional)
├── frontend/               # Next.js frontend
│   └── app/
│       └── page.tsx        # Main UI page
└── README.md

---

## ⚙️ Requirements

Make sure you have these installed:

| Tool | Version | Download |
|---|---|---|
| Python | 3.8+ | https://python.org |
| Node.js | 18+ | https://nodejs.org |
| Git | Any | https://git-scm.com |

---

## 🚀 Setup — Step by Step

### Step 1 — Clone the Repository

Open Command Prompt and run:

```bash
git clone https://github.com/YOURUSERNAME/extension-detector.git
cd extension-detector
```

---

### Step 2 — Install Python Libraries

```bash
pip install scikit-learn numpy pandas matplotlib seaborn joblib fastapi uvicorn python-multipart
```

---

### Step 3 — Download the Dataset

👉 **[JS Malware Dataset — Mendeley](https://data.mendeley.com/datasets/3drdhrxjm7/1)**

- Click **Download All**
- You will get a file called `JS_DATASET.svm`
- Place it inside the `extension-detector` folder

---

### Step 4 — Train the ML Model

```bash
python train_model.py
```

Wait about 30 seconds. You will see:
Accuracy: 99.93%
✅ All done! Your AI model is ready.

This creates `malicious_extension_model.pkl` — your trained AI model.

> Two chart popups will appear. Close them to continue.

---

### Step 5 — Install Frontend Dependencies

```bash
cd frontend
npm install
cd ..
```

---

### Step 6 — Run the App

You need **two terminals open at the same time**.

**Terminal 1 — Start the backend:**
```bash
python backend.py
```

Wait until you see:
Uvicorn running on http://0.0.0.0:8000

**Terminal 2 — Start the frontend:**
```bash
cd frontend
npm run dev
```

Wait until you see:
Local: http://localhost:3000

---

### Step 7 — Open the App

Open your browser and go to:
http://localhost:3000

---

## 🧪 How to Test It

**Option A — From your Chrome extensions:**
1. Open File Explorer and go to:
C:\Users\YOUR_NAME\AppData\Local\Google\Chrome\User Data\Default\Extensions
2. Open any folder → open the version folder inside (e.g. `1.0.0_0`)
3. Go one level back → right click → **Send to → Compressed (zipped) folder**
4. Drag that `.zip` onto the website

**Option B — Download any extension:**
1. Download any Chrome extension as `.crx` or `.zip`
2. Drag it directly onto the website

---

## 📊 Model Details

| Property | Value |
|---|---|
| Algorithm | Random Forest |
| Training samples | 6,726 |
| Features | 77 JS + permission features |
| Accuracy | 99.93% |
| Dataset | Mendeley JS Malware Dataset |

---

## 🔮 Future Scope

- Real-time Chrome Web Store scanning
- Browser extension version (auto-scan on install)
- Sandbox runtime behavior analysis
- API for third-party integration

---

## 👨‍💻 Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js + Tailwind CSS |
| Backend | FastAPI (Python) |
| ML Model | Scikit-learn Random Forest |
| Dataset | Mendeley JS Malware Dataset |

---

## ⚠️ Important Notes

- The `.pkl` model file is not included in this repo
- You must run `train_model.py` once after cloning to generate it
- The dataset must be downloaded separately from Mendeley

---

## 📄 License

MIT License — free to use and modify.
