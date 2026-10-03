# SafeNet

**An Edge-AI Driven Browser Extension for Real-Time Phishing and Zero-Day Web Threat Mitigation**

SafeNet is a client-side, privacy-preserving browser extension that detects phishing and zero-day malicious URLs in real time — without relying on static blocklists or sending browsing data to any external server. It uses a machine learning classifier trained on lexical and statistical URL features, running entirely on-device via a Chrome Manifest V3 extension.

## Why SafeNet

Traditional phishing protection (Google Safe Browsing, PhishTank blocklists) is reactive — a malicious domain has to be seen, reported, and indexed before it's blocked. This leaves a "zero-day window" where brand-new phishing sites go undetected. SafeNet instead analyzes the *structure* of a URL itself (entropy, subdomain depth, suspicious keywords, brand impersonation patterns, etc.) so it can flag suspicious sites it has never seen before, entirely offline and in milliseconds.

## Project Status

🚧 In active development — Zeroth Review stage.

* \[x] Dataset collected (PhishTank verified phishing URLs + Tranco top legitimate domains)
* \[x] Lexical/statistical feature engineering pipeline
* \[x] Baseline Random Forest model trained and evaluated (F1 ≈ 0.93)
* \[ ] Feature refinement (brand impersonation, keyword detection)
* \[ ] Chrome Manifest V3 extension shell
* \[ ] Model → JavaScript translation
* \[ ] Integration + latency benchmarking
* \[ ] Testing against live phishing feeds

## Repository Structure

```
SafeNet/
├── ml/
│   ├── feature\\\_engineering.py   # Extracts lexical/statistical features from a URL
│   ├── build\\\_real\\\_dataset.py    # Combines PhishTank + Tranco into a labeled dataset
│   ├── enrich\\\_legit\\\_urls.py     # Adds realistic paths to legitimate URLs (avoids shortcut bias)
│   ├── train\\\_model.py           # Trains \\\& evaluates the Random Forest classifier
│   └── safenet\\\_model.joblib     # Saved trained model
├── datasets/
│   ├── verified\\\_online.csv      # Raw PhishTank export (phishing URLs)
│   ├── tranco\\\_Q2X24.csv         # Raw Tranco top-sites list (legitimate domains)
│   └── real\\\_dataset\\\_enriched.csv # Final combined, labeled training dataset
└── README.md
```

## Tech Stack

|Layer|Tools|
|-|-|
|Data / ML|Python, pandas, scikit-learn|
|Feature Engineering|Custom lexical/entropy-based extraction|
|Extension|Chrome Manifest V3, JavaScript, chrome.webNavigation API|
|Model Deployment|Trained model logic hand-ported to JavaScript for local inference|

## Getting Started (ML pipeline)

```bash
pip install pandas scikit-learn joblib
cd ml
python train\\\_model.py
```

This loads `datasets/real\\\_dataset\\\_enriched.csv`, extracts features, trains the classifier, prints evaluation metrics, and saves the model to `safenet\\\_model.joblib`.

To use the trained model on a new URL:

```python
import joblib, pandas as pd
from feature\\\_engineering import extract\\\_features

model = joblib.load('safenet\\\_model.joblib')
features = pd.DataFrame(\\\[extract\\\_features("http://example-url-to-check.com")])
prediction = model.predict(features)   # 1 = phishing, 0 = legitimate
```

## Team

|Name|Role|
|-|-|
|Fakrul Mumina H - 23TD0759|Team Lead — ML Pipeline|
|Ragavi R - 23TD0779|Co-ordinator — Browser Extension|
|Kavitha M - 23TD0765|Documentation \& Literature Review|
|Yoga Priyankha S - 23TD0796|Testing \& Evaluation|

**Project Guide:** Mrs. A. Dharani - AP/CSE
**College:** RAAK College of Engineering and Technology

## References

Base papers and full project abstract available in the project report (see `/docs` — to be added).

