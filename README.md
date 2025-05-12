# IAM Risk Analyzer

A lightweight IAM policy risk scoring tool with **two modes**:

* **Offline**: Analyze a local JSON policy file
* **Live**: Pull all customer‑managed IAM policies from the current AWS account and score them

## Features
* Simple rule engine (see `iam_analyzer/rules.py`)
* Color‑coded CLI output
* Tiny Flask UI for quick uploads or on‑demand AWS audit
* Zero external storage – results live in memory
* Secure upload handling (filename sanitization, JSON validation)

## Quick start – CLI

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# analyze a local file
python -m iam_analyzer.cli file example_policy.json

# analyze live account (uses default AWS creds)
python -m iam_analyzer.cli live
```

## Quick start – Flask UI

```bash
export SECRET_KEY=$(openssl rand -hex 16)
export AWS_PROFILE=myprofile   # or use env vars AWS_ACCESS_KEY_ID ...

FLASK_APP=iam_analyzer.app:create_app flask run
```

Browse to <http://127.0.0.1:5000>, upload a JSON policy or select Live Audit.

## Security considerations
* **No secrets in repo** – AWS creds supplied via env/CLI as usual.
* **CSRF‑safe** – UI only uses POST for uploads.
* **Upload path sanitized** – `secure_filename()` + temp dir.
* **Rate‑limit recommended** – add `Flask-Limiter` if exposing publicly.

## Extending rules

Edit `iam_analyzer/rules.py` and append new functions that accept a policy dict and return a list of `(description, score)` tuples, then add them to `RULE_FUNCS`.

Happy auditing! ✨
