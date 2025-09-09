# IAM Risk Analyzer

Practical IAM policy risk scoring with both CLI and a simple Flask UI.

- Offline: analyze local JSON policies
- Live: audit all customer-managed IAM policies in the current AWS account

## Features
- Rule engine with actionable checks (see `iam_analyzer/rules.py`)
- CLI text or JSON output, plus threshold-based exit codes for CI
- Flask UI for quick uploads or on-demand AWS audit
- In-memory uploads (no disk write), JSON validation, CSRF token
- No persistence; results live in memory only

## Install

Linux/macOS
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Windows (PowerShell)
```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## CLI usage

Analyze a local file
```bash
python -m iam_analyzer.cli file example_policy.json
```

Read from stdin and emit JSON (good for automation)
```bash
cat example_policy.json | python -m iam_analyzer.cli file - --format json
```

Fail CI if score >= 30
```bash
python -m iam_analyzer.cli file example_policy.json --threshold 30
```

Analyze live account (uses default AWS creds)
```bash
python -m iam_analyzer.cli live
```

Emit JSON for all policies and fail if any score >= 50
```bash
python -m iam_analyzer.cli live --format json --threshold 50
```

## Flask UI

Linux/macOS
```bash
export SECRET_KEY=$(python - <<<'import secrets;print(secrets.token_hex(16))')
FLASK_APP=iam_analyzer.app:create_app flask run
```

Windows (PowerShell)
```powershell
$env:SECRET_KEY = [guid]::NewGuid().ToString('N')
$env:FLASK_APP = 'iam_analyzer.app:create_app'
flask run
```

Open http://127.0.0.1:5000, upload a JSON policy, or select Live Audit.

## Security notes
- Use a strong `SECRET_KEY` in production (env var)
- CSRF token on form posts; session cookies are HTTPOnly + SameSite=Lax
- Request body size limited via `MAX_CONTENT_LENGTH` (default 1MB; override via env)
- Uploads parsed in-memory with content-type checks; filenames sanitized
- If exposing the UI publicly, consider adding rate limiting (e.g., Flask-Limiter) and auth

## Extending rules

Add functions to `iam_analyzer/rules.py` that accept a policy dict (normalized document) and return a list of `(description, score)` tuples. Append the function to `RULE_FUNCS`.

Included checks cover wildcards, service-wide wildcards (e.g., `iam:*`), risky IAM identity operations, S3 policy/ACL mutation, and `NotResource` usage.

## Version

See `iam_analyzer/__init__.py` for the current version.

