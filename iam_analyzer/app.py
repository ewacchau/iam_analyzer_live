from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from pathlib import Path
import json, os, tempfile, secrets
from .analyzer import analyze_policy
from .aws_integration import get_all_policies

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXT = {'.json'}

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "changeme")
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    # Basic hardening
    app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 1024 * 1024))  # 1MB default
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    if os.getenv('SESSION_COOKIE_SECURE', '0') == '1':
        app.config['SESSION_COOKIE_SECURE'] = True

    @app.route('/', methods=['GET', 'POST'])
    def index():
        # Lightweight CSRF token
        if request.method == 'GET':
            session['csrf_token'] = secrets.token_urlsafe(16)
            return render_template('index.html', csrf_token=session['csrf_token'])

        if request.method == 'POST':
            token = request.form.get('csrf_token')
            if not token or token != session.get('csrf_token'):
                flash('Invalid CSRF token', 'danger')
                return redirect(url_for('index'))
            mode = request.form.get('mode')
            if mode == 'file':
                file = request.files.get('policy')
                # Validate presence, extension, and basic mimetype when available
                if not file or Path(file.filename).suffix.lower() not in ALLOWED_EXT:
                    flash('Invalid file', 'danger')
                    return redirect(url_for('index'))
                if file.mimetype and file.mimetype not in {"application/json", "text/json", "application/octet-stream"}:
                    flash('Unsupported content type', 'danger')
                    return redirect(url_for('index'))
                fname = secure_filename(file.filename) or 'policy.json'
                try:
                    pol_json = json.load(file)
                except json.JSONDecodeError:
                    flash('Invalid JSON document', 'danger')
                    return redirect(url_for('index'))
                except Exception as e:
                    flash(f'Error reading file: {e}', 'danger')
                    return redirect(url_for('index'))
                result = analyze_policy(pol_json)
                return render_template('results.html', name=fname, result=result)
            elif mode == 'live':
                try:
                    policies = get_all_policies()
                except Exception as e:
                    flash(f'Error fetching AWS data: {e}', 'danger')
                    return redirect(url_for('index'))
                reports = [(p['PolicyName'], analyze_policy(p['Document'])) for p in policies]
                return render_template('live_results.html', reports=reports)
        # Fallback (should not reach here)
        return redirect(url_for('index'))

    return app
