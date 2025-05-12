from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from pathlib import Path
import json, os, tempfile
from .analyzer import analyze_policy
from .aws_integration import get_all_policies

UPLOAD_FOLDER = tempfile.gettempdir()
ALLOWED_EXT = {'.json'}

def create_app():
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", "changeme")
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    @app.route('/', methods=['GET', 'POST'])
    def index():
        if request.method == 'POST':
            mode = request.form.get('mode')
            if mode == 'file':
                file = request.files.get('policy')
                if not file or Path(file.filename).suffix.lower() not in ALLOWED_EXT:
                    flash('Invalid file', 'danger')
                    return redirect(url_for('index'))
                fname = secure_filename(file.filename)
                fpath = Path(app.config['UPLOAD_FOLDER']) / fname
                file.save(fpath)
                with open(fpath, 'r') as f:
                    pol_json = json.load(f)
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
        return render_template('index.html')

    return app
