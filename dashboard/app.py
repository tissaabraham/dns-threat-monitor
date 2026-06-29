from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from functools import wraps
import sqlite3
import sys
import os

# Needs to be above the next two or it'll cause crashes
# Add the project root to the path before importing project modules.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from config.config import Config
from database.database import DatabaseManager

# Set up Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = Config.SECRET_KEY

# SESSION_COOKIE_HTTPONLY: browser JS cannot read the session cookie, blocks XSS cookie theft.
app.config['SESSION_COOKIE_HTTPONLY'] = True
# SESSION_COOKIE_SAMESITE: cookie is not sent on cross-site requests, reduces CSRF risk.
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# SESSION_COOKIE_SECURE: cookie is only sent over HTTPS; set SESSION_COOKIE_SECURE=true in .env when deploying with HTTPS.
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

# Connect to database
db = DatabaseManager()


def seed_default_admin():
    """Create the default admin account on first run if there are no users yet."""
    try:
        if db.count_users() == 0:
            db.create_user(
                username=Config.DEFAULT_ADMIN_USERNAME,
                password=Config.DEFAULT_ADMIN_PASSWORD
            )
            print(f"Created default admin account '{Config.DEFAULT_ADMIN_USERNAME}'. "
                  f"Change the password after first login.")
    except Exception as e:
        print(f"Could not seed default admin: {e}")


seed_default_admin()


def login_required(view):
    """Block access unless a user is logged in. API routes get a 401 JSON
    response, page routes get redirected to the login page."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        # No user in the session means the request is not logged in.
        if not session.get('user_id'):
            # API calls expect JSON, pages get sent to the login screen.
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


# --- Authentication routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Show the login form and handle login submissions."""
    if request.method == 'GET':
        if session.get('user_id'):
            return redirect(url_for('dashboard'))
        return render_template('login.html', registration_enabled=Config.ENABLE_REGISTRATION)

    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    user = db.verify_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
    # Remember who is logged in for later requests.
    session['user_id'] = user['id']
    session['username'] = user['username']
    return jsonify({'ok': True, 'redirect': url_for('dashboard')})


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Show the registration form and create new accounts."""
    if not Config.ENABLE_REGISTRATION:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('register.html')

    data = request.get_json(silent=True) or request.form
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    full_name = (data.get('full_name') or '').strip() or None
    email = (data.get('email') or '').strip() or None

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    try:
        user_id = db.create_user(username, password, full_name, email)
    except sqlite3.IntegrityError:
        # The username column is unique, so a duplicate raises this.
        return jsonify({'error': 'That username is already taken'}), 409

    # Log the new user in straight away.
    session['user_id'] = user_id
    session['username'] = username
    return jsonify({'ok': True, 'redirect': url_for('dashboard')})


@app.route('/logout')
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    return redirect(url_for('login'))


# --- Page routes (just serve the HTML templates) ---

@app.route('/')
@login_required
def dashboard():
    """Show main dashboard page."""
    return render_template('dashboard.html', username=session.get('username', ''))

@app.route('/profile')
@login_required
def profile():
    """Show user profile page using the username stored in the session."""
    # Read the username from the Flask session (set by the login logic)
    return render_template('profile.html', username=session.get('username'))

@app.route('/live-monitoring')
@login_required
def live_monitoring():
    """Show live monitoring page."""
    return render_template('live_monitoring.html')

@app.route('/active-threats')
@login_required
def active_threats():
    """Show active threats page."""
    return render_template('active_threats.html')

@app.route('/logs')
@login_required
def logs():
    """Show logs page."""
    return render_template('logs.html')

# --- API routes (the frontend JS calls these to get data) ---

@app.route('/api/summary')
@login_required
def api_summary():
    """Numbers for the three summary cards at the top of the dashboard."""
    try:
        summary = db.get_dashboard_summary()
        severity_dist = summary.get('severity_distribution', {})
        num_threats = sum(severity_dist.values()) if severity_dist else 0
        return jsonify({
            'total_queries': summary.get('recent_queries_24h', 0),
            'num_threats': num_threats,
            'active_alerts': summary.get('new_alerts', 0),
            'threat_cache_size': summary.get('threat_cache_size', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dns-logs')
@login_required
def api_dns_logs():
    """All DNS logs from last 24hrs - used in the requests modal."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=50)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-logs')
@login_required
def api_recent_logs():
    """Get last 5 DNS queries."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=5)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
@login_required
def api_logs():
    """For the logs page - can filter by date."""
    try:
        date_str = request.args.get('date')
        logs = db.get_recent_dns_logs(hours=24 * 365, limit=500)
        if date_str:
            logs = [l for l in logs if l.get('timestamp', '').startswith(date_str)]
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/live-logs')
@login_required
def api_live_logs():
    """Get last 25 queries for live view."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=25)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
@login_required
def api_alerts():
    """Active threats page uses this - only shows unresolved ones."""
    try:
        alerts = db.get_active_alerts(limit=50)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/severity-distribution')
@login_required
def api_severity_distribution():
    """How many High/Medium/Low alerts we have. Stephen wanted this for the threats modal."""
    try:
        alerts = db.search_alerts(hours=24)
        severity_dist = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for alert in alerts:
            severity = alert.get('severity', 'Low')
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
        
        return jsonify(severity_dist)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts/<int:alert_id>/status', methods=['POST'])
@login_required
def api_update_alert_status(alert_id):
    """Update the status of an alert and record the change in history."""
    try:
        data = request.get_json(force=True) or {}
        new_status = data.get('status', '').strip()
        notes = data.get('notes', '').strip() or None
        valid_statuses = {'new', 'acknowledged', 'resolved', 'archived'}
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {sorted(valid_statuses)}'}), 400
        success = db.update_alert_status(alert_id, new_status, notes)
        if not success:
            return jsonify({'error': 'Alert not found'}), 404
        return jsonify({'ok': True, 'alert_id': alert_id, 'new_status': new_status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>/history')
@login_required
def api_alert_history(alert_id):
    """Get the full status-change history for a single alert."""
    try:
        history = db.get_alert_history(alert_id)
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/me')
@login_required
def api_me():
    """Return the logged-in user's profile details."""
    try:
        user = db.get_user_by_id(session['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({
            'username': user['username'],
            'full_name': user.get('full_name') or '',
            'email': user.get('email') or ''
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/profile', methods=['POST'])
@login_required
def api_update_profile():
    """Update the logged-in user's full name and email."""
    try:
        data = request.get_json(silent=True) or request.form
        full_name = (data.get('full_name') or '').strip() or None
        email = (data.get('email') or '').strip() or None
        success = db.update_profile(session['user_id'], full_name, email)
        if not success:
            return jsonify({'error': 'User not found'}), 404
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/change-password', methods=['POST'])
@login_required
def api_change_password():
    """Change the logged-in user's password after verifying the current one."""
    try:
        data = request.get_json(silent=True) or request.form
        current = data.get('current_password') or ''
        new_password = data.get('new_password') or ''
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters'}), 400
        success = db.update_password(session['user_id'], current, new_password)
        if not success:
            return jsonify({'error': 'Current password is incorrect'}), 400
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    """Handle page not found."""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    """Handle server errors."""
    return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    try:
        print(" Starting DNS Threat Monitor Dashboard...")
        print(" Dashboard available at: http://localhost:5000")
        app.run(debug=Config.DASHBOARD_DEBUG, host=Config.DASHBOARD_HOST, port=Config.DASHBOARD_PORT)
    except Exception as e:
        print(f" Error starting dashboard: {e}")
    finally:
        # Close database when done
        db.close()

