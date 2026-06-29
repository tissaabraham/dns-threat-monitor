from flask import Flask, render_template, jsonify, request, session
import sys
import os

# Add parent folder to imports
# Needs to be above the next two or it'll cause crashes
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


from config.config import Config
from database.database import DatabaseManager

# Set up Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'dns-monitor-secret-key-change-in-production'

# Connect to database
db = DatabaseManager()

# --- Page routes (just serve the HTML templates) ---

@app.route('/')
def dashboard():
    """Show main dashboard page."""
    return render_template('dashboard.html', username='')

@app.route('/profile')
def profile():
    """Show user profile page using the username stored in the session."""
    # Read the username from the Flask session (set by the frontend or login logic)
    return render_template('profile.html', username=session.get('username'))

@app.route('/live-monitoring')
def live_monitoring():
    """Show live monitoring page."""
    return render_template('live_monitoring.html')

@app.route('/active-threats')
def active_threats():
    """Show active threats page."""
    return render_template('active_threats.html')

@app.route('/logs')
def logs():
    """Show logs page."""
    return render_template('logs.html')

# --- API routes (the frontend JS calls these to get data) ---

@app.route('/api/summary')
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
def api_dns_logs():
    """All DNS logs from last 24hrs - used in the requests modal."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=50)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-logs')
def api_recent_logs():
    """Get last 5 DNS queries."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=5)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
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
def api_live_logs():
    """Get last 25 queries for live view."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=25)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Active threats page uses this - only shows unresolved ones."""
    try:
        alerts = db.get_active_alerts(limit=50)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/severity-distribution')
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
def api_alert_history(alert_id):
    """Get the full status-change history for a single alert."""
    try:
        history = db.get_alert_history(alert_id)
        return jsonify(history)
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

