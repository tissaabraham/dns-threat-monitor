from flask import Flask, render_template, jsonify, request, session
import sys
import os
from config.config import Config

# Add parent folder to imports
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database.database import DatabaseManager

# Set up Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'dns-monitor-secret-key-change-in-production'

# Connect to database
db = DatabaseManager()

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

@app.route('/api/summary')
def api_summary():
    """Get stats for dashboard."""
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
    """Get recent DNS queries."""
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
    """Get logs, filter by date if needed."""
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
    """Get all active alerts."""
    try:
        alerts = db.get_active_alerts(limit=50)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/severity-distribution')
def api_severity_distribution():
    """Count alerts by severity."""
    try:
        alerts = db.search_alerts(hours=24)
        severity_dist = {'High': 0, 'Medium': 0, 'Low': 0}
        
        for alert in alerts:
            severity = alert.get('severity', 'Low')
            severity_dist[severity] = severity_dist.get(severity, 0) + 1
        
        return jsonify(severity_dist)
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

