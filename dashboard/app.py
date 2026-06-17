from flask import Flask, render_template, jsonify, request, session
import sys
import os
from config.config import Config

# Add parent directory to path to import database module
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from database.database import DatabaseManager

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'dns-monitor-secret-key-change-in-production'
db = DatabaseManager()

@app.route('/')
def dashboard():
    """Render the dashboard homepage."""
    return render_template('dashboard.html', username='')

@app.route('/profile')
def profile():
    """Render the user profile page."""
    return render_template('profile.html', username=session.get('username'))

@app.route('/live-monitoring')
def live_monitoring():
    """Render the live monitoring page."""
    return render_template('live_monitoring.html')

@app.route('/active-threats')
def active_threats():
    """Render the active threats page."""
    return render_template('active_threats.html')

@app.route('/logs')
def logs():
    """Render the logs page."""
    return render_template('logs.html')

@app.route('/api/summary')
def api_summary():
    """Get dashboard summary statistics."""
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
    """Get recent DNS logs (last 24 hours)."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=50)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/recent-logs')
def api_recent_logs():
    """Get the 5 most recent DNS log entries."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=5)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def api_logs():
    """Get DNS logs optionally filtered by date (YYYY-MM-DD)."""
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
    """Get the 25 most recent DNS log entries for live monitoring."""
    try:
        logs = db.get_recent_dns_logs(hours=24, limit=25)
        return jsonify(logs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    """Get active alerts."""
    try:
        alerts = db.get_active_alerts(limit=50)
        return jsonify(alerts)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/severity-distribution')
def api_severity_distribution():
    """Get distribution of alert severities for the last 24 hours."""
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
    """Handle 404 errors."""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors."""
    return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    try:
        print(" Starting DNS Threat Monitor Dashboard...")
        print(" Dashboard available at: http://localhost:5000")
        app.run(debug=Config.DASHBOARD_DEBUG, host=Config.DASHBOARD_HOST, port=Config.DASHBOARD_PORT)
    except Exception as e:
        print(f" Error starting dashboard: {e}")
    finally:
        db.close()

