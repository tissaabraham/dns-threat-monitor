import time
from capture.capture_combo import combined_capture
from parser.input_parser import parse_line
from parser.blacklist import Blacklist
from detection.rules import RuleEngine
from detection.threat_detector import Detector
from database.database import DatabaseManager
from config.config import Config

def main():
    # Print config on startup for debugging, can remove maybe when finished
    Config.print_configuration()

    # -------------------------
    # 1. Set up the blacklist
    # -------------------------
    blacklist = Blacklist()
    blacklist.load_from_file(str(Config.THREATS_FILE))

    # Load feeds first so we start with a populated list, then start auto refreshing in the background.
    if Config.ENABLE_REMOTE_BLACKLIST:
        for url in Config.REMOTE_BLACKLIST_URLS:
            blacklist.load_from_url_sync(url)

        blacklist.start_auto_refresh(
            Config.REMOTE_BLACKLIST_URLS[0],
            interval_hours=Config.BLACKLIST_REFRESH_URLHAUS
        )
        blacklist.start_auto_refresh(
            Config.REMOTE_BLACKLIST_URLS[1],
            interval_hours=Config.BLACKLIST_REFRESH_OPENPHISH
        )
    # -------------------------
    # 2. Set up detection
    # -------------------------
    rule_engine = RuleEngine()
    detector = Detector(blacklist, rule_engine)

    # -------------------------
    # 3. Set up database
    # -------------------------
    db = DatabaseManager()

    print("Monitoring started...")

    # -------------------------
    # 4. Main section
    # -------------------------
    try:
        for source, raw_line in combined_capture():
            event = parse_line(source, raw_line)
            if event is None:
                continue  # line not useful, skip it

            alert = detector.analyse(event)

            if alert:
                # Store the DNS event with its threat score
                dns_log_id = db.store_dns_log(event, threat_score=alert.score)
                # Store the alert, linked to the DNS event
                db.store_alert(alert, dns_log_id)
                # Print to console so you can see detections in real time
                print(f"[{alert.severity}] {alert.domain} from {alert.source_ip} "
                      f"— score: {alert.score}, rules: {alert.rules_triggered}")
            else:
                # Clean traffic — store with score 0
                db.store_dns_log(event, threat_score=0)

    except KeyboardInterrupt:
        # Ctrl+C pressed — shut down cleanly
        print("\nMonitoring stopped.")
    finally:
        db.close()

if __name__ == "__main__":
    main()