"""
DNS Threat Monitor - Main Orchestrator
=====================================

This is the main orchestrator that connects all system components:
- Capture Layer (dnsmasq + tshark)
- Parser Layer (input parsing + blacklist)
- Detection Layer (rules + threat detector)
- Database Layer (storage + queries)

The system processes DNS traffic in real-time, detects threats,
and stores results for dashboard access.
"""

import sys
import time
import signal
import logging
from datetime import datetime, timezone
from queue import Queue
from threading import Thread, Event

# Import system components
from capture.capture_combo import combined_capture
from parser.input_parser import parse_line
from parser.blacklist import Blacklist
from detection.rules import RuleEngine
from detection.threat_detector import Detector
from database.database import DatabaseManager
from config.config import Config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/dns_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DNSThreatMonitor:
    """
    Main orchestrator for the DNS Threat Monitoring system.
    Coordinates all components and manages the data pipeline.
    """

    def __init__(self):
        """Initialize the DNS Threat Monitor system."""
        logger.info("Initializing DNS Threat Monitor...")

        # Load configuration
        self.config = Config()

        # Initialize components
        self.database = DatabaseManager()
        self.blacklist = Blacklist()
        self.rule_engine = RuleEngine()
        self.detector = Detector(self.blacklist, self.rule_engine)

        # Processing queue and control
        self.event_queue = Queue(maxsize=self.config.QUEUE_SIZE)
        self.stop_event = Event()

        # Statistics
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'start_time': datetime.now(timezone.utc)
        }

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        logger.info("✓ DNS Threat Monitor initialized successfully")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop()

    def start(self):
        """Start the DNS threat monitoring system."""
        logger.info("Starting DNS Threat Monitor...")

        try:
            # Initialize blacklist
            self._initialize_blacklist()

            # Start processing threads
            self._start_processing_threads()

            # Start capture
            self._start_capture()

            logger.info("✓ DNS Threat Monitor started successfully")
            logger.info("Monitoring DNS traffic... Press Ctrl+C to stop")

            # Keep main thread alive
            while not self.stop_event.is_set():
                time.sleep(1)
                self._print_stats()

        except Exception as e:
            logger.error(f"Error starting DNS Threat Monitor: {e}")
            self.stop()
            raise

    def stop(self):
        """Stop the DNS threat monitoring system."""
        logger.info("Stopping DNS Threat Monitor...")

        self.stop_event.set()

        # Close database connection
        if hasattr(self, 'database'):
            self.database.close()

        logger.info("✓ DNS Threat Monitor stopped")

    def _initialize_blacklist(self):
        """Initialize the blacklist with local and remote sources."""
        logger.info("Initializing blacklist...")

        # Load local threats file
        try:
            self.blacklist.load_from_file(self.config.THREATS_FILE)
            logger.info(f"✓ Loaded local threats from {self.config.THREATS_FILE}")
        except FileNotFoundError:
            logger.warning(f"Local threats file not found: {self.config.THREATS_FILE}")

        # Start auto-refresh from remote sources
        if self.config.ENABLE_REMOTE_BLACKLIST:
            for url in self.config.REMOTE_BLACKLIST_URLS:
                self.blacklist.start_auto_refresh(url)
                logger.info(f"✓ Started auto-refresh from {url}")

    def _start_processing_threads(self):
        """Start the event processing threads."""
        logger.info("Starting processing threads...")

        # Start multiple processing threads for better throughput
        for i in range(self.config.PROCESSING_THREADS):
            thread = Thread(
                target=self._process_events_worker,
                name=f"Processor-{i+1}",
                daemon=True
            )
            thread.start()
            logger.info(f"✓ Started processing thread {i+1}")

    def _start_capture(self):
        """Start the DNS traffic capture."""
        logger.info("Starting DNS capture...")

        # Start capture in a separate thread
        capture_thread = Thread(
            target=self._capture_worker,
            name="Capture",
            daemon=True
        )
        capture_thread.start()
        logger.info("✓ DNS capture started")

    def _capture_worker(self):
        """Worker thread for DNS traffic capture."""
        try:
            for source, line in combined_capture():
                if self.stop_event.is_set():
                    break

                # Put event in processing queue
                try:
                    self.event_queue.put((source, line), timeout=1)
                except:
                    # Queue full, skip this event
                    logger.warning("Processing queue full, skipping event")

        except Exception as e:
            logger.error(f"Error in capture worker: {e}")
            self.stop()

    def _process_events_worker(self):
        """Worker thread for processing DNS events."""
        while not self.stop_event.is_set():
            try:
                # Get event from queue
                source, line = self.event_queue.get(timeout=1)

                # Process the event
                self._process_dns_event(source, line)

                # Mark task as done
                self.event_queue.task_done()

            except:
                # Timeout or queue empty, continue
                continue

    def _process_dns_event(self, source: str, line: str):
        """Process a single DNS event through the pipeline."""
        try:
            # Parse the raw line into a DnsEvent
            event = parse_line(source, line)
            if not event:
                return  # Skip invalid events

            # Analyze the event for threats
            alert = self.detector.analyse(event)

            # Store the DNS log
            threat_score = alert.score if alert else 0
            dns_log_id = self.database.store_dns_log(event, threat_score)

            # Store alert if generated
            if alert:
                alert_id = self.database.store_alert(alert, dns_log_id)
                logger.warning(f"🚨 ALERT: {alert.domain} ({alert.severity}) - {alert.rules_triggered}")
                self.stats['alerts_generated'] += 1

            # Update statistics
            self.stats['events_processed'] += 1

        except Exception as e:
            logger.error(f"Error processing DNS event: {e}")

    def _print_stats(self):
        """Print current system statistics."""
        runtime = datetime.now(timezone.utc) - self.stats['start_time']
        hours = runtime.total_seconds() / 3600

        if hours > 0:
            eps = self.stats['events_processed'] / hours
            aps = self.stats['alerts_generated'] / hours

            print(f"\r📊 Events: {self.stats['events_processed']} "
                  f"Alerts: {self.stats['alerts_generated']} "
                  f"Rate: {eps:.1f} EPS, {aps:.2f} APS", end='', flush=True)


def main():
    """Main entry point for the DNS Threat Monitor."""
    try:
        monitor = DNSThreatMonitor()
        monitor.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        if 'monitor' in locals():
            monitor.stop()


if __name__ == "__main__":
    main()
