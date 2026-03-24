"""
DNS Threat Monitor - Main Application

Group E Capstone Project CT5180 at NUIG
Team: Stephen Small, Tissa Abraham, Robert O'Brien

Main entry point for the DNS threat monitoring system.
"""

import logging
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from capture.dns_capture import DNSCapture
from parser.dns_parser import DNSParser
from detection.detection_engine import DetectionEngine
from database.database_manager import DatabaseManager
from dashboard.app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dns_threat_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class DNSThreatMonitor:
    """
    Main DNS Threat Monitor Application
    
    Orchestrates all components:
    - Traffic Capture Layer
    - Parsing and Processing Layer
    - Detection Engine
    - Data Storage Layer
    - Presentation and Alerting Layer
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize the DNS threat monitor.
        
        Args:
            config_file: Path to configuration file
        """
        logger.info("Initializing DNS Threat Monitor...")
        
        # Initialize components
        self.capture = DNSCapture()
        self.parser = DNSParser()
        self.detector = DetectionEngine()
        self.database = DatabaseManager()
        
        logger.info("All components initialized successfully")
        
    def start(self):
        """Start the monitoring system."""
        try:
            logger.info("Starting DNS Threat Monitor...")
            
            # Start traffic capture
            self.capture.start_capture()
            
            # Process captured traffic
            self._process_traffic()
            
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            self.stop()
        except Exception as e:
            logger.error(f"Error during execution: {e}", exc_info=True)
            self.stop()
            
    def stop(self):
        """Stop the monitoring system."""
        logger.info("Stopping DNS Threat Monitor...")
        self.capture.stop_capture()
        self.database.close()
        logger.info("DNS Threat Monitor stopped")
        
    def _process_traffic(self):
        """
        Process captured DNS traffic.
        
        This is the main loop that:
        1. Captures DNS traffic
        2. Parses DNS queries
        3. Applies detection rules
        4. Generates alerts
        5. Stores in database
        """
        logger.info("Starting traffic processing loop...")
        
        # Implementation will process captured packets
        # and apply detection rules
        pass
    
    def run_dashboard(self, host: str = '0.0.0.0', port: int = 5000):
        """
        Run the Flask web dashboard.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        logger.info(f"Starting web dashboard on {host}:{port}")
        app = create_app()
        app.run(host=host, port=port, debug=False)


def main():
    """Main entry point."""
    logger.info("=" * 60)
    logger.info("DNS Threat Monitor - Group E, CT5180 Capstone Project")
    logger.info("Team: Stephen Small, Tissa Abraham, Robert O'Brien")
    logger.info("=" * 60)
    
    # Create monitor instance
    monitor = DNSThreatMonitor()
    
    # Start monitoring
    monitor.start()


if __name__ == '__main__':
    main()

