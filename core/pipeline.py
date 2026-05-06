"""
DNS Threat Monitor - Data Pipeline
==================================

This module defines the data processing pipeline that connects
all system components in a clean, maintainable flow.
"""

import logging
from typing import Optional
from datetime import datetime, timezone

from database.dataModels import DnsEvent, Alert
from parser.input_parser import parse_line
from parser.blacklist import Blacklist
from detection.rules import RuleEngine
from detection.threat_detector import Detector
from database.database import DatabaseManager
from utils.logger import get_logger, Timer

logger = get_logger(__name__)


class ProcessingPipeline:
    """
    Data processing pipeline for DNS threat monitoring.

    This class orchestrates the flow of data through all system components:
    Raw Input → Parsing → Detection → Storage → Output
    """

    def __init__(self, database: DatabaseManager, blacklist: Blacklist,
                 rule_engine: RuleEngine, detector: Detector):
        """
        Initialize the processing pipeline.

        Args:
            database: Database manager instance
            blacklist: Blacklist manager instance
            rule_engine: Rule engine instance
            detector: Threat detector instance
        """
        self.database = database
        self.blacklist = blacklist
        self.rule_engine = rule_engine
        self.detector = detector

        # Pipeline statistics
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'parse_errors': 0,
            'db_errors': 0
        }

        logger.info("Processing pipeline initialized")

    def process_dns_event(self, source: str, raw_line: str) -> Optional[Alert]:
        """
        Process a single DNS event through the complete pipeline.

        Args:
            source: Source of the DNS data ("dnsmasq" or "tshark")
            raw_line: Raw log line from capture source

        Returns:
            Alert object if threat detected, None otherwise
        """
        with Timer("process_dns_event", logger):

            # Step 1: Parse the raw line into a DnsEvent
            event = self._parse_event(source, raw_line)
            if not event:
                return None

            # Step 2: Analyze the event for threats
            alert = self._analyze_event(event)
            if not alert:
                # Store clean event with no threat score
                self._store_event(event, 0)
                return None

            # Step 3: Store the event and alert
            self._store_event_and_alert(event, alert)

            # Step 4: Return alert for further processing (notifications, etc.)
            return alert

    def _parse_event(self, source: str, raw_line: str) -> Optional[DnsEvent]:
        """
        Parse raw DNS log line into DnsEvent object.

        Args:
            source: Data source ("dnsmasq" or "tshark")
            raw_line: Raw log line

        Returns:
            DnsEvent object or None if parsing failed
        """
        try:
            event = parse_line(source, raw_line)
            if event:
                self.stats['events_processed'] += 1
                logger.debug(f"Parsed event: {event.domain} from {event.source_ip}")
                return event
            else:
                logger.debug(f"Skipped invalid line from {source}: {raw_line[:100]}...")
                return None

        except Exception as e:
            self.stats['parse_errors'] += 1
            logger.error(f"Parse error for {source} line: {e}")
            return None

    def _analyze_event(self, event: DnsEvent) -> Optional[Alert]:
        """
        Analyze DNS event for potential threats.

        Args:
            event: Parsed DnsEvent object

        Returns:
            Alert object if threat detected, None otherwise
        """
        try:
            alert = self.detector.analyse(event)
            if alert:
                self.stats['alerts_generated'] += 1
                logger.warning(f"Threat detected: {alert.domain} ({alert.severity}) - {alert.rules_triggered}")
            return alert

        except Exception as e:
            logger.error(f"Analysis error for event {event.domain}: {e}")
            return None

    def _store_event(self, event: DnsEvent, threat_score: int):
        """
        Store DNS event in database.

        Args:
            event: DnsEvent to store
            threat_score: Threat score for the event
        """
        try:
            self.database.store_dns_log(event, threat_score)
            logger.debug(f"Stored event: {event.domain}")
        except Exception as e:
            self.stats['db_errors'] += 1
            logger.error(f"Database error storing event {event.domain}: {e}")

    def _store_event_and_alert(self, event: DnsEvent, alert: Alert):
        """
        Store both DNS event and alert in database.

        Args:
            event: DnsEvent to store
            alert: Alert to store
        """
        try:
            # Store the DNS log first
            dns_log_id = self.database.store_dns_log(event, alert.score)

            # Store the alert linked to the DNS log
            self.database.store_alert(alert, dns_log_id)

            logger.info(f"Stored alert: {alert.domain} (ID: {dns_log_id})")

        except Exception as e:
            self.stats['db_errors'] += 1
            logger.error(f"Database error storing alert {alert.domain}: {e}")

    def get_pipeline_stats(self) -> dict:
        """
        Get current pipeline processing statistics.

        Returns:
            Dictionary with processing statistics
        """
        return self.stats.copy()

    def reset_stats(self):
        """Reset pipeline statistics counters."""
        self.stats = {
            'events_processed': 0,
            'alerts_generated': 0,
            'parse_errors': 0,
            'db_errors': 0
        }
        logger.info("Pipeline statistics reset")


class PipelineFactory:
    """
    Factory class for creating and configuring processing pipelines.
    """

    @staticmethod
    def create_pipeline() -> ProcessingPipeline:
        """
        Create a fully configured processing pipeline.

        Returns:
            Configured ProcessingPipeline instance
        """
        logger.info("Creating processing pipeline...")

        # Initialize all components
        database = DatabaseManager()
        blacklist = Blacklist()
        rule_engine = RuleEngine()
        detector = Detector(blacklist, rule_engine)

        # Create and return pipeline
        pipeline = ProcessingPipeline(database, blacklist, rule_engine, detector)

        logger.info("Processing pipeline created successfully")
        return pipeline

    @staticmethod
    def create_test_pipeline() -> ProcessingPipeline:
        """
        Create a pipeline configured for testing (may use test databases, etc.).

        Returns:
            Test-configured ProcessingPipeline instance
        """
        # For now, same as regular pipeline
        # Could be extended to use test databases or mock components
        return PipelineFactory.create_pipeline()
