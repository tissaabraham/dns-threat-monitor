from datetime import datetime, timezone
from database.dataModels import DnsEvent, Alert
from parser.blacklist import Blacklist
from detection.rules import RuleEngine


class Detector:
    """
    The main detection engine.
    Takes a DnsEvent, runs all checks, and returns an Alert if suspicious.
    """

    def __init__(self, blacklist: Blacklist, rule_engine: RuleEngine):
        self.blacklist = blacklist
        self.rule_engine = rule_engine

    def analyse(self, event: DnsEvent) -> Alert | None:
        """
        Analyse DNS event.
        Returns an Alert if something suspicious was found.
        """
        blacklist_hit = self.blacklist.is_malicious(event.domain)

        # Skip normal responses unless they hit the blacklist
        if event.is_response and event.response_code != 3 and not blacklist_hit:
            return None
        rules_triggered = self.rule_engine.check(event)

        if not blacklist_hit and not rules_triggered:
            return None  # nothing suspicious, move on

        score = self._calculate_score(blacklist_hit, rules_triggered)
        severity = self._get_severity(score)

        return Alert(
            timestamp=datetime.now(timezone.utc),
            source_ip=event.source_ip,
            domain=event.domain,
            severity=severity,
            score=score,
            rules_triggered=rules_triggered
        )

    def _calculate_score(self, blacklist_hit: bool, rules: list) -> int:
        score = 0
        if blacklist_hit:
            score += 100

#Can adjust the severity of the scores as we like
        rule_scores = {
            "suspicious_tld": 20,
            "high_query_rate": 30,
            "nxdomain_flood": 35,
            "subdomain_abuse": 50,
            "dga_pattern": 40,
        }
        for rule in rules:
            score += rule_scores.get(rule, 0)

        return score

    def _get_severity(self, score: int) -> str:
        if score >= 100:
            return "High"
        elif score >= 50:
            return "Medium"
        else:
            return "Low"