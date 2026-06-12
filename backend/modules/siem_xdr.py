"""
AegisXDR SIEM + XDR + SOAR Engine
Alert correlation, detection rules (Sigma/YARA), UEBA, playbooks
"""
import uuid
import json
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict


class SIEMEngine:
    """Security Information and Event Management"""

    MITRE_TECHNIQUES = {
        "T1059": "Command and Scripting Interpreter",
        "T1055": "Process Injection",
        "T1003": "OS Credential Dumping",
        "T1021": "Remote Services",
        "T1078": "Valid Accounts",
        "T1486": "Data Encrypted for Impact",
        "T1190": "Exploit Public-Facing Application",
        "T1566": "Phishing",
        "T1036": "Masquerading",
        "T1071": "Application Layer Protocol",
        "T1560": "Archive Collected Data",
        "T1041": "Exfiltration Over C2 Channel",
        "T1499": "Endpoint Denial of Service",
        "T1110": "Brute Force",
        "T1548": "Abuse Elevation Control Mechanism",
    }

    def __init__(self):
        self._alerts: List[Dict] = []
        self._incidents: List[Dict] = []
        self._rules: List[Dict] = []
        self._event_buffer: List[Dict] = []
        self._correlation_window = 300  # 5 minutes
        self._load_default_rules()

    def _load_default_rules(self):
        self._rules = [
            {
                "id": str(uuid.uuid4()),
                "name": "Multiple Failed Logins",
                "type": "sigma",
                "condition": {"field": "event_type", "value": "auth_failure",
                               "threshold": 5, "window_seconds": 300},
                "severity": "high",
                "mitre": ["T1110"],
                "enabled": True
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Ransomware Encryption Activity",
                "type": "sigma",
                "condition": {"field": "event_type", "value": "file_mass_rename",
                               "threshold": 100, "window_seconds": 60},
                "severity": "critical",
                "mitre": ["T1486"],
                "enabled": True
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Process Injection Detected",
                "type": "sigma",
                "condition": {"field": "event_type", "value": "process_injection"},
                "severity": "critical",
                "mitre": ["T1055"],
                "enabled": True
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Lateral Movement via SMB",
                "type": "sigma",
                "condition": {"field": "event_type", "value": "smb_lateral_movement"},
                "severity": "high",
                "mitre": ["T1021"],
                "enabled": True
            },
            {
                "id": str(uuid.uuid4()),
                "name": "Data Exfiltration - Large Transfer",
                "type": "sigma",
                "condition": {"field": "bytes_out", "operator": "gt",
                               "value": 10485760},  # 10MB
                "severity": "high",
                "mitre": ["T1041"],
                "enabled": True
            }
        ]

    def ingest_event(self, event: Dict) -> List[Dict]:
        """Process incoming event, check rules, generate alerts"""
        event["id"] = str(uuid.uuid4())
        event["ingested_at"] = datetime.utcnow().isoformat()
        self._event_buffer.append(event)

        # Keep buffer at 10000 events
        if len(self._event_buffer) > 10000:
            self._event_buffer = self._event_buffer[-10000:]

        triggered_alerts = []
        for rule in self._rules:
            if not rule["enabled"]:
                continue
            if self._evaluate_rule(rule, event):
                alert = self._create_alert(rule, event)
                self._alerts.append(alert)
                triggered_alerts.append(alert)

        return triggered_alerts

    def _evaluate_rule(self, rule: Dict, event: Dict) -> bool:
        condition = rule["condition"]
        field = condition.get("field")
        value = condition.get("value")
        operator = condition.get("operator", "eq")
        threshold = condition.get("threshold")
        window = condition.get("window_seconds", 300)

        if field not in event:
            return False

        if operator == "eq":
            if event[field] != value:
                return False
        elif operator == "gt":
            try:
                if float(event[field]) <= float(value):
                    return False
            except (TypeError, ValueError):
                return False
        elif operator == "contains":
            if value not in str(event[field]):
                return False

        # Threshold check
        if threshold:
            cutoff = datetime.utcnow() - timedelta(seconds=window)
            matching = sum(
                1 for e in self._event_buffer
                if e.get(field) == value and
                datetime.fromisoformat(e.get("ingested_at",
                                              datetime.utcnow().isoformat())) > cutoff
            )
            return matching >= threshold

        return True

    def _create_alert(self, rule: Dict, event: Dict) -> Dict:
        alert_id = str(uuid.uuid4())
        alert = {
            "id": alert_id,
            "title": rule["name"],
            "description": f"Rule '{rule['name']}' triggered by event",
            "severity": rule["severity"],
            "category": rule["type"],
            "source": event.get("source", "SIEM"),
            "tenant_id": event.get("tenant_id", "default"),
            "status": "open",
            "mitre_techniques": rule.get("mitre", []),
            "mitre_descriptions": [self.MITRE_TECHNIQUES.get(t, t) for t in rule.get("mitre", [])],
            "raw_event": event,
            "risk_score": self._severity_to_score(rule["severity"]),
            "rule_id": rule["id"],
            "created_at": datetime.utcnow().isoformat()
        }
        return alert

    def _severity_to_score(self, severity: str) -> float:
        return {"critical": 0.95, "high": 0.75, "medium": 0.5,
                "low": 0.25, "info": 0.1}.get(severity, 0.5)

    def get_alerts(self, tenant_id: str = None, status: str = None,
                   severity: str = None, limit: int = 100) -> List[Dict]:
        alerts = self._alerts[:]
        if tenant_id:
            alerts = [a for a in alerts if a.get("tenant_id") == tenant_id]
        if status:
            alerts = [a for a in alerts if a.get("status") == status]
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        return alerts[-limit:]

    def update_alert(self, alert_id: str, updates: Dict) -> Optional[Dict]:
        for i, alert in enumerate(self._alerts):
            if alert["id"] == alert_id:
                self._alerts[i].update(updates)
                return self._alerts[i]
        return None

    def correlate_alerts(self, time_window_minutes: int = 30) -> List[Dict]:
        """Correlate related alerts into incidents"""
        cutoff = datetime.utcnow() - timedelta(minutes=time_window_minutes)
        recent = [a for a in self._alerts
                  if datetime.fromisoformat(a["created_at"]) > cutoff
                  and a["status"] == "open"]

        # Group by tenant
        by_tenant = defaultdict(list)
        for alert in recent:
            by_tenant[alert.get("tenant_id", "default")].append(alert)

        incidents = []
        for tenant_id, tenant_alerts in by_tenant.items():
            if len(tenant_alerts) >= 3:
                incident = self._create_incident(tenant_alerts, tenant_id)
                self._incidents.append(incident)
                incidents.append(incident)
        return incidents

    def _create_incident(self, alerts: List[Dict], tenant_id: str) -> Dict:
        severities = [a["severity"] for a in alerts]
        max_severity = ("critical" if "critical" in severities
                        else "high" if "high" in severities
                        else "medium")
        all_mitre = list(set(t for a in alerts for t in a.get("mitre_techniques", [])))
        return {
            "id": str(uuid.uuid4()),
            "title": f"Correlated Incident - {len(alerts)} alerts",
            "description": f"Auto-correlated incident from {len(alerts)} related alerts",
            "severity": max_severity,
            "status": "open",
            "tenant_id": tenant_id,
            "alert_ids": [a["id"] for a in alerts],
            "mitre_techniques": all_mitre,
            "created_at": datetime.utcnow().isoformat()
        }

    def get_stats(self, tenant_id: str = None) -> Dict:
        alerts = self._alerts if not tenant_id else \
            [a for a in self._alerts if a.get("tenant_id") == tenant_id]
        by_severity = defaultdict(int)
        by_status = defaultdict(int)
        for a in alerts:
            by_severity[a["severity"]] += 1
            by_status[a["status"]] += 1
        return {
            "total_alerts": len(alerts),
            "total_incidents": len(self._incidents),
            "total_rules": len(self._rules),
            "by_severity": dict(by_severity),
            "by_status": dict(by_status),
            "events_processed": len(self._event_buffer)
        }


class UEBAEngine:
    """User and Entity Behavior Analytics"""

    def __init__(self):
        self._baselines: Dict[str, Dict] = {}
        self._anomalies: List[Dict] = []

    def update_baseline(self, user_id: str, event: Dict):
        if user_id not in self._baselines:
            self._baselines[user_id] = {
                "login_hours": [],
                "login_ips": [],
                "data_access_bytes": [],
                "commands_executed": [],
                "failed_auths": 0,
                "total_events": 0
            }
        b = self._baselines[user_id]
        hour = datetime.utcnow().hour
        if hour not in b["login_hours"]:
            b["login_hours"].append(hour)
        if event.get("ip") and event["ip"] not in b["login_ips"]:
            b["login_ips"].append(event["ip"])
        if event.get("bytes"):
            b["data_access_bytes"].append(event["bytes"])
        b["total_events"] += 1

    def detect_anomaly(self, user_id: str, event: Dict) -> Optional[Dict]:
        baseline = self._baselines.get(user_id, {})
        anomalies = []
        hour = datetime.utcnow().hour
        known_hours = baseline.get("login_hours", [])
        if known_hours and hour not in known_hours:
            anomalies.append({
                "type": "unusual_login_time",
                "detail": f"Login at hour {hour}, typical hours: {known_hours[:5]}"
            })
        known_ips = baseline.get("login_ips", [])
        if event.get("ip") and known_ips and event["ip"] not in known_ips:
            anomalies.append({
                "type": "new_ip_address",
                "detail": f"New IP: {event.get('ip')}"
            })
        if event.get("bytes") and baseline.get("data_access_bytes"):
            avg = sum(baseline["data_access_bytes"]) / len(baseline["data_access_bytes"])
            if event["bytes"] > avg * 5:
                anomalies.append({
                    "type": "unusual_data_volume",
                    "detail": f"Data accessed: {event['bytes']} bytes vs avg {avg:.0f}"
                })

        if anomalies:
            anomaly = {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "anomalies": anomalies,
                "risk_score": min(len(anomalies) * 0.25, 1.0),
                "event": event,
                "timestamp": datetime.utcnow().isoformat()
            }
            self._anomalies.append(anomaly)
            return anomaly
        return None

    def get_user_risk(self, user_id: str) -> Dict:
        user_anomalies = [a for a in self._anomalies if a["user_id"] == user_id]
        recent = [a for a in user_anomalies
                  if datetime.fromisoformat(a["timestamp"]) >
                  datetime.utcnow() - timedelta(days=7)]
        risk = min(len(recent) * 0.1, 1.0)
        return {
            "user_id": user_id,
            "risk_score": round(risk, 3),
            "risk_level": "high" if risk > 0.6 else "medium" if risk > 0.3 else "low",
            "total_anomalies": len(user_anomalies),
            "recent_anomalies": len(recent),
            "baseline_established": user_id in self._baselines
        }

    def get_all_anomalies(self, limit: int = 100) -> List[Dict]:
        return self._anomalies[-limit:]


# Singletons
siem = SIEMEngine()
ueba = UEBAEngine()
