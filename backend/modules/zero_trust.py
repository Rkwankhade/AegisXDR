"""
AegisXDR Zero Trust Identity Module
Continuous verification: Device + User + Location + Behavior + Risk Score
"""
import uuid
import hashlib
import math
from datetime import datetime, timedelta
from typing import Dict, Optional, List


class ZeroTrustEngine:
    """Continuous verification engine - never trust, always verify"""

    TRUST_THRESHOLDS = {
        "high": 0.8,
        "medium": 0.5,
        "low": 0.2,
        "none": 0.0
    }

    KNOWN_GOOD_LOCATIONS = set()
    RISK_INDICATORS = {
        "new_device": 0.3,
        "new_location": 0.25,
        "unusual_time": 0.15,
        "failed_mfa": 0.4,
        "high_volume_requests": 0.2,
        "anomalous_behavior": 0.35,
        "vpn_detected": 0.1,
        "tor_detected": 0.6,
        "known_bad_ip": 0.9,
    }

    def __init__(self):
        self._sessions: Dict[str, Dict] = {}
        self._user_baselines: Dict[str, Dict] = {}
        self._device_registry: Dict[str, Dict] = {}

    def evaluate_access(self, user_id: str, device_fingerprint: str,
                        ip_address: str, resource: str,
                        action: str, context: Dict = None) -> Dict:
        """Main Zero Trust evaluation - returns trust decision"""
        context = context or {}
        session_id = str(uuid.uuid4())

        # Gather signals
        device_score = self._evaluate_device(device_fingerprint, user_id)
        user_score = self._evaluate_user(user_id, ip_address, context)
        location_score = self._evaluate_location(ip_address, user_id)
        behavior_score = self._evaluate_behavior(user_id, action, resource, context)

        # Weighted risk calculation
        risk_score = (
            (1 - device_score) * 0.25 +
            (1 - user_score) * 0.35 +
            (1 - location_score) * 0.20 +
            (1 - behavior_score) * 0.20
        )

        # Apply additional risk indicators
        additional_risk = self._check_risk_indicators(ip_address, context)
        final_risk = min(risk_score + additional_risk, 1.0)
        trust_score = 1.0 - final_risk
        trust_level = self._determine_trust_level(trust_score)

        decision = {
            "session_id": session_id,
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "trust_score": round(trust_score, 4),
            "risk_score": round(final_risk, 4),
            "trust_level": trust_level,
            "granted": trust_level in ["high", "medium"],
            "requires_mfa": trust_level == "medium",
            "signals": {
                "device_score": round(device_score, 4),
                "user_score": round(user_score, 4),
                "location_score": round(location_score, 4),
                "behavior_score": round(behavior_score, 4),
                "additional_risk": round(additional_risk, 4)
            },
            "risk_factors": self._get_risk_factors(ip_address, context, device_fingerprint, user_id),
            "timestamp": datetime.utcnow().isoformat(),
            "recommendations": self._generate_recommendations(trust_level, trust_score)
        }

        # Store session
        self._sessions[session_id] = {
            **decision,
            "ip_address": ip_address,
            "device_fingerprint": device_fingerprint,
            "expires_at": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }

        # Update user baseline
        self._update_user_baseline(user_id, ip_address, device_fingerprint, behavior_score)

        return decision

    def _evaluate_device(self, fingerprint: str, user_id: str) -> float:
        if fingerprint in self._device_registry:
            device = self._device_registry[fingerprint]
            if device.get("owner") == user_id:
                return 0.95
            elif device.get("trusted"):
                return 0.7
        return 0.3  # Unknown device

    def _evaluate_user(self, user_id: str, ip: str, context: Dict) -> float:
        baseline = self._user_baselines.get(user_id, {})
        score = 0.7  # base score

        # Check login history
        if baseline.get("successful_logins", 0) > 10:
            score += 0.1
        if baseline.get("failed_mfa_attempts", 0) > 3:
            score -= 0.3
        if context.get("mfa_verified"):
            score += 0.2
        if context.get("certificate_auth"):
            score += 0.15

        return max(0.0, min(1.0, score))

    def _evaluate_location(self, ip: str, user_id: str) -> float:
        baseline = self._user_baselines.get(user_id, {})
        known_ips = baseline.get("known_ips", [])

        if ip in known_ips:
            return 0.9
        if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return 0.85  # Private network
        return 0.4  # Unknown external IP

    def _evaluate_behavior(self, user_id: str, action: str, resource: str, context: Dict) -> float:
        baseline = self._user_baselines.get(user_id, {})
        common_actions = baseline.get("common_actions", [])
        common_resources = baseline.get("common_resources", [])

        score = 0.7
        if action in common_actions:
            score += 0.15
        if resource in common_resources:
            score += 0.1
        if context.get("requests_per_minute", 0) > 100:
            score -= 0.3
        if context.get("data_volume_mb", 0) > 1000:
            score -= 0.2
        if context.get("unusual_hour"):
            score -= 0.15

        return max(0.0, min(1.0, score))

    def _check_risk_indicators(self, ip: str, context: Dict) -> float:
        risk = 0.0
        if context.get("tor_exit_node"):
            risk += self.RISK_INDICATORS["tor_detected"]
        if context.get("known_bad_ip"):
            risk += self.RISK_INDICATORS["known_bad_ip"]
        if context.get("vpn"):
            risk += self.RISK_INDICATORS["vpn_detected"]
        if context.get("failed_mfa"):
            risk += self.RISK_INDICATORS["failed_mfa"]
        return min(risk, 1.0)

    def _get_risk_factors(self, ip: str, context: Dict,
                          device_fp: str, user_id: str) -> List[str]:
        factors = []
        if device_fp not in self._device_registry:
            factors.append("Unrecognized device")
        if context.get("tor_exit_node"):
            factors.append("Tor exit node detected")
        if context.get("known_bad_ip"):
            factors.append("IP flagged as malicious")
        if context.get("failed_mfa"):
            factors.append("Recent MFA failures")
        if context.get("unusual_hour"):
            factors.append("Access at unusual hour")
        if context.get("new_location"):
            factors.append("New geographic location")
        return factors

    def _determine_trust_level(self, trust_score: float) -> str:
        if trust_score >= self.TRUST_THRESHOLDS["high"]:
            return "high"
        elif trust_score >= self.TRUST_THRESHOLDS["medium"]:
            return "medium"
        elif trust_score >= self.TRUST_THRESHOLDS["low"]:
            return "low"
        return "none"

    def _generate_recommendations(self, trust_level: str, score: float) -> List[str]:
        recs = []
        if trust_level in ["low", "none"]:
            recs.append("Require step-up MFA authentication")
            recs.append("Restrict access to sensitive resources")
        if trust_level == "medium":
            recs.append("Verify MFA before granting access")
        if score < 0.3:
            recs.append("Consider blocking and alerting SOC")
            recs.append("Initiate identity verification workflow")
        return recs

    def register_device(self, fingerprint: str, owner: str,
                        device_name: str = None, trusted: bool = False) -> Dict:
        self._device_registry[fingerprint] = {
            "fingerprint": fingerprint,
            "owner": owner,
            "device_name": device_name or "Unknown Device",
            "trusted": trusted,
            "registered_at": datetime.utcnow().isoformat()
        }
        return self._device_registry[fingerprint]

    def _update_user_baseline(self, user_id: str, ip: str,
                               device_fp: str, behavior_score: float):
        if user_id not in self._user_baselines:
            self._user_baselines[user_id] = {
                "known_ips": [], "known_devices": [],
                "common_actions": [], "common_resources": [],
                "successful_logins": 0, "failed_mfa_attempts": 0
            }
        baseline = self._user_baselines[user_id]
        if ip not in baseline["known_ips"]:
            baseline["known_ips"].append(ip)
            if len(baseline["known_ips"]) > 20:
                baseline["known_ips"] = baseline["known_ips"][-20:]
        baseline["successful_logins"] = baseline.get("successful_logins", 0) + 1

    def get_session(self, session_id: str) -> Optional[Dict]:
        return self._sessions.get(session_id)

    def invalidate_session(self, session_id: str) -> bool:
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def get_user_risk_profile(self, user_id: str) -> Dict:
        baseline = self._user_baselines.get(user_id, {})
        return {
            "user_id": user_id,
            "known_ips_count": len(baseline.get("known_ips", [])),
            "known_devices_count": len(baseline.get("known_devices", [])),
            "successful_logins": baseline.get("successful_logins", 0),
            "failed_mfa_attempts": baseline.get("failed_mfa_attempts", 0),
            "active_sessions": sum(1 for s in self._sessions.values()
                                   if s.get("user_id") == user_id)
        }


# Singleton
zero_trust = ZeroTrustEngine()
