"""
MITRE ATT&CK mapper: maps predicted attack labels to techniques, tactics, and mitigations.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import ATTACK_TO_MITRE
from mitre.knowledge_base import MitreKnowledgeBase
from utils.logger import get_logger

log = get_logger(__name__)


class MitreMapper:
    """Maps predicted attacks to MITRE ATT&CK framework."""

    def __init__(self, kb: MitreKnowledgeBase = None):
        self.kb = kb
        self.mapping = ATTACK_TO_MITRE

    def map_prediction(self, attack_label: str) -> dict:
        """
        Map a predicted attack label to MITRE ATT&CK information.

        Returns:
            dict with technique_id, technique_name, tactic, description,
            next_techniques, mitigations
        """
        # Direct mapping from config
        info = self.mapping.get(attack_label, self.mapping.get("Normal"))
        if info is None:
            info = {
                "technique_id": "Unknown",
                "technique_name": attack_label,
                "tactic": "Unknown",
                "description": f"No MITRE mapping found for '{attack_label}'",
                "next_techniques": [],
                "mitigations": ["Investigate and classify the attack manually"]
            }

        # Enrich with knowledge base if available
        if self.kb and info["technique_id"] != "N/A":
            kb_info = self.kb.get_technique(info["technique_id"])
            if kb_info.get("name") != "Unknown":
                info["kb_description"] = kb_info.get("description", "")
                info["kb_mitigation"] = kb_info.get("mitigation", "")

        return info

    def map_batch(self, attack_labels: list) -> list:
        """Map a batch of predictions to MITRE information."""
        return [self.map_prediction(label) for label in attack_labels]

    def get_attack_chain(self, attack_label: str) -> list:
        """
        Get the predicted attack chain (current → possible next stages).

        Returns:
            list of dicts representing the kill chain progression
        """
        current = self.map_prediction(attack_label)
        chain = [{
            "stage": "Current",
            "technique_id": current["technique_id"],
            "technique_name": current["technique_name"],
            "tactic": current["tactic"],
        }]

        for next_tech in current.get("next_techniques", []):
            # Parse "T1078 (Valid Accounts)" format
            parts = next_tech.split("(")
            tech_id = parts[0].strip()
            tech_name = parts[1].rstrip(")") if len(parts) > 1 else tech_id

            chain.append({
                "stage": "Possible Next",
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": "Predicted",
            })

        return chain

    def generate_recommendation(self, attack_label: str, risk_score: float = 0) -> dict:
        """
        Generate a comprehensive recommendation for an attack prediction.

        Returns:
            dict with attack_info, risk_level, mitigations, chain
        """
        info = self.map_prediction(attack_label)
        chain = self.get_attack_chain(attack_label)

        # Determine urgency
        if risk_score >= 81:
            urgency = "CRITICAL — Immediate action required"
        elif risk_score >= 61:
            urgency = "HIGH — Action needed within 1 hour"
        elif risk_score >= 31:
            urgency = "MEDIUM — Investigate within 4 hours"
        else:
            urgency = "LOW — Monitor and review"

        return {
            "attack_label": attack_label,
            "technique_id": info["technique_id"],
            "technique_name": info["technique_name"],
            "tactic": info["tactic"],
            "description": info["description"],
            "risk_score": risk_score,
            "urgency": urgency,
            "mitigations": info["mitigations"],
            "attack_chain": chain,
        }
