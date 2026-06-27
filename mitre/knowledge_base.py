"""
MITRE ATT&CK knowledge base loader and query interface.
Loads MitreEnterprise.csv and attackmitre.csv.
"""
import pandas as pd
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import MITRE_ENTERPRISE_CSV, ATTACK_MITRE_CSV
from utils.logger import get_logger

log = get_logger(__name__)


class MitreKnowledgeBase:
    """MITRE ATT&CK Enterprise knowledge base."""

    def __init__(self):
        self.enterprise_df = None
        self.attack_df = None
        self.techniques = {}
        self.tactics = {}

    def load(self):
        """Load MITRE CSV files."""
        log.info("📚 Loading MITRE ATT&CK knowledge base...")

        # Load MitreEnterprise
        self.enterprise_df = pd.read_csv(MITRE_ENTERPRISE_CSV, encoding="utf-8")
        self.enterprise_df.columns = self.enterprise_df.columns.str.strip()
        log.info(f"  MitreEnterprise: {len(self.enterprise_df)} rows")

        # Build technique lookup
        for _, row in self.enterprise_df.iterrows():
            tid = str(row.get("Tactic ID", "")).strip()
            if tid.startswith("T"):
                self.techniques[tid] = {
                    "id": tid,
                    "name": str(row.get("Tactic Name", "")).strip(),
                    "description": str(row.get("Description", "")).strip()[:500],
                    "mitigation": str(row.get("Mitigation Steps", "")).strip()[:500],
                }

        log.info(f"  Loaded {len(self.techniques)} techniques")

        # Load attackmitre
        self.attack_df = pd.read_csv(ATTACK_MITRE_CSV, encoding="utf-8")
        self.attack_df.columns = self.attack_df.columns.str.strip()
        log.info(f"  AttackMitre: {len(self.attack_df)} rows")

        return self

    def get_technique(self, technique_id: str) -> dict:
        """Look up a MITRE technique by ID."""
        return self.techniques.get(technique_id, {
            "id": technique_id,
            "name": "Unknown",
            "description": "Technique not found in knowledge base",
            "mitigation": "No mitigation data available"
        })

    def search_techniques(self, query: str, limit: int = 10) -> list:
        """Search techniques by name or description."""
        results = []
        query_lower = query.lower()
        for tid, info in self.techniques.items():
            if (query_lower in info["name"].lower() or
                query_lower in info["description"].lower()):
                results.append(info)
                if len(results) >= limit:
                    break
        return results

    def get_apt_groups(self) -> list:
        """Get unique APT groups from attack mapping."""
        if self.attack_df is not None:
            return self.attack_df["APT Group Name"].unique().tolist()
        return []

    def get_group_techniques(self, group_name: str) -> list:
        """Get techniques used by a specific APT group."""
        if self.attack_df is None:
            return []
        group_rows = self.attack_df[self.attack_df["APT Group Name"] == group_name]
        techniques = set()
        for _, row in group_rows.iterrows():
            tech_str = str(row.get("Group Techniques", ""))
            for t in tech_str.split(";"):
                t = t.strip()
                if t.startswith("T"):
                    techniques.add(t)
        return list(techniques)
