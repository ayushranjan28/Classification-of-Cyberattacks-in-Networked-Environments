"""
Central configuration for the AI-Based Predictive Intrusion Detection System.
All paths, hyperparameters, and constants are defined here.
"""
import os
from pathlib import Path

# ─── Base Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent.resolve()
DATA_ROOT = PROJECT_ROOT.parent  # c:\Users\ayush\Desktop\dataport

# Dataset paths
MSCAD_CSV = DATA_ROOT / "MSCAD_Dataset" / "CSV" / "MSCAD.csv"
ML_CVE_DIR = DATA_ROOT / "MachineLearningCVE"
TRAFFIC_DIR = DATA_ROOT / "TrafficLabelling"
MITRE_ENTERPRISE_CSV = DATA_ROOT / "MitreEnterprise.csv"
ATTACK_MITRE_CSV = DATA_ROOT / "attackmitre.csv"

# Output paths
SAVED_MODELS_DIR = PROJECT_ROOT / "saved_models"
REPORTS_DIR = PROJECT_ROOT / "reports"
PREPROCESSED_DIR = PROJECT_ROOT / "data" / "preprocessed"

for d in [SAVED_MODELS_DIR, REPORTS_DIR, PREPROCESSED_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ─── MSCAD Label Distribution ─────────────────────────────────────────────────
# Brute_Force: 88502, Normal: 28502, Port_Scan: 11081,
# HTTP_DDoS: 641, ICMP_Flood: 45, Web_Crwling: 28
ATTACK_LABELS = [
    "Normal", "Brute_Force", "Port_Scan", "HTTP_DDoS", "ICMP_Flood", "Web_Crwling"
]

# ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
ATTACK_TO_MITRE = {
    "Brute_Force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        "next_techniques": ["T1078 (Valid Accounts)", "T1021 (Remote Services)", "T1076 (RDP)"],
        "mitigations": [
            "Enable Multi-Factor Authentication (MFA)",
            "Implement account lockout policies after failed attempts",
            "Block source IP at firewall",
            "Reset compromised credentials immediately",
            "Monitor SMB and RDP for lateral movement"
        ]
    },
    "Port_Scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": "Adversaries may scan for services running on remote hosts to identify exploitable targets.",
        "next_techniques": ["T1190 (Exploit Public-Facing App)", "T1133 (External Remote Services)"],
        "mitigations": [
            "Implement network segmentation",
            "Deploy IDS/IPS signatures for scan detection",
            "Rate-limit connection attempts per source IP",
            "Block known scanner tools at perimeter",
            "Enable host-based firewall rules"
        ]
    },
    "HTTP_DDoS": {
        "technique_id": "T1499",
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform DoS attacks to degrade or block availability of targeted resources.",
        "next_techniques": ["T1498 (Network DoS)", "T1489 (Service Stop)"],
        "mitigations": [
            "Deploy DDoS mitigation services (e.g., Cloudflare, AWS Shield)",
            "Implement rate limiting on web servers",
            "Enable connection throttling",
            "Use CDN for traffic absorption",
            "Set up auto-scaling for critical services"
        ]
    },
    "ICMP_Flood": {
        "technique_id": "T1498",
        "technique_name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform network-level DoS attacks using ICMP floods to overwhelm targets.",
        "next_techniques": ["T1499 (Endpoint DoS)", "T1485 (Data Destruction)"],
        "mitigations": [
            "Rate-limit ICMP traffic at network perimeter",
            "Configure ICMP flood protection on firewalls",
            "Deploy upstream DDoS scrubbing",
            "Disable ICMP echo replies on critical servers",
            "Implement BCP38 anti-spoofing"
        ]
    },
    "Web_Crwling": {
        "technique_id": "T1595",
        "technique_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "description": "Adversaries may scan websites to gather information for targeting.",
        "next_techniques": ["T1190 (Exploit Public-Facing App)", "T1589 (Gather Victim Identity)"],
        "mitigations": [
            "Implement rate limiting on web applications",
            "Deploy CAPTCHA on sensitive endpoints",
            "Use robots.txt and WAF rules to block scrapers",
            "Monitor for unusual crawling patterns",
            "Implement IP reputation scoring"
        ]
    },
    "Normal": {
        "technique_id": "N/A",
        "technique_name": "Benign Traffic",
        "tactic": "N/A",
        "description": "Normal network traffic with no malicious indicators.",
        "next_techniques": [],
        "mitigations": ["No action required — traffic is benign"]
    }
}

# ─── CIC-IDS2017 Label Mapping (for MachineLearningCVE / TrafficLabelling) ───
CICIDS_LABEL_MAP = {
    "BENIGN": "Normal",
    "FTP-Patator": "Brute_Force",
    "SSH-Patator": "Brute_Force",
    "DoS slowloris": "HTTP_DDoS",
    "DoS Slowhttptest": "HTTP_DDoS",
    "DoS Hulk": "HTTP_DDoS",
    "DoS GoldenEye": "HTTP_DDoS",
    "Heartbleed": "HTTP_DDoS",
    "Web Attack – Brute Force": "Brute_Force",
    "Web Attack – XSS": "Web_Crwling",
    "Web Attack – Sql Injection": "Web_Crwling",
    "Infiltration": "Web_Crwling",
    "Bot": "Brute_Force",
    "PortScan": "Port_Scan",
    "DDoS": "HTTP_DDoS",
}

# ─── Risk Score Thresholds ─────────────────────────────────────────────────────
RISK_THRESHOLDS = {
    "low": (0, 30),
    "medium": (31, 60),
    "high": (61, 80),
    "critical": (81, 100),
}

RISK_COLORS = {
    "low": "#22c55e",       # green
    "medium": "#eab308",    # yellow
    "high": "#f97316",      # orange
    "critical": "#ef4444",  # red
}

# ─── Model Hyperparameters ────────────────────────────────────────────────────
XGBOOST_PARAMS = {
    "n_estimators": 300,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_weight": 5,
    "objective": "multi:softprob",
    "eval_metric": "mlogloss",
    "tree_method": "hist",
    "random_state": 42,
    "n_jobs": -1,
}

LIGHTGBM_PARAMS = {
    "n_estimators": 300,
    "max_depth": 8,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "min_child_samples": 20,
    "objective": "multiclass",
    "metric": "multi_logloss",
    "random_state": 42,
    "n_jobs": -1,
    "verbose": -1,
}

CATBOOST_PARAMS = {
    "iterations": 300,
    "depth": 8,
    "learning_rate": 0.1,
    "loss_function": "MultiClass",
    "random_seed": 42,
    "verbose": 0,
}

RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": 15,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "random_state": 42,
    "n_jobs": -1,
}

# GNN parameters
GNN_PARAMS = {
    "hidden_channels": 64,
    "num_layers": 2,
    "dropout": 0.3,
    "lr": 0.005,
    "epochs": 200,
    "patience": 30,
}

# Temporal model parameters
TEMPORAL_PARAMS = {
    "sequence_length": 20,
    "hidden_dim": 128,
    "num_layers": 2,
    "num_heads": 4,
    "dropout": 0.2,
    "lr": 0.001,
    "epochs": 100,
    "batch_size": 256,
    "patience": 20,
}

# Autoencoder parameters
AUTOENCODER_PARAMS = {
    "encoding_dim": 32,
    "hidden_dims": [128, 64],
    "lr": 0.001,
    "epochs": 100,
    "batch_size": 256,
    "anomaly_percentile": 95,
    "patience": 20,
}

# Ensemble weights (initial — will be optimized)
ENSEMBLE_WEIGHTS = {
    "classifier": 0.4,
    "gnn": 0.2,
    "temporal": 0.2,
    "autoencoder": 0.2,
}

# ─── Feature Configuration ────────────────────────────────────────────────────
# Columns to drop from MSCAD (if present)
DROP_COLUMNS = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]

# Graph construction
GRAPH_TIME_WINDOW = 300  # seconds for dynamic graph windows
MAX_NODES_PER_GRAPH = 5000

# Train/Val/Test split ratios
TRAIN_RATIO = 0.70
VAL_RATIO = 0.15
TEST_RATIO = 0.15

# Sampling ratio for fast iteration (set to 1.0 for full training)
SAMPLE_RATIO = 1.0

RANDOM_STATE = 42
