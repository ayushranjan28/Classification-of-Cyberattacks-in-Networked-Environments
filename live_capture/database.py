import sqlite3
import json
from pathlib import Path
from datetime import datetime
import sys

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))
from config import PROJECT_ROOT
from utils.logger import get_logger

log = get_logger(__name__)

DB_PATH = PROJECT_ROOT / "data" / "live_traffic.db"

def init_db():
    """Initialize the SQLite database for live traffic."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS live_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            risk_score REAL,
            risk_label TEXT,
            predicted_attack TEXT,
            confidence REAL,
            features_json TEXT
        )
    """)
    conn.commit()
    conn.close()
    log.info(f"Initialized live traffic database at {DB_PATH}")

def insert_flow(src_ip: str, src_port: int, dst_ip: str, dst_port: int, 
                protocol: str, risk_score: float, risk_label: str, 
                predicted_attack: str, confidence: float, features: dict):
    """Insert a processed flow prediction into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO live_flows (
            src_ip, src_port, dst_ip, dst_port, protocol,
            risk_score, risk_label, predicted_attack, confidence, features_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (src_ip, src_port, dst_ip, dst_port, protocol, 
          risk_score, risk_label, predicted_attack, confidence, json.dumps(features)))
    
    conn.commit()
    conn.close()

def get_recent_flows(limit: int = 50):
    """Retrieve the most recent network flows from the database."""
    if not DB_PATH.exists():
        return []
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            id, 
            datetime(timestamp, 'localtime') as timestamp,
            src_ip, src_port, dst_ip, dst_port, protocol, 
            risk_score, risk_label, predicted_attack, confidence, features_json
        FROM live_flows 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]
