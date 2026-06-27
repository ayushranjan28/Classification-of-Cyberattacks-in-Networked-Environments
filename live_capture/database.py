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
            explanation TEXT,
            features_json TEXT
        )
    """)
    conn.commit()
    conn.close()
    log.info(f"Initialized live traffic database at {DB_PATH}")

def insert_flow(src_ip: str, src_port: int, dst_ip: str, dst_port: int, 
                protocol: str, risk_score: float, risk_label: str, 
                predicted_attack: str, confidence: float, explanation: str, features: dict):
    """Insert a processed flow prediction into the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("""
        INSERT INTO live_flows (
            timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
            risk_score, risk_label, predicted_attack, confidence, explanation, features_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (local_time, src_ip, src_port, dst_ip, dst_port, protocol, 
          risk_score, risk_label, predicted_attack, confidence, explanation, json.dumps(features)))
    
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
            timestamp,
            src_ip, src_port, dst_ip, dst_port, protocol, 
            risk_score, risk_label, predicted_attack, confidence, explanation, features_json
        FROM live_flows 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_database_stats():
    """Retrieve true total counts from the database instead of relying on frontend limits."""
    if not DB_PATH.exists():
        return {"total": 0, "threats": 0, "critical": 0}
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM live_flows")
    total = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM live_flows WHERE predicted_attack != 'Normal'")
    threats = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM live_flows WHERE risk_label = 'Critical'")
    critical = cursor.fetchone()[0]
    
    conn.close()
    return {"total": total, "threats": threats, "critical": critical}

def update_flow_attack(src_ip: str, src_port: int, dst_ip: str, dst_port: int,
                       predicted_attack: str, risk_score: float, risk_label: str,
                       confidence: float):
    """Update the most recent matching flow with behavioral detection results."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        UPDATE live_flows 
        SET predicted_attack = ?, risk_score = ?, risk_label = ?, confidence = ?
        WHERE id = (
            SELECT id FROM live_flows 
            WHERE src_ip = ? AND src_port = ? AND dst_ip = ? AND dst_port = ?
            ORDER BY id DESC LIMIT 1
        )
    """, (predicted_attack, risk_score, risk_label, confidence,
          src_ip, src_port, dst_ip, dst_port))
    
    conn.commit()
    conn.close()

