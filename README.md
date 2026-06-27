# 🛡️ AI-Based Predictive Intrusion Prevention System (IPS)
*An intelligent, real-time cybersecurity SOC daemon built for the IEEE DataPort Hackathon.*

![AI-SOC Dashboard](https://img.shields.io/badge/Status-Active_Defense-success.svg)
![Python](https://img.shields.io/badge/Python-3.12-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-GNN-EE4C2C.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-FF4B4B.svg)

## 📌 Overview
This project transforms a standard machine learning pipeline into a **production-grade Active Intrusion Prevention System (IPS)** natively integrated with the Windows Operating System.

Instead of just passively classifying static CSV datasets, this system actively sniffs live network traffic using `cicflowmeter`, computes 84 complex flow features in real-time, and evaluates them against an advanced **AI Ensemble Engine**. If a critical threat (like a DDoS or Port Scan) is detected, the AI bypasses human intervention and instantly rewrites Windows Defender Firewall rules to sever the attacker's connection.

---

## ✨ Key Features
* **🔴 Live Packet Capture & Analysis:** Real-time TCP/UDP flow extraction directly from your Wi-Fi/Ethernet adapter.
* **🧠 Advanced AI Ensemble:** Combines XGBoost, Graph Attention Networks (GAT), Long Short-Term Memory (LSTM), and Isolation Forests to generate a unified 0-100% Risk Score.
* **🛡️ Active Defense (IPS):** Automatically executes native `netsh advfirewall` commands to block malicious IPs upon critical threat detection.
* **🔔 Native Desktop Alerts:** Uses `win10toast` to push Windows Desktop pop-ups for high-risk anomalies.
* **📊 Next-Gen SOC Dashboard:** A beautifully styled Streamlit interface featuring live traffic streaming, network graph visualization, MITRE ATT&CK mapping, and Explainable AI (SHAP).

---

## 🏗️ Architecture

1. **Sniffer Daemon (`live_capture/sniffer.py`)**  
   Hooks into the network adapter, intercepts packets via Scapy, and mathematically extracts CIC-IDS-2017 features on the fly.
2. **Inference Engine (`live_capture/inference.py`)**  
   Normalizes the raw live features and passes them through the AI models to predict the attack vector and calculate risk.
3. **Defense Module (`live_capture/firewall.py`)**  
   Triggered by the Inference Engine. Communicates directly with the Windows OS to sever connections from hostile IP addresses.
4. **Asynchronous SQLite Stream (`live_capture/database.py`)**  
   Decouples the heavy packet sniffing loop from the frontend by streaming risk assessments into a lightweight local database.
5. **Streamlit Frontend (`dashboard/app.py`)**  
   Reads from the database in real-time, providing an intuitive, auto-refreshing UI for Security Analysts.

---

## 🚀 Installation & Usage

### Prerequisites
* Windows 10/11 (Required for native Firewall IPS functionality)
* Npcap (Ensure it is installed in "WinPcap API-compatible mode" for live sniffing)
* Python 3.10+

### Setup
```bash
# Clone the repository
git clone https://github.com/ayushranjan28/Classification-of-Cyberattacks-in-Networked-Environments.git
cd Classification-of-Cyberattacks-in-Networked-Environments

# Install requirements
pip install -r requirements.txt
```

### Running the System
We have provided a unified one-click launcher for Windows.

1. Double click **`Start-AI-SOC.bat`**.
2. Grant Administrator Privileges (required for the AI to manage the Windows Firewall).
3. The Streamlit SOC dashboard will open automatically in your browser.
4. The Python background daemon will begin sniffing your active network adapter and actively defending your machine!

---

## 🧪 Model Training Pipeline
If you wish to retrain the models from scratch using the IEEE DataPort datasets:
```bash
python main.py
```
This script runs the entire end-to-end pipeline:
1. Loads and balances the MSCAD / ML-CVE datasets.
2. Normalizes numerical features via StandardScaling.
3. Trains multiple Classifiers, Graph Neural Networks, and Temporal models.
4. Serializes the best performers into the `saved_models/` directory for use by the Live Sniffer.

---

## 🤝 Developed By
**Ayush Ranjan**  
*Built for the IEEE DataPort Hackathon 2025.*
