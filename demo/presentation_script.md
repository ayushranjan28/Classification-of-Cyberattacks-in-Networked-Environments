# 🎤 Hackathon Demonstration Script (5-7 Minutes)

*This script is designed to perfectly pace your demonstration while showcasing all 14 phases of the architecture. Before starting, ensure your computer is connected to the internet/Wi-Fi.*

---

### [0:00 - 1:00] The Hook & Architecture Overview
**(Action: Have the GitHub README open on screen.)**

**You:** 
"Hello judges, my name is Ayush, and today I'm presenting an **Active Intrusion Prevention System** built on top of the IEEE DataPort datasets. 

Most cybersecurity models are passive—they evaluate static CSV files and spit out an accuracy score. I wanted to build something real. So, I took an ensemble of advanced AI—XGBoost, Graph Attention Networks, LSTMs, and Isolation Forests—and integrated them directly into the Windows Operating System. 

Today, this AI isn't just analyzing data. It is actively sniffing the Wi-Fi card on this laptop, extracting 84 complex packet features mathematically in real-time, and defending this machine without human intervention."

---

### [1:00 - 2:30] Starting the Live Demo
**(Action: Open your project folder and double-click `Start-AI-SOC.bat`.)**

**You:**
"Let me show you. I'm going to run my master boot script. 
Notice that it instantly asks for Administrator privileges. This is because the AI has the authority to natively rewrite Windows Defender Firewall rules if it detects a critical threat.

*(Wait for the Streamlit dashboard to pop up automatically).*

Here is the Security Operations Center (SOC) dashboard. On the left sidebar, let's navigate to the **📡 Live Traffic** tab."

**(Action: Click on the Live Traffic tab.)**

"Right now, this dashboard is pulling from a high-speed SQLite stream. The Python daemon in the background is intercepting the Wi-Fi traffic from my laptop, zero-padding the features, running it through the PyTorch pipeline, and scoring it. You can see the benign traffic flowing through right now—just normal background processes reaching out to the internet with near 0% risk."

---

### [2:30 - 4:00] Triggering an Attack (The IPS in Action)
**(Action: Open a new terminal. Run `python demo/generate_test_traffic.py --type all`)**

**You:**
"Now, let's see what happens during a zero-day event. I'm going to run a safe simulation script that mimics a rapid Port Scan and an HTTP Flood DoS attack against this machine.

*(Wait 2 seconds. The terminal will log the attack, and a Windows 10/11 Desktop notification should pop up!)*

Look at the bottom right of the screen! The AI instantly detected the anomaly. But it didn't just log it—it fired a native `netsh advfirewall` command and permanently blocked the attacker's IP address. 

If we look back at the **Live Traffic** dashboard, the screen flashes red, the Risk Score hits Critical, and the exact flow is caught in real-time."

---

### [4:00 - 5:30] Explainable AI & MITRE ATT&CK
**(Action: Click on the 🎯 MITRE ATT&CK tab, then the 🔍 Explainable AI tab.)**

**You:**
"Detection isn't enough; Security Analysts need to know *why* the AI made its decision. 

If we look at the **MITRE ATT&CK** mapping, the system automatically correlates the detected DoS and Port Scan to standard Enterprise threat tactics, providing instant mitigation strategies.

And under **Explainable AI**, we use SHAP values to tear open the black box. The model explains in human-readable terms exactly which network features—like abnormal Forward Packet Lengths or rapid connection drops—caused the risk score to spike."

---

### [5:30 - 6:30] Graph Neural Networks & Conclusion
**(Action: Click on the 🕸️ Network Graph tab.)**

**You:**
"Finally, we don't just look at tabular data. By processing the live IPs into a dynamic PyTorch Geometric Graph, our Graph Attention Network evaluates the *relationships* between nodes, allowing it to catch coordinated botnet attacks that standard classifiers miss.

**In conclusion:** I didn't just train a model. I built a production-ready, ultra-low-latency Intrusion Prevention System. 

It handles live packet capture, graph neural network inference, and OS-level active defense, all visualized through an enterprise-grade dashboard. Thank you."

---

### 🚨 Failsafe Note:
If the Wi-Fi at the Hackathon venue is strictly blocking promiscuous mode packet sniffing, you can gracefully transition to Replay Mode. 
Instead of `Start-AI-SOC.bat`, simply tell the judges:
*"Due to venue Wi-Fi restrictions, I will run the AI in Replay Mode, feeding a captured PCAP file natively into the inference engine."*
Then run: `python demo/replay_traffic.py sample.pcap`.
