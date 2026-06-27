import sqlite3
conn = sqlite3.connect('data/live_traffic.db')

total = conn.execute('SELECT count(1) FROM live_flows').fetchone()[0]
print(f"Total flows: {total}")

# Check for attack flows
attacks = conn.execute("SELECT count(1) FROM live_flows WHERE predicted_attack != 'Normal'").fetchone()[0]
print(f"Attack flows: {attacks}")

# Check for example.com (93.184.215.14)
ddos = conn.execute("SELECT count(1) FROM live_flows WHERE dst_ip = '93.184.215.14' OR src_ip = '93.184.215.14'").fetchone()[0]
print(f"Flows to/from example.com: {ddos}")

# Show last 15 flows
print("\nLast 15 flows:")
rows = conn.execute('SELECT timestamp, src_ip, dst_ip, dst_port, predicted_attack, risk_label FROM live_flows ORDER BY id DESC LIMIT 15').fetchall()
for r in rows:
    print(r)

conn.close()
