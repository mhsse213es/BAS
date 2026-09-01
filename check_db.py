import psycopg2
import json

try:
    conn = psycopg2.connect("postgres://bas_user:bas_pass@localhost:5433/bas_platform?sslmode=disable")
    cur = conn.cursor()
    
    print("--- Campaigns ---")
    cur.execute("SELECT id, name, scenario_name, created_at, stopped_at, completed_at, skips FROM campaigns ORDER BY created_at DESC LIMIT 5")
    rows = cur.fetchall()
    for r in rows:
        print(f"ID: {r[0]} | Name: {r[1]} | Scenario: {r[2]} | CreatedAt: {r[3]} | StoppedAt: {r[4]} | CompletedAt: {r[5]}")
        skips = json.loads(bytes(r[6])) if r[6] else []
        print(f"  Skips: {skips}")
        
        # Get child runs
        cur.execute("SELECT id, agent_id, status FROM scenario_runs WHERE campaign_id = %s", (r[0],))
        runs = cur.fetchall()
        for run in runs:
            print(f"    Child Run: {run[0]} | Agent: {run[1]} | Status: {run[2]}")
            
    conn.close()
except Exception as e:
    print(f"Error checking DB: {e}")
