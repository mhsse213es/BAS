import sys
sys.stdout.reconfigure(encoding='utf-8')

path = r"C:\Users\Administrator\Downloads\Audspect_Cloud\orchestrator\wwwroot\index.html"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# Let's inspect tab-remediation and tab-findings block
lines = content.splitlines()
in_tab = False
for i, line in enumerate(lines, 1):
    if 'id="tab-findings"' in line or 'id="tab-remediation"' in line or 'id="tab-campaigns"' in line:
        in_tab = True
        print(f"=== START {line.strip()} (line {i}) ===")
    elif in_tab and 'id="tab-' in line:
        in_tab = False
        print(f"=== END (line {i}) ===")
    elif in_tab:
        if "class=" in line or "style=" in line:
            print(f"{i}: {line.strip()}")
