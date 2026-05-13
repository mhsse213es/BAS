with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/wwwroot/index.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

replacements = [
    ("let agents = [];", "var agents = [];"),
    ("let reports = {};", "var reports = {};"),
    ("let selected = null; // currently selected agentId", "var selected = null;"),
    ("let connection = null;", "var connection = null;"),
    ("let patchStatuses = {};", "var patchStatuses = {};"),
    ("let currentView = 'dashboard'; // 'dashboard' or 'systemTree'", "var currentView = 'dashboard';"),
    ("let globalCharts = {};", "var globalCharts = {};"),
    ("let showDeltaOnly = false; // Toggle for Delta views", "var showDeltaOnly = false;"),
]

for old, new in replacements:
    if old in content:
        content = content.replace(old, new, 1)
        print(f"Replaced: {old[:60]}")
    else:
        print(f"NOT FOUND: {old[:60]}")

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/wwwroot/index.html', 'w', encoding='utf-8') as f:
    f.write(content)

print("Done.")
