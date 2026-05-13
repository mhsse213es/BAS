"""Generates Phase1_Testing_Guide.docx in the project root."""
from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

OUT = r"C:\Users\Administrator\Downloads\Audspect_Cloud\Phase1_Testing_Guide.docx"

# ── Palette — stored as (r, g, b) tuples ─────────────────────────────────────
DARK_BG   = (0x0A, 0x0C, 0x0F)
TEAL      = (0x00, 0xD4, 0xAA)
RED_COL   = (0xFF, 0x4F, 0x5A)
AMBER     = (0xF0, 0xA5, 0x00)
WHITE     = (0xFF, 0xFF, 0xFF)
LIGHT_TXT = (0xE2, 0xE6, 0xEA)
DIM_TXT   = (0x7A, 0x85, 0x90)
CODE_BG   = (0x11, 0x14, 0x18)
PASS_GRN  = (0x00, 0xC8, 0x7A)
HEAD_BG   = (0x16, 0x1A, 0x20)
ROW_ALT   = (0x1C, 0x21, 0x28)
ROW_NORM  = (0x11, 0x14, 0x18)

def rgb(t): return RGBColor(t[0], t[1], t[2])
def hex6(t): return f'{t[0]:02X}{t[1]:02X}{t[2]:02X}'

doc = Document()

# ── Page margins ──────────────────────────────────────────────────────────────
for section in doc.sections:
    section.page_width  = Inches(8.5)
    section.page_height = Inches(11)
    section.left_margin = section.right_margin = Inches(1)
    section.top_margin  = section.bottom_margin = Inches(0.9)

# ── Base styles ───────────────────────────────────────────────────────────────
style = doc.styles['Normal']
style.font.name = 'Calibri'
style.font.size = Pt(10)
style.font.color.rgb = rgb(LIGHT_TXT)

def set_para_bg(para, rgb):
    """Set paragraph background shading."""
    pPr = para._p.get_or_add_pPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex6(rgb))
    pPr.append(shd)

def set_cell_bg(cell, rgb):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), hex6(rgb))
    tcPr.append(shd)

def add_heading(text, level=1, color=None):
    if color is None: color = TEAL
    p = doc.add_paragraph()
    set_para_bg(p, DARK_BG)
    run = p.add_run(text)
    sizes = {1: 18, 2: 14, 3: 11}
    run.font.size = Pt(sizes.get(level, 11))
    run.font.bold = True
    run.font.color.rgb = rgb(color)
    run.font.name = 'Calibri'
    p.paragraph_format.space_before = Pt(14 if level == 1 else 8)
    p.paragraph_format.space_after  = Pt(4)
    return p

def add_body(text, color=None, bold=False, italic=False, indent=False):
    if color is None: color = LIGHT_TXT
    p = doc.add_paragraph()
    set_para_bg(p, DARK_BG)
    run = p.add_run(text)
    run.font.size  = Pt(10)
    run.font.color.rgb = rgb(color)
    run.font.bold  = bold
    run.font.italic = italic
    run.font.name  = 'Calibri'
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after  = Pt(3)
    if indent:
        p.paragraph_format.left_indent = Inches(0.3)
    return p

def add_bullet(text, color=None, level=0):
    if color is None: color = LIGHT_TXT
    p = doc.add_paragraph(style='List Bullet')
    set_para_bg(p, DARK_BG)
    run = p.add_run(text)
    run.font.size  = Pt(10)
    run.font.color.rgb = rgb(color)
    run.font.name  = 'Calibri'
    p.paragraph_format.left_indent  = Inches(0.3 + level * 0.2)
    p.paragraph_format.space_before = Pt(1)
    p.paragraph_format.space_after  = Pt(2)
    return p

def add_code(lines, comment=''):
    if comment:
        p = doc.add_paragraph()
        set_para_bg(p, CODE_BG)
        r = p.add_run(f'  # {comment}')
        r.font.name  = 'Courier New'
        r.font.size  = Pt(8.5)
        r.font.color.rgb = rgb(DIM_TXT)
        r.font.italic = True
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after  = Pt(0)

    for i, line in enumerate(lines):
        p = doc.add_paragraph()
        set_para_bg(p, CODE_BG)
        r = p.add_run(f'  {line}')
        r.font.name  = 'Courier New'
        r.font.size  = Pt(8.5)
        # Colour keywords / comments
        if line.strip().startswith('#'):
            r.font.color.rgb = rgb(DIM_TXT)
            r.font.italic = True
        elif line.strip().startswith('$') or line.strip().startswith('export'):
            r.font.color.rgb = rgb(TEAL)
        elif 'Expected' in line or 'should' in line:
            r.font.color.rgb = rgb(PASS_GRN)
            r.font.italic = True
        else:
            r.font.color.rgb = rgb(LIGHT_TXT)
        p.paragraph_format.space_before = Pt(0)
        p.paragraph_format.space_after  = Pt(0 if i < len(lines)-1 else 6)
        p.paragraph_format.left_indent  = Inches(0)

def add_table(headers, rows, col_widths=None):
    t = doc.add_table(rows=1+len(rows), cols=len(headers))
    t.alignment = WD_TABLE_ALIGNMENT.LEFT
    # Header row
    hdr = t.rows[0]
    for i, h in enumerate(headers):
        cell = hdr.cells[i]
        set_cell_bg(cell, HEAD_BG)
        p = cell.paragraphs[0]
        p.clear()
        run = p.add_run(h)
        run.font.bold  = True
        run.font.color.rgb = rgb(TEAL)
        run.font.size  = Pt(9.5)
        run.font.name  = 'Calibri'
    # Data rows
    for ri, row in enumerate(rows):
        bg = ROW_NORM if ri % 2 == 0 else ROW_ALT
        for ci, val in enumerate(row):
            cell = t.rows[ri+1].cells[ci]
            set_cell_bg(cell, bg)
            p = cell.paragraphs[0]
            p.clear()
            color = LIGHT_TXT
            if val in ('✓ Yes', 'Pass', 'Good', 'Excellent', 'Recommended', '100% portable'):
                color = PASS_GRN
            elif val in ('✗ No',):
                color = RED_COL
            elif val in ('Yes — it IS a Windows binary',):
                color = TEAL
            run = p.add_run(val)
            run.font.color.rgb = rgb(color)
            run.font.size  = Pt(9.5)
            run.font.name  = 'Calibri'
    # Column widths
    if col_widths:
        for i, w in enumerate(col_widths):
            for row in t.rows:
                row.cells[i].width = Inches(w)
    doc.add_paragraph()  # spacer

def add_divider():
    p = doc.add_paragraph()
    set_para_bg(p, DARK_BG)
    run = p.add_run('─' * 80)
    run.font.color.rgb = rgb(DIM_TXT)
    run.font.size = Pt(7)
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(4)

def add_note(text, kind='info'):
    color = {'info': TEAL, 'warn': AMBER, 'danger': RED_COL}.get(kind, TEAL)
    prefix = {'info': 'ℹ  NOTE', 'warn': '⚠  WARNING', 'danger': '✖  IMPORTANT'}.get(kind, 'NOTE')
    p = doc.add_paragraph()
    bg = (0x0D, 0x18, 0x22) if kind == 'info' else (0x1E, 0x16, 0x07)
    set_para_bg(p, bg)
    r1 = p.add_run(f'{prefix}:  ')
    r1.font.bold  = True
    r1.font.color.rgb = rgb(color)
    r1.font.size  = Pt(9.5)
    r1.font.name  = 'Calibri'
    r2 = p.add_run(text)
    r2.font.color.rgb = rgb(LIGHT_TXT)
    r2.font.size  = Pt(9.5)
    r2.font.name  = 'Calibri'
    p.paragraph_format.space_before = Pt(4)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.left_indent  = Inches(0.15)

# Set document background (body xml)
body = doc.element.body
sectPr = body.find(qn('w:sectPr'))
if sectPr is None:
    sectPr = OxmlElement('w:sectPr')
    body.append(sectPr)

# ═════════════════════════════════════════════════════════════════════════════
#  COVER
# ═════════════════════════════════════════════════════════════════════════════
p = doc.add_paragraph()
set_para_bg(p, DARK_BG)
p.paragraph_format.space_before = Pt(30)

p = doc.add_paragraph()
set_para_bg(p, DARK_BG)
r = p.add_run('AUDSPECT BAS PLATFORM')
r.font.name = 'Calibri'
r.font.size = Pt(26)
r.font.bold = True
r.font.color.rgb = rgb(TEAL)
p.alignment = WD_ALIGN_PARAGRAPH.CENTER

p = doc.add_paragraph()
set_para_bg(p, DARK_BG)
r = p.add_run('Phase 1 — Testing Guide')
r.font.name = 'Calibri'
r.font.size = Pt(16)
r.font.color.rgb = rgb(LIGHT_TXT)
p.alignment = WD_ALIGN_PARAGRAPH.CENTER

p = doc.add_paragraph()
set_para_bg(p, DARK_BG)
r = p.add_run('Go Orchestrator  ·  Python API  ·  PostgreSQL  ·  WSL2 Ubuntu 24.04')
r.font.name   = 'Calibri'
r.font.size   = Pt(10)
r.font.color.rgb = rgb(DIM_TXT)
r.font.italic = True
p.alignment   = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_before = Pt(6)

doc.add_paragraph().paragraph_format.space_before = Pt(20)
add_divider()

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 0 — UNDERSTANDING THE SETUP
# ═════════════════════════════════════════════════════════════════════════════
add_heading('0.  Understanding the Setup — Windows vs Ubuntu', 1)
add_body(
    'You have two components: the server (orchestrator + API) which will run on Ubuntu in production, '
    'and the agent which runs on Windows endpoints. Testing the server on Windows is valid because the '
    'server code is 100% cross-platform. WSL2 gives you a real Ubuntu environment on your Windows machine '
    'that mirrors production exactly.',
    color=LIGHT_TXT
)
doc.add_paragraph()

add_table(
    ['Component', 'Runs on (Production)', 'Windows-specific code?', 'Safe to test on Windows?'],
    [
        ['Go Orchestrator',  'Ubuntu server (k3s)',      '✗ No — pure Go, cross-platform', '100% portable'],
        ['Python API',       'Ubuntu server (k3s)',      '✗ No — pure Python',             '100% portable'],
        ['Go Agent',         'Windows endpoints',        '✓ Yes — Registry, WMI, Win32',   'Yes — it IS a Windows binary'],
    ],
    col_widths=[1.6, 1.8, 2.3, 1.7]
)

add_note(
    'WSL2 (Windows Subsystem for Linux 2) runs a real Ubuntu 24.04 kernel on your Windows 10 machine. '
    'Services started inside WSL2 are reachable from Windows on localhost. This is the recommended '
    'test environment as it is identical to production Ubuntu.',
    kind='info'
)

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — ENABLE WSL2
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 1 — Enable WSL2 and Install Ubuntu 24.04', 1)
add_body('Open PowerShell as Administrator and run:')
add_code(['wsl --install -d Ubuntu-24.04'], comment='PowerShell (Admin)')
add_body('Reboot when prompted. After reboot, Ubuntu opens automatically and asks you to create a username and password (e.g., basdev / any password).')
add_body('Verify WSL2 is running (not WSL1):')
add_code(
    ['wsl -l -v',
     '# Expected output:',
     '# NAME            STATE    VERSION',
     '# Ubuntu-24.04    Running  2      ← must be VERSION 2'],
    comment='PowerShell'
)
add_note('Your Windows 10 build 19045 (22H2) fully supports WSL2. If wsl --install fails, enable virtualisation in BIOS first.', kind='info')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — INSTALL DEPENDENCIES IN WSL2
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 2 — Install Dependencies Inside WSL2', 1)
add_body('Open the WSL2 Ubuntu terminal (search "Ubuntu 24.04" in Start, or run wsl -d Ubuntu-24.04 in PowerShell). All commands in this section run inside WSL2.')

add_heading('2a. System update', 2)
add_code(
    ['sudo apt-get update && sudo apt-get upgrade -y'],
    comment='WSL2 Ubuntu terminal'
)

add_heading('2b. Install Go 1.22', 2)
add_code([
    'wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz',
    'sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz',
    "echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc",
    'source ~/.bashrc',
    'go version',
    '# Expected: go version go1.22.5 linux/amd64',
], comment='WSL2 Ubuntu terminal')

add_heading('2c. Install Python 3.12', 2)
add_note('Use Python 3.12, not 3.14 — better binary wheel compatibility for asyncpg and bcrypt.', kind='warn')
add_code([
    'sudo apt-get install -y python3.12 python3.12-venv python3-pip',
    'python3.12 --version',
    '# Expected: Python 3.12.x',
], comment='WSL2 Ubuntu terminal')

add_heading('2d. Install PostgreSQL 16', 2)
add_code([
    'sudo apt-get install -y postgresql-16',
    'sudo service postgresql start',
    'sudo -u postgres psql -c "SELECT version();"',
    '# Expected: PostgreSQL 16.x on x86_64-pc-linux-gnu',
], comment='WSL2 Ubuntu terminal')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — DATABASE SETUP
# ═════════════════════════════════════════════════════════════════════════════
add_heading("Step 3 — Create the Database", 1)
add_code([
    "sudo -u postgres psql << 'EOF'",
    "CREATE USER bas_user WITH PASSWORD 'TestPass123!';",
    "CREATE DATABASE bas_platform OWNER bas_user ENCODING 'UTF8';",
    "GRANT ALL PRIVILEGES ON DATABASE bas_platform TO bas_user;",
    r"\q",
    'EOF',
    '',
    '# Verify connection',
    "psql -h localhost -U bas_user -d bas_platform -c \"SELECT 1 AS ok;\"",
    '# Expected: ok = 1',
], comment='WSL2 Ubuntu terminal')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — PROJECT FILES
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 4 — Access Project Files from WSL2', 1)
add_body('Your Windows files are automatically mounted at /mnt/c/ in WSL2 — no copying needed.')
add_code([
    'cd /mnt/c/Users/Administrator/Downloads/Audspect_Cloud',
    'ls',
    '# You should see: orchestrator/  api/  scenarios/  helm/  scripts/  BAS.Agent/  BAS.Server/',
], comment='WSL2 Ubuntu terminal')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — RUN GO ORCHESTRATOR
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 5 — Configure and Run the Go Orchestrator', 1)

add_heading('5a. Update config.json', 2)
add_code([
    'cd /mnt/c/Users/Administrator/Downloads/Audspect_Cloud/orchestrator',
    '',
    "cat > config.json << 'EOF'",
    '{',
    '  "database_url": "postgres://bas_user:TestPass123!@localhost:5432/bas_platform",',
    '  "jwt_secret":   "dev-secret-change-in-prod-min32chars!!",',
    '  "http_port":    9000,',
    '  "scenarios_dir": "/mnt/c/Users/Administrator/Downloads/Audspect_Cloud/scenarios"',
    '}',
    'EOF',
], comment='WSL2 Ubuntu terminal')

add_heading('5b. Create wwwroot placeholder', 2)
add_code([
    'mkdir -p wwwroot',
    "echo '<html><body>BAS Orchestrator - Phase 1</body></html>' > wwwroot/index.html",
], comment='WSL2 Ubuntu terminal')

add_heading('5c. Download dependencies and build', 2)
add_code([
    'go mod tidy',
    '# Downloads: pgx, chi, jwt, gorilla/websocket, yaml, bcrypt (~1 min)',
    '',
    'go build -o bas-orchestrator ./cmd/server',
    '# Produces a Linux binary — identical to what runs in production k3s',
], comment='WSL2 Ubuntu terminal')

add_heading('5d. Run the orchestrator', 2)
add_code([
    './bas-orchestrator config.json',
    '',
    '# Expected output:',
    '# [+] PostgreSQL connected',
    '# [+] Schema verified',
    "# [+] Default admin created — username: admin  password: ChangeMe!2024",
    '# [+] Loaded 5 scenarios from /mnt/c/.../scenarios',
    '# [*] BAS Orchestrator listening on :9000',
], comment='WSL2 Ubuntu terminal — leave this terminal open')

add_note('Keep this terminal open. The orchestrator must stay running for all subsequent tests.', kind='warn')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — TEST ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 6 — Test All API Endpoints', 1)
add_body('Open a new PowerShell window on Windows. WSL2 services are automatically accessible on localhost.')

add_heading('6a. Health check', 2)
add_code([
    'curl http://localhost:9000/health',
    '# Expected: {"status":"ok"}',
], comment='Windows PowerShell')

add_heading('6b. Login and get JWT token', 2)
add_code([
    "$body = '{\"username\":\"admin\",\"password\":\"ChangeMe!2024\"}'",
    '$resp = curl -s -X POST http://localhost:9000/api/auth/login `',
    '    -H "Content-Type: application/json" -d $body | ConvertFrom-Json',
    '$TOKEN = $resp.token',
    'Write-Host "Token: $TOKEN"',
    '# Expected: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... (long JWT string)',
], comment='Windows PowerShell')

add_heading('6c. List scenarios (confirms YAML files loaded)', 2)
add_code([
    'curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/api/scenarios | ConvertFrom-Json | Select-Object id, name',
    '',
    '# Expected: 5 scenarios',
    '# id                     name',
    '# --                     ----',
    '# ad-credential-access   Active Directory Credential Access Drill',
    '# apt36-spearphish        APT36 Spear-Phishing Kill Chain',
    '# cscrf-mii-drill         CSCRF-MII Core Control Validation Drill',
    '# ransomware-drill        Ransomware Drill (BFSI Business Continuity Test)',
    '# upi-fraud-killchain     UPI Fraud Kill Chain',
], comment='Windows PowerShell')

add_heading('6d. List agents (empty — no agents connected yet)', 2)
add_code([
    'curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/api/agents',
    '# Expected: []',
], comment='Windows PowerShell')

add_heading('6e. Simulate an agent heartbeat', 2)
add_code([
    '$hb = @{',
    '    agentId   = "test-agent-001"',
    '    hostname  = "TESTPC"',
    '    ipAddress = "192.168.1.50"',
    '    osVersion = "Windows 11 Pro"',
    '    username  = "testuser"',
    '    status    = "idle"',
    '    envLabel  = "Lab"',
    '} | ConvertTo-Json',
    'curl -s -X POST http://localhost:9000/api/heartbeat `',
    '    -H "Content-Type: application/json" -d $hb',
    '# Expected: 200 OK',
], comment='Windows PowerShell')

add_heading('6f. Verify agent is now stored in database', 2)
add_code([
    'curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/api/agents | ConvertFrom-Json',
    '# Expected: one agent — test-agent-001 with hostname TESTPC',
], comment='Windows PowerShell')

add_heading('6g. Test RBAC — wrong password', 2)
add_code([
    "curl -X POST http://localhost:9000/api/auth/login `",
    '    -H "Content-Type: application/json" `',
    "    -d '{\"username\":\"admin\",\"password\":\"wrongpassword\"}'",
    '# Expected: 401  {"error":"invalid credentials"}',
], comment='Windows PowerShell')

add_heading('6h. Test RBAC — no token', 2)
add_code([
    'curl http://localhost:9000/api/agents',
    '# Expected: 401  {"error":"unauthorized"}',
], comment='Windows PowerShell')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — WEBSOCKET TEST
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 7 — Test WebSocket (Real-time Push)', 1)
add_body('Open Chrome or Edge, press F12, go to the Console tab, and paste:')
add_code([
    'const ws = new WebSocket("ws://localhost:9000/ws/browser");',
    'ws.onopen    = () => console.log("Connected to BAS orchestrator");',
    'ws.onmessage = e => console.log("Message:", JSON.parse(e.data));',
    'ws.onerror   = e => console.error("Error:", e);',
], comment='Browser DevTools Console (F12)')

add_body('Now send another heartbeat from PowerShell (repeat Step 6e). You should immediately see in the browser console:')
add_code([
    'Connected to BAS orchestrator',
    'Message: {type: "agentUpdate", agentId: "test-agent-001", data: {...}}',
], comment='Expected browser console output')

add_note('If you see "Connected" but no message after the heartbeat — check that the orchestrator terminal is still running.', kind='info')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — PYTHON API
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 8 — Run the Python API', 1)
add_body('Open a second WSL2 terminal (run wsl -d Ubuntu-24.04 in a new PowerShell window).')

add_heading('8a. Install dependencies', 2)
add_code([
    'cd /mnt/c/Users/Administrator/Downloads/Audspect_Cloud/api',
    'python3.12 -m venv venv',
    'source venv/bin/activate',
    'pip install -r requirements.txt',
], comment='WSL2 Ubuntu terminal (2nd window)')

add_heading('8b. Run the API', 2)
add_code([
    'export DATABASE_URL="postgresql+asyncpg://bas_user:TestPass123!@localhost:5432/bas_platform"',
    'export ORCHESTRATOR_URL="http://localhost:9000"',
    '',
    'uvicorn main:app --host 0.0.0.0 --port 8000 --reload',
    '',
    '# Expected:',
    '# INFO: Application startup complete.',
    '# INFO: Uvicorn running on http://0.0.0.0:8000',
], comment='WSL2 Ubuntu terminal (2nd window)')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — TEST PYTHON API
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 9 — Test the Python API', 1)
add_body('Back in Windows PowerShell:')

add_heading('9a. Health', 2)
add_code([
    'curl http://localhost:8000/health',
    '# Expected: {"status":"ok","service":"bas-api"}',
], comment='Windows PowerShell')

add_heading('9b. Agents (reads same PostgreSQL as orchestrator)', 2)
add_code([
    'curl http://localhost:8000/api/agents | ConvertFrom-Json',
    '# Expected: same test-agent-001 created in Step 6e',
], comment='Windows PowerShell')

add_heading('9c. Scenarios (Python proxies to Go orchestrator)', 2)
add_code([
    'curl http://localhost:8000/api/scenarios | ConvertFrom-Json | Select-Object id, name',
    '# Expected: same 5 BFSI scenarios',
], comment='Windows PowerShell')

add_heading('9d. Scoring engine direct test', 2)
add_code([
    "python3.12 -c \"",
    "import sys; sys.path.insert(0, '.')",
    "import scoring",
    "categories = [{'phase': 'credential-access', 'checks': [",
    "    {'result': 'Fail', 'severity': 'Critical'},",
    "    {'result': 'Pass', 'severity': 'High'},",
    "    {'result': 'Fail', 'severity': 'Critical'},",
    "]}]",
    "s = scoring.compute(categories)",
    "print('Risk Score:', s.risk_score)",
    "print('Classification:', s.classification)",
    "print('Prevention:', s.prevention_effectiveness)",
    '"',
    '# Expected: Risk Score: ~50-70  Classification: Medium Risk or High Risk',
], comment='WSL2 Ubuntu terminal (api dir, venv active)')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — DATABASE VERIFICATION
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Step 10 — Verify PostgreSQL Directly', 1)
add_code([
    'psql -h localhost -U bas_user -d bas_platform',
    '',
    r'\dt',
    '# Expected tables: agents, scenario_runs, reports, users',
    '',
    'SELECT * FROM agents;',
    '# Expected: test-agent-001 row',
    '',
    'SELECT id, username, role FROM users;',
    '# Expected: admin user with role=admin',
    '',
    r'\q',
], comment='WSL2 Ubuntu terminal')

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — PASS/FAIL CHECKLIST
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Phase 1 Pass / Fail Checklist', 1)
add_table(
    ['#', 'Test', 'Expected Result', 'Status'],
    [
        ['1',  'Orchestrator starts',           '5 log lines, "Loaded 5 scenarios"',     '☐ Pass  ☐ Fail'],
        ['2',  'GET /health',                   '{"status":"ok"}',                        '☐ Pass  ☐ Fail'],
        ['3',  'POST /api/auth/login',          'JWT token returned',                     '☐ Pass  ☐ Fail'],
        ['4',  'GET /api/scenarios',            '5 BFSI scenarios listed',                '☐ Pass  ☐ Fail'],
        ['5',  'POST /api/heartbeat',           '200 OK',                                 '☐ Pass  ☐ Fail'],
        ['6',  'GET /api/agents after heartbeat','test-agent-001 visible',                '☐ Pass  ☐ Fail'],
        ['7',  'Wrong password',                '401 invalid credentials',                '☐ Pass  ☐ Fail'],
        ['8',  'No token on /api/agents',       '401 unauthorized',                       '☐ Pass  ☐ Fail'],
        ['9',  'WebSocket browser connect',     'Connected message in console',           '☐ Pass  ☐ Fail'],
        ['10', 'WebSocket agentUpdate push',    'Message appears on heartbeat',           '☐ Pass  ☐ Fail'],
        ['11', 'Python API /health',            '{"status":"ok","service":"bas-api"}',    '☐ Pass  ☐ Fail'],
        ['12', 'Python API /api/agents',        'Same agent data as orchestrator',        '☐ Pass  ☐ Fail'],
        ['13', 'Scoring engine',                'Returns numeric risk score',             '☐ Pass  ☐ Fail'],
        ['14', 'PostgreSQL — 4 tables exist',   'agents, users, scenario_runs, reports',  '☐ Pass  ☐ Fail'],
    ],
    col_widths=[0.25, 2.2, 2.8, 1.2]
)

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — COMMON ISSUES
# ═════════════════════════════════════════════════════════════════════════════
add_heading('Common Issues & Fixes', 1)
add_table(
    ['Problem', 'Fix'],
    [
        ['go mod tidy fails (module download)',     'Check internet; corporate proxy may block proxy.golang.org — set GOPROXY=direct'],
        ['PostgreSQL connection refused',           'Run: sudo service postgresql start (PostgreSQL is not auto-started in WSL2)'],
        ['Port 9000 already in use',                'Run: netstat -ano | findstr 9000 in PowerShell to find and kill the process'],
        ['asyncpg install fails',                   'Run: pip install asyncpg --pre  (pre-release wheel supports Python 3.12)'],
        ['Scenarios not loading (0 scenarios)',     'Check scenarios_dir in config.json — use the full /mnt/c/... absolute path'],
        ['wsl --install fails',                     'Enable virtualisation in BIOS; or run: Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform'],
        ['WebSocket shows error in browser',        'Check orchestrator is still running in WSL2 terminal — it may have crashed'],
        ['curl returns Cannot connect to proxy',    'Run: $env:NO_PROXY = "localhost,127.0.0.1" in PowerShell before curl commands'],
    ],
    col_widths=[2.8, 3.7]
)

# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — PRODUCTION PATH
# ═════════════════════════════════════════════════════════════════════════════
add_heading('After Testing — Moving to Production Ubuntu', 1)
add_body('Once all 14 tests pass in WSL2, the production deployment is straightforward:')
add_bullet('Copy the project to the Ubuntu 24.04 server (scp or git clone)')
add_bullet('Run: sudo bash scripts/harden-ubuntu.sh')
add_bullet('Run: sudo bash scripts/setup-postgres.sh <db_password>')
add_bullet('Run: sudo bash scripts/install-k3s.sh <db_password> <jwt_secret>')
add_bullet('Build the Docker images and push to your registry')
add_bullet('Helm deploys the same orchestrator and Python API into k3s')
add_body('The binary you built in WSL2 (go build -o bas-orchestrator) is already a Linux amd64 binary — the same format that runs in the k3s container.', color=DIM_TXT, italic=True)

add_divider()
p = doc.add_paragraph()
set_para_bg(p, DARK_BG)
r = p.add_run('Audspect BAS Platform  ·  Phase 1 Testing Guide  ·  Confidential')
r.font.size = Pt(8)
r.font.color.rgb = rgb(DIM_TXT)
r.font.italic = True
r.font.name = 'Calibri'
p.alignment = WD_ALIGN_PARAGRAPH.CENTER

# ── Save ──────────────────────────────────────────────────────────────────────
doc.save(OUT)
print(f"Saved: {OUT}")
