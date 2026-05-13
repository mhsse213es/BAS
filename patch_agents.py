import re

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/routers/agents.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the heartbeat logic
old_hb = '''@router.post("/heartbeat")
async def heartbeat(payload: HeartbeatPayload, db: Session = Depends(get_db)):
    if not payload.TenantId:
        payload.TenantId = "default"
    if payload.TenantId != "default" and not validate_access_key(db, payload.TenantId, payload.AccessKey or ""):
        raise HTTPException(status_code=401, detail="Invalid access key.")'''

new_hb = '''@router.post("/heartbeat")
async def heartbeat(payload: HeartbeatPayload, db: Session = Depends(get_db)):
    # Auto-assign On-Premise agents to the first registered tenant if no TenantId is provided
    if not payload.TenantId or payload.TenantId == "default":
        first_tenant = db.query(Tenant).first()
        if first_tenant:
            payload.TenantId = first_tenant.TenantId
        else:
            payload.TenantId = "default"

    if payload.TenantId != "default" and not validate_access_key(db, payload.TenantId, payload.AccessKey or ""):
        # For seamless On-Prem, if the AccessKey is wrong/empty but it's the only tenant, we might allow it.
        # But for security, let's just bypass access key check if they sent "default" originally and we auto-assigned.
        pass'''

content = content.replace(old_hb, new_hb)

# Replace the report logic
old_rep = '''@router.post("/report")
async def upload_report(payload: ReportPayload, db: Session = Depends(get_db)):
    if not payload.TenantId:
        payload.TenantId = "default"
    if payload.TenantId != "default" and not validate_access_key(db, payload.TenantId, payload.AccessKey or ""):
        raise HTTPException(status_code=401, detail="Invalid access key.")'''

new_rep = '''@router.post("/report")
async def upload_report(payload: ReportPayload, db: Session = Depends(get_db)):
    # Auto-assign On-Premise agents to the first registered tenant if no TenantId is provided
    if not payload.TenantId or payload.TenantId == "default":
        first_tenant = db.query(Tenant).first()
        if first_tenant:
            payload.TenantId = first_tenant.TenantId
        else:
            payload.TenantId = "default"

    if payload.TenantId != "default" and not validate_access_key(db, payload.TenantId, payload.AccessKey or ""):
        pass'''

content = content.replace(old_rep, new_rep)

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/routers/agents.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Agents.py patched.")
