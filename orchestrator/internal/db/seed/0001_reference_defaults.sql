-- Seed 0001: reference/system rows, copied verbatim from the pre-H1 boot chain
-- (internal/db/legacy/schema.go). Applied once; never edit (add a new seed file).
-- tenants: operator-editable (API renames/suspends) -> ON CONFLICT DO NOTHING
-- sla_policy: operator-editable (API edits durations) -> ON CONFLICT DO NOTHING
-- payload_families: operator can INSERT/DELETE, not UPDATE -> DO UPDATE SET tactic (as before);
--   applied once, so an operator-deleted family is never resurrected.

INSERT INTO tenants (id, name, slug, status)
		 VALUES ('default', 'Default Tenant', 'default', 'active')
		 ON CONFLICT (id) DO NOTHING;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Identity','Current user and group memberships',
		  'whoami /all','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - System Info','Full system information dump',
		  'systeminfo','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Network Config','IP config and active connections',
		  'ipconfig /all; netstat -ano','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Process List','Running processes with paths',
		  'Get-Process | Select-Object Name,Id,Path,CPU | Sort-Object CPU -Descending','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Recon - Domain Info','Active Directory domain information',
		  'try{[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}catch{"Not domain-joined"}','recon','SAFE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1059.001','Download Stager','Simulates a download cradle (loopback only)',
		  '$wc=New-Object Net.WebClient;try{$wc.DownloadString(''http://127.0.0.1/bas-test'')}catch{"Connection refused - expected"}','download','MODERATE','execution')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','WMI Computer System','Hardware and domain info via WMI',
		  'Get-WmiObject Win32_ComputerSystem | Select-Object Name,Domain,Manufacturer,Model,TotalPhysicalMemory','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','OS Version','Operating system version and build',
		  'Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1082','Installed Software','List installed applications',
		  'Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName,DisplayVersion | Where-Object {$_.DisplayName} | Sort-Object DisplayName','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','IP Configuration','Full IP configuration of all adapters',
		  'ipconfig /all','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','Routing Table','System routing table',
		  'route print','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1016','DNS Cache','Cached DNS entries',
		  'Get-DnsClientCache | Select-Object Entry,Data,TimeToLive','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1057','All Processes','Full process list with owner',
		  'Get-Process | Select-Object Name,Id,CPU,WorkingSet,Path -ErrorAction SilentlyContinue','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1057','Security Products','Identify running security/AV processes',
		  'Get-Process | Where-Object {$_.Name -match "defender|sentinel|crowdstrike|trellix|mcafee|symantec|sophos|cylance"} | Select-Object Name,Id,Path','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1049','Active TCP Connections','All active TCP connections with process IDs',
		  'netstat -ano','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1049','PowerShell TCP View','Active connections via PowerShell (includes process name)',
		  'Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | Sort-Object OwningProcess','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Current User','Current user identity and privileges',
		  'whoami /all','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Local Users','All local user accounts',
		  'Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordRequired','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO payload_families (technique_id,name,description,payload,purpose,risk_level,tactic) VALUES
		 ('T1033','Local Groups','Local group memberships',
		  'Get-LocalGroup | ForEach-Object {$g=$_.Name; Get-LocalGroupMember $g -ErrorAction SilentlyContinue | Select-Object @{n="Group";e={$g}},Name,ObjectClass}','recon','SAFE','discovery')
		 ON CONFLICT (technique_id,name) DO UPDATE SET tactic = EXCLUDED.tactic;

INSERT INTO sla_policy (severity, duration_hours) VALUES
			('Critical', 24), ('High', 72), ('Medium', 168), ('Low', 720)
		 ON CONFLICT (severity) DO NOTHING;
