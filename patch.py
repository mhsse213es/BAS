import re

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/wwwroot/index.html', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

# Replace script tag
content = content.replace('<script src="/signalr.min.js"></script>', '<!-- Native WebSockets in use -->')

new_init = '''
    // SIGNALR CONNECTION REPLACED WITH NATIVE WEBSOCKET
    let connection = null; // keeps global variable name for legacy code just in case
    function initApp() {
      fetchAgents();

      const token = BASAuth.getToken();
      if (!token) return;

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/bashub?access_token=${token}`;

      connection = new WebSocket(wsUrl);

      connection.onopen = () => {
        setConnected(true);
      };

      connection.onmessage = (event) => {
        if (event.data === 'pong') return;
        
        let payload;
        try {
          payload = JSON.parse(event.data);
        } catch(e) { return; }

        const ev = payload.event;
        const data = payload.data;

        if (ev === 'agentUpdate') {
          const incomingId = data.agentId || data.AgentId;
          const incomingHost = data.hostname || data.Hostname;
          const incomingStatus = data.status || data.Status;

          let idx = agents.findIndex(a => (a.agentId || a.AgentId) === incomingId);
          if (idx === -1) {
            agents.push({ ...data, hasReport: false });
          } else {
            agents[idx] = { ...agents[idx], ...data };
          }
          renderTree();
          toast("info", `<b>${incomingHost}</b> — agent status: <b>${incomingStatus}</b>`);
        }

        if (ev === 'reportReady') {
          let id = data.agentId || data.AgentId;
          let host = data.hostname || data.Hostname;

          let idx = agents.findIndex(a => (a.agentId || a.AgentId) === id);
          if (idx !== -1) {
            agents[idx].status = "done";
            agents[idx].hasReport = true;
          }
          renderTree();
          fetchReport(id);
          toast("ok", `Report ready from <b>${host}</b>`);
        }

        if (ev === 'patch_status_update') {
          let agentId = data.agentId || data.AgentId;
          patchStatuses[agentId] = data;
          if (selected === agentId) {
            const overlay = document.getElementById('patch-status-overlay');
            if (overlay) {
              overlay.outerHTML = buildPatchStatusOverlay(data);
            } else {
              const patchSec = document.querySelector('.patch-section');
              if (patchSec) {
                const wrapper = document.createElement('div');
                wrapper.innerHTML = buildPatchStatusOverlay(data);
                patchSec.insertBefore(wrapper.firstElementChild, patchSec.firstElementChild.nextSibling);
              }
            }
          }
        }
      };

      connection.onclose = () => {
        setConnected(false);
        setTimeout(initApp, 5000);
      };

      connection.onerror = (e) => {
        console.warn("WebSocket error", e);
      };
      
      // Keepalive ping
      setInterval(() => {
        if (connection && connection.readyState === WebSocket.OPEN) {
          connection.send('ping');
        }
      }, 30000);
    }
'''

# We will just replace everything from function initApp() { to the end of the setConnected(false); block
pattern = r'function initApp\(\) \{.*?setConnected\(false\);\s*\}\);\s*\}'
content = re.sub(pattern, new_init.strip(), content, flags=re.DOTALL)

with open('c:/Users/Administrator/Downloads/Audspect_Cloud/BAS.Server.Python/wwwroot/index.html', 'w', encoding='utf-8') as f:
    f.write(content)
print('Patch applied')
