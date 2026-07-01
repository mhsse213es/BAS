package tracker

const defaultSafeLandingHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Security Awareness</title>
<style>body{font-family:sans-serif;max-width:600px;margin:80px auto;padding:20px;text-align:center}
.warn{background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:24px;margin:24px 0}
h2{color:#856404}</style></head>
<body>
<div class="warn">
  <h2>&#9888; This was a security awareness test</h2>
  <p>You clicked a simulated phishing link as part of an authorised cyber exercise.</p>
  <p>No data was captured. If you receive a similar email in real life, please report it immediately.</p>
</div>
</body></html>`

const defaultCredLandingHTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:20px}
input{width:100%;padding:8px;margin:6px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;background:#0b5394;color:#fff;border:0;border-radius:4px;cursor:pointer}</style></head>
<body>
<h2>Sign in</h2>
<form id="f">
  <input type="text" name="username" placeholder="Username" autocomplete="username">
  <input type="password" name="password" placeholder="Password" autocomplete="current-password">
  <button type="submit">Sign in</button>
</form>
<script>
document.getElementById('f').addEventListener('submit',function(e){
  e.preventDefault();
  fetch(location.href,{method:'POST',body:new FormData(this)})
    .then(function(){document.body.innerHTML='<div style="margin:80px auto;max-width:400px;padding:20px;text-align:center"><h2 style="color:#856404">&#9888; Security Awareness Test</h2><p>You entered credentials into a simulated phishing page. No passwords were stored. Please report suspicious emails immediately.</p></div>';});
});
</script>
</body></html>`
