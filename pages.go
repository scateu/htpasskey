package main

import "fmt"

func registerHTML(prefix string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register Passkey</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:12px;padding:2rem;max-width:600px;width:100%%;
  box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:.3rem}
.sub{color:#94a3b8;margin-bottom:1.5rem;font-size:.9rem;line-height:1.4}
label{display:block;font-size:.85rem;color:#cbd5e1;margin-bottom:.3rem}
input{width:100%%;padding:.6rem .8rem;border:1px solid #334155;border-radius:6px;
  background:#0f172a;color:#f1f5f9;font-size:1rem;margin-bottom:1rem;outline:none}
input:focus{border-color:#3b82f6}
.btn{display:block;width:100%%;padding:.7rem;border:none;border-radius:6px;font-size:1rem;
  cursor:pointer;color:#fff;text-align:center}
.btn-primary{background:#3b82f6}.btn-primary:hover{background:#2563eb}
.btn-copy{background:#059669;margin-top:.5rem}.btn-copy:hover{background:#047857}
.btn:disabled{background:#475569;cursor:not-allowed}
.result{display:none;margin-top:1.5rem}
.result.show{display:block}
.ok-box{background:#052e16;border:1px solid #16a34a;border-radius:8px;padding:1rem;margin-bottom:1rem}
.ok-box h3{color:#4ade80;margin-bottom:.3rem}
.cred-box{background:#020617;border:1px solid #334155;border-radius:6px;padding:.8rem;
  font-family:"SF Mono",Monaco,monospace;font-size:.72rem;word-break:break-all;
  white-space:pre-wrap;max-height:220px;overflow-y:auto;color:#a5b4fc;line-height:1.5;
  margin:.8rem 0;user-select:all}
.info{background:#172554;border:1px solid #1d4ed8;border-radius:8px;padding:1rem;
  font-size:.85rem;line-height:1.5;margin-top:1rem}
.info code{background:#0f172a;padding:.1rem .4rem;border-radius:3px;color:#93c5fd;font-size:.8rem}
.err{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:1rem;
  margin-top:1rem;display:none;color:#fca5a5}
.err.show{display:block}
.spinner{display:none;text-align:center;padding:1rem;color:#94a3b8}
.spinner.show{display:block}
.links{margin-top:1.5rem;text-align:center}
.links a{color:#60a5fa;text-decoration:none;font-size:.9rem}
</style></head>
<body>
<div class="card">
  <h1>🔐 Register Passkey</h1>
  <p class="sub">Create a WebAuthn credential. After registration, copy the credential text and send it to your administrator for approval.</p>

  <div id="form">
    <label for="u">Username</label>
    <input id="u" type="text" placeholder="alice" autocomplete="username webauthn"
           onkeydown="if(event.key==='Enter')go()">
    <button class="btn btn-primary" onclick="go()" id="gobtn">Register Passkey</button>
  </div>

  <div id="spin" class="spinner">⏳ Waiting for authenticator…</div>
  <div id="err" class="err"></div>

  <div id="result" class="result">
    <div class="ok-box">
      <h3>✅ Credential Created</h3>
      <p>Copy the text below and send it to your administrator.</p>
    </div>
    <div class="cred-box" id="cred"></div>
    <button class="btn btn-copy" onclick="doCopy()">📋 Copy to Clipboard</button>
    <div class="info">
      <strong>Admin:</strong> paste into <code>.htpasskey</code><br>
      <code>pbpaste >> /path/to/.htpasskey</code>
    </div>
  </div>

  <div class="links"><a href="%[1]s/login">Already registered? Login →</a></div>
</div>

<script>
const P=%[2]q;
const b2u=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%%4)s+='=';const d=atob(s),a=new Uint8Array(d.length);for(let i=0;i<d.length;i++)a[i]=d.charCodeAt(i);return a.buffer};

function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('show')}

async function go(){
  const username=document.getElementById('u').value.trim();
  if(!username){showErr('Enter a username');return}
  document.getElementById('err').classList.remove('show');
  document.getElementById('gobtn').disabled=true;
  document.getElementById('spin').classList.add('show');

  try{
    const r1=await fetch(P+'/register/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    if(!r1.ok)throw new Error((await r1.json()).error||'begin failed');
    const opts=await r1.json();

    opts.publicKey.challenge=u2b(opts.publicKey.challenge);
    opts.publicKey.user.id=u2b(opts.publicKey.user.id);
    if(opts.publicKey.excludeCredentials)opts.publicKey.excludeCredentials=opts.publicKey.excludeCredentials.map(c=>({...c,id:u2b(c.id)}));

    const cred=await navigator.credentials.create(opts);
    const body={id:cred.id,rawId:b2u(cred.rawId),type:cred.type,response:{
      attestationObject:b2u(cred.response.attestationObject),
      clientDataJSON:b2u(cred.response.clientDataJSON)}};
    if(cred.response.getTransports)body.response.transports=cred.response.getTransports();

    const r2=await fetch(P+'/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const res=await r2.json();
    if(!r2.ok)throw new Error(res.error||'finish failed');

    document.getElementById('cred').textContent=res.credential;
    document.getElementById('result').classList.add('show');
    document.getElementById('form').style.display='none';
  }catch(e){
    showErr(e.message||'Registration failed');
    document.getElementById('gobtn').disabled=false;
  }finally{
    document.getElementById('spin').classList.remove('show');
  }
}

function doCopy(){
  navigator.clipboard.writeText(document.getElementById('cred').textContent).then(()=>{
    const b=document.querySelector('.btn-copy');b.textContent='✅ Copied!';
    setTimeout(()=>b.textContent='📋 Copy to Clipboard',2000);
  });
}
</script>
</body></html>`, prefix, prefix)
}

func loginHTML(prefix string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Passkey</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem}
.card{background:#1e293b;border-radius:12px;padding:2rem;max-width:420px;width:100%%;
  box-shadow:0 8px 32px rgba(0,0,0,.5)}
h1{font-size:1.5rem;margin-bottom:.3rem}
.sub{color:#94a3b8;margin-bottom:1.5rem;font-size:.9rem}
label{display:block;font-size:.85rem;color:#cbd5e1;margin-bottom:.3rem}
input{width:100%%;padding:.6rem .8rem;border:1px solid #334155;border-radius:6px;
  background:#0f172a;color:#f1f5f9;font-size:1rem;margin-bottom:1rem;outline:none}
input:focus{border-color:#3b82f6}
.btn{display:block;width:100%%;padding:.7rem;border:none;border-radius:6px;font-size:1rem;
  cursor:pointer;color:#fff;text-align:center;margin-bottom:.6rem}
.btn-primary{background:#3b82f6}.btn-primary:hover{background:#2563eb}
.btn-secondary{background:#475569;font-size:.9rem}.btn-secondary:hover{background:#374151}
.btn:disabled{background:#475569;cursor:not-allowed}
.or{text-align:center;color:#64748b;margin:.6rem 0;font-size:.85rem}
.err{background:#450a0a;border:1px solid #dc2626;border-radius:8px;padding:1rem;
  margin-bottom:1rem;display:none;color:#fca5a5}
.err.show{display:block}
.spinner{display:none;text-align:center;padding:1rem;color:#94a3b8}
.spinner.show{display:block}
.links{margin-top:1.5rem;text-align:center}
.links a{color:#60a5fa;text-decoration:none;font-size:.9rem}
</style></head>
<body>
<div class="card">
  <h1>🔑 Login</h1>
  <p class="sub">Authenticate with your passkey.</p>
  <div id="err" class="err"></div>

  <button class="btn btn-primary" onclick="doLogin('')" id="pkbtn">🔐 Login with Passkey</button>
  <div class="or">— or enter username —</div>
  <label for="u">Username</label>
  <input id="u" type="text" placeholder="alice" autocomplete="username webauthn"
         onkeydown="if(event.key==='Enter')doLoginUser()">
  <button class="btn btn-secondary" onclick="doLoginUser()" id="ubtn">Login as User</button>
  <div id="spin" class="spinner">⏳ Waiting for authenticator…</div>
  <div class="links"><a href="%[1]s/register">Need to register? →</a></div>
</div>

<script>
const P=%[2]q;
const b2u=b=>{let s='';new Uint8Array(b).forEach(x=>s+=String.fromCharCode(x));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
const u2b=s=>{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%%4)s+='=';const d=atob(s),a=new Uint8Array(d.length);for(let i=0;i<d.length;i++)a[i]=d.charCodeAt(i);return a.buffer};

function showErr(m){const e=document.getElementById('err');e.textContent=m;e.classList.add('show')}
function getRedir(){return new URLSearchParams(location.search).get('redirect')||'/'}

async function doLogin(username){
  document.getElementById('err').classList.remove('show');
  document.getElementById('pkbtn').disabled=true;
  document.getElementById('ubtn').disabled=true;
  document.getElementById('spin').classList.add('show');

  try{
    const r1=await fetch(P+'/login/begin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username})});
    if(!r1.ok)throw new Error((await r1.json()).error||'begin failed');
    const opts=await r1.json();

    opts.publicKey.challenge=u2b(opts.publicKey.challenge);
    if(opts.publicKey.allowCredentials)
      opts.publicKey.allowCredentials=opts.publicKey.allowCredentials.map(c=>({...c,id:u2b(c.id)}));

    const assertion=await navigator.credentials.get(opts);
    const body={id:assertion.id,rawId:b2u(assertion.rawId),type:assertion.type,response:{
      authenticatorData:b2u(assertion.response.authenticatorData),
      clientDataJSON:b2u(assertion.response.clientDataJSON),
      signature:b2u(assertion.response.signature)}};
    if(assertion.response.userHandle)body.response.userHandle=b2u(assertion.response.userHandle);

    const r2=await fetch(P+'/login/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const res=await r2.json();
    if(!r2.ok)throw new Error(res.error||'login failed');

    location.href=getRedir();
  }catch(e){
    showErr(e.message||'Login failed');
    document.getElementById('pkbtn').disabled=false;
    document.getElementById('ubtn').disabled=false;
  }finally{
    document.getElementById('spin').classList.remove('show');
  }
}

function doLoginUser(){
  const u=document.getElementById('u').value.trim();
  if(!u){showErr('Enter a username');return}
  doLogin(u);
}
</script>
</body></html>`, prefix, prefix)
}