// ============================================================================
//  CineReview - Movie Review System  (SINGLE FILE)
//  Node.js + built-in SQLite. No npm packages needed.
//
//  Run:   node app.js          then open  http://localhost:3000
//  Admin: username  admin   |   password  123
//  Needs Node.js 22.13 or newer  (https://nodejs.org  -> LTS)
// ============================================================================
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

let DatabaseSync;
try { ({ DatabaseSync } = require('node:sqlite')); }
catch (e) {
  console.error('This app needs Node.js 22.13 or newer (your version: ' + process.version + ').');
  console.error('Download the LTS version from https://nodejs.org and run again.');
  process.exit(1);
}

// ---------- Database (one file, created automatically) ----------
const DB_FILE = process.env.DB_PATH || path.join(__dirname, 'movie_reviews.db');   // set DB_PATH to a persistent disk when deployed
const db = new DatabaseSync(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    movie TEXT NOT NULL,
    name TEXT NOT NULL,
    district TEXT NOT NULL,
    gender TEXT NOT NULL CHECK (gender IN ('Male','Female','Other')),
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    review_text TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_reviews_district ON reviews(district);
  CREATE INDEX IF NOT EXISTS idx_reviews_movie ON reviews(movie);
`);

// ---------- Password hashing (scrypt, built into Node) ----------
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return 'scrypt$' + salt + '$' + crypto.scryptSync(pw, salt, 32).toString('hex');
}
function checkPassword(pw, stored) {
  const [, salt, hash] = String(stored).split('$');
  const a = Buffer.from(crypto.scryptSync(pw, salt, 32).toString('hex'));
  const b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
if (!db.prepare('SELECT 1 FROM admins WHERE username = ?').get('admin')) {
  db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run('admin', hashPassword(process.env.ADMIN_PASSWORD || '123'));
  console.log('Default admin created -> username: admin | password: ' + (process.env.ADMIN_PASSWORD ? '(from ADMIN_PASSWORD)' : '123'));
}

// ---------- Sessions & helpers ----------
const sessions = new Map();           // token -> expiry time
const attempts = new Map();           // ip -> { n, t }  (simple login throttle)
const GENDERS = ['Male', 'Female', 'Other'];

const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(x => x[0]));
const isAdmin = req => { const t = cookies(req).sid, e = sessions.get(t); return !!(e && e > Date.now()); };
const send = (res, code, body, type = 'application/json; charset=utf-8', extra = {}) => {
  res.writeHead(code, { 'Content-Type': type, 'X-Content-Type-Options': 'nosniff', ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const readJson = req => new Promise(resolve => {
  let data = '';
  req.on('data', c => { data += c; if (data.length > 20000) req.destroy(); });
  req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve({}); } });
});
const SELECT_ALL = `SELECT id, movie, name, district, gender, rating,
                    COALESCE(review_text, '') AS text, created_at AS ts
                    FROM reviews ORDER BY created_at DESC`;
const allReviews = () => db.prepare(SELECT_ALL).all().map(r => ({ ...r }));

// ---------- Web server + API ----------
const server = http.createServer(async (req, res) => {
  try {
    const p = new URL(req.url, 'http://localhost').pathname;
    const m = req.method;

    if (m === 'GET' && (p === '/' || p === '/index.html')) return send(res, 200, PAGE, 'text/html; charset=utf-8');
    if (!p.startsWith('/api/')) return send(res, 404, 'Not found', 'text/plain');

    // Public: submit a review
    if (m === 'POST' && p === '/api/reviews') {
      const b = await readJson(req);
      const movie = String(b.movie || '').trim().slice(0, 80);
      const name = String(b.name || '').trim().slice(0, 60);
      const district = String(b.district || '').trim().slice(0, 60);
      const text = String(b.text || '').trim().slice(0, 500);
      const rating = parseInt(b.rating, 10);
      if (!movie || !name || !district || !GENDERS.includes(b.gender) || !(rating >= 1 && rating <= 5))
        return send(res, 400, { error: 'Please fill all required fields correctly.' });
      db.prepare('INSERT INTO reviews (movie, name, district, gender, rating, review_text, created_at) VALUES (?,?,?,?,?,?,?)')
        .run(movie, name, district, b.gender, rating, text || null, Date.now());   // placeholders = SQL-injection safe
      return send(res, 200, { ok: true });
    }

    // Admin auth
    if (m === 'POST' && p === '/api/login') {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(), a = attempts.get(ip) || { n: 0, t: Date.now() };
      if (Date.now() - a.t > 600000) { a.n = 0; a.t = Date.now(); }
      if (a.n >= 8) return send(res, 429, { error: 'Too many attempts. Try again in a few minutes.' });
      const b = await readJson(req);
      const row = db.prepare('SELECT password_hash FROM admins WHERE username = ?').get(String(b.username || ''));
      if (!row || !checkPassword(String(b.password || ''), row.password_hash)) {
        a.n++; attempts.set(ip, a);
        return send(res, 401, { error: 'Invalid username or password' });
      }
      attempts.delete(ip);
      const token = crypto.randomBytes(24).toString('hex');
      sessions.set(token, Date.now() + 2 * 3600 * 1000);
      return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=7200` + (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '') });
    }
    if (m === 'POST' && p === '/api/logout') {
      sessions.delete(cookies(req).sid);
      return send(res, 200, { ok: true }, undefined, { 'Set-Cookie': 'sid=; HttpOnly; Path=/; Max-Age=0' });
    }
    if (m === 'GET' && p === '/api/me') return send(res, 200, { admin: isAdmin(req) });

    // Everything below needs admin login
    if (!isAdmin(req)) return send(res, 401, { error: 'Admin login required' });

    if (m === 'GET' && p === '/api/reviews') return send(res, 200, allReviews());

    const del = p.match(/^\/api\/reviews\/(\d+)$/);
    if (m === 'DELETE' && del) {
      db.prepare('DELETE FROM reviews WHERE id = ?').run(parseInt(del[1], 10));
      return send(res, 200, { ok: true });
    }

    // Download database as CSV
    if (m === 'GET' && p === '/api/export/csv') {
      const safe = v => {                    // quote + block spreadsheet formula injection
        let s = String(v ?? '');
        if (/^[=+\-@]/.test(s)) s = "'" + s;
        return '"' + s.replace(/"/g, '""') + '"';
      };
      const head = ['id', 'created_at', 'name', 'district', 'gender', 'movie', 'rating', 'review'];
      const lines = allReviews().map(r => [r.id, new Date(r.ts).toISOString(), r.name, r.district, r.gender, r.movie, r.rating, r.text].map(safe).join(','));
      return send(res, 200, '\ufeff' + head.join(',') + '\n' + lines.join('\n'), 'text/csv; charset=utf-8',
        { 'Content-Disposition': 'attachment; filename="movie_reviews.csv"' });
    }

    // Download the real SQLite database file
    if (m === 'GET' && p === '/api/export/db') {
      return send(res, 200, fs.readFileSync(DB_FILE), 'application/octet-stream',
        { 'Content-Disposition': 'attachment; filename="movie_reviews.db"' });
    }

    send(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    send(res, 500, { error: 'Server error' });
  }
});

// ---------- Front-end page (HTML + CSS + JavaScript) ----------
const PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>CineReview – Movie Review System</title>
<style>
:root{--bg:#0a0a0a;--card:#16140f;--ink:#f5ecd0;--mut:#a89a74;--line:#3a3220;--pri:#d4af37;--pri2:#c0392b;--ok:#16a34a;--bar:#d4af37;
box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px);color-scheme:dark}


*{box-sizing:border-box}html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5}
header{background:linear-gradient(120deg,#000,#1c1606);color:var(--pri);border-bottom:2px solid var(--pri);padding:22px 16px 18px}
.wrap{max-width:980px;margin:0 auto;padding:0 16px}header .wrap{padding:0}
h1{margin:0;font-size:1.6rem}header p{margin:2px 0 0;opacity:.9}
nav{display:flex;gap:8px;margin:16px 0}
nav button{flex:1;padding:11px;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:10px;font-weight:600;cursor:pointer;font-size:.95rem}
nav button.on{background:var(--pri);color:#111;border-color:var(--pri)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
label{display:block;font-weight:600;font-size:.88rem;margin:12px 0 5px}
input,select,textarea{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:90px;resize:vertical}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
@media (max-width:600px){.row{grid-template-columns:1fr}}
.gender{display:flex;gap:14px;flex-wrap:wrap}.gender label{display:flex;align-items:center;gap:6px;font-weight:500;margin:0}.gender input{width:auto}
.emojis{display:flex;gap:8px;flex-wrap:wrap}
.emo{flex:1;min-width:58px;text-align:center;padding:10px 4px;border:2px solid var(--line);border-radius:12px;cursor:pointer;background:var(--bg);color:var(--ink);font:inherit}
.emo span{display:block;font-size:2rem;line-height:1.1}.emo small{color:var(--mut);font-size:.72rem}
.emo.on{border-color:var(--pri);background:color-mix(in srgb,var(--pri) 14%,var(--bg));transform:scale(1.05)}
.btn{background:linear-gradient(135deg,#f0d77a,#d4af37 55%,#a67c00);color:#111;border:0;padding:12px 20px;border-radius:10px;font-weight:700;cursor:pointer;font-size:1rem;margin-top:16px}
.btn.sec{background:transparent;color:var(--ink);border:1px solid var(--line);margin:0;padding:8px 12px;font-size:.85rem}
.msg{padding:10px 12px;border-radius:9px;margin-top:12px;font-size:.9rem}
.msg.ok{background:color-mix(in srgb,var(--ok) 16%,var(--card));color:var(--ink)}.msg.err{background:color-mix(in srgb,var(--pri2) 18%,var(--card))}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
.stat b{display:block;font-size:1.7rem;color:var(--pri)}.stat span{color:var(--mut);font-size:.82rem}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media (max-width:700px){.grid2{grid-template-columns:1fr}}
h3{margin:0 0 10px;font-size:1rem;color:var(--pri)}
.bar{display:flex;align-items:center;gap:8px;margin:6px 0;font-size:.85rem}
.bar i{flex:0 0 78px;font-style:normal;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bar div{flex:1;background:var(--line);border-radius:6px;height:14px;overflow:hidden}.bar div u{display:block;height:100%;background:var(--bar);border-radius:6px}
.bar em{flex:0 0 28px;text-align:right;font-style:normal;color:var(--mut)}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}.tools input,.tools select{flex:1;min-width:130px;width:auto}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.88rem;min-width:640px}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mut);font-weight:600}
.lock{text-align:center;padding:30px 10px}.lock input{max-width:240px;margin:10px auto}
.mut{color:var(--mut);font-size:.85rem}.hide{display:none}
.donut{width:120px;height:120px;border-radius:50%;display:grid;place-items:center;flex:none}
.donut span{background:var(--card);width:78px;height:78px;border-radius:50%;display:grid;place-items:center;font-weight:700;color:var(--pri);font-size:1.1rem}
.sentwrap{display:flex;gap:18px;align-items:center;flex-wrap:wrap}.legend div{margin:5px 0;font-size:.9rem}
.spark{display:flex;gap:8px;align-items:stretch;height:150px}
.spark>div{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;font-size:.72rem;min-width:0}
.bw{flex:1;width:100%;display:flex;align-items:flex-end}.spark u{display:block;width:100%;background:var(--bar);border-radius:5px 5px 0 0;min-height:2px}
.spark em{font-style:normal;color:var(--mut)}
.bad{border-color:var(--pri2)!important}
.pager{display:flex;justify-content:space-between;align-items:center;margin-top:10px;gap:8px;flex-wrap:wrap}
</style>
</head>
<body>
<header><div class="wrap"><h1>🎬 CineReview</h1><p>Share your movie experience · Powered by SQLite</p></div></header>
<div class="wrap">
<nav><button id="t-review" class="on">✍️ Write Review</button><button id="t-admin">📊 Admin Dashboard</button></nav>

<section id="v-review">
 <div class="card">
  <h3>Submit your review</h3>
  <label for="movie">Movie name</label><input id="movie" maxlength="80" placeholder="e.g. Kantara">
  <div class="row">
   <div><label for="name">Your name</label><input id="name" maxlength="60" placeholder="Full name"></div>
   <div><label for="district">District</label><input id="district" list="dl" maxlength="60" placeholder="Select or type district"><datalist id="dl"></datalist></div>
  </div>
  <label>Gender</label>
  <div class="gender">
   <label><input type="radio" name="g" value="Male"> Male</label>
   <label><input type="radio" name="g" value="Female"> Female</label>
   <label><input type="radio" name="g" value="Other"> Other</label>
  </div>
  <label>Rating</label><div class="emojis" id="emojis"></div><div class="mut" id="rl" style="margin-top:6px;min-height:1.3em"></div>
  <label for="text">Your review (optional)</label><textarea id="text" maxlength="500" placeholder="What did you think?"></textarea><div class="mut" id="cnt" style="text-align:right">0/500</div>
  <button class="btn" id="submit">Submit review</button>
  <div id="fmsg"></div>
 </div>
</section>

<section id="v-admin" class="hide">
 <div id="lock" class="card lock hide"></div>
 <div id="dash" class="hide"><div class="tools"><button class="btn sec" id="dlcsv">⬇ Download CSV</button><button class="btn sec" id="dldb">⬇ Download database (.db)</button><button class="btn sec" id="logout">Logout</button></div>
  <div class="stats" id="stats"></div>
  <div class="grid2">
   <div class="card"><h3>Rating distribution</h3><div id="c-rate"></div></div>
   <div class="card"><h3>Gender split</h3><div id="c-gender"></div></div>
  </div>
  <div class="grid2">
   <div class="card"><h3>Reviews by district</h3><div id="c-dist"></div></div>
   <div class="card"><h3>Top movies (avg rating)</h3><div id="c-movie"></div></div>
  </div>
  <div class="grid2">
   <div class="card"><h3>Sentiment</h3><div class="sentwrap" id="c-sent"></div></div>
   <div class="card"><h3>Reviews in the last 7 days</h3><div id="c-trend"></div></div>
  </div>
  <div class="card"><h3>Average rating by district</h3><div id="c-davg"></div></div>
  <div class="card">
   <h3>All reviews</h3>
   <div class="tools"><input id="q" placeholder="Search name, movie, district…"><select id="fg"><option value="">All genders</option><option>Male</option><option>Female</option><option>Other</option></select><select id="fr"><option value="">All ratings</option></select><select id="fd"><option value="">All districts</option></select><select id="sort"><option value="new">Newest first</option><option value="old">Oldest first</option><option value="hi">Highest rating</option><option value="lo">Lowest rating</option><option value="az">Name A–Z</option></select><input type="date" id="d1" title="From date"><input type="date" id="d2" title="To date"></div>
   <div class="scroll"><table><thead><tr><th>Date</th><th>Name</th><th>District</th><th>Gender</th><th>Movie</th><th>Rating</th><th>Review</th><th></th></tr></thead><tbody id="rows"></tbody></table></div>
   <p class="mut" id="empty"></p><div class="pager"><span class="mut" id="pginfo"></span><span><button class="btn sec" id="prev">‹ Prev</button> <button class="btn sec" id="next">Next ›</button></span></div>
  </div>
 </div>
</section>
</div>

<script>
const EMO=[["😡","Awful"],["😕","Poor"],["😐","Okay"],["😊","Good"],["🤩","Superb"]];
const DISTRICTS=["Balod","Baloda Bazar","Balrampur","Bastar","Bemetara","Bijapur","Bilaspur","Dantewada","Dhamtari","Durg","Gariaband","Gaurela-Pendra-Marwahi","Janjgir-Champa","Jashpur","Kabirdham","Kanker","Khairagarh","Kondagaon","Korba","Koriya","Mahasamund","Manendragarh","Mohla-Manpur","Mungeli","Narayanpur","Raigarh","Raipur","Rajnandgaon","Sakti","Sarangarh-Bilaigarh","Sukma","Surajpur","Surguja"];
const $=s=>document.querySelector(s);
const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let rating=0,reviews=[],loggedIn=false;

async function api(url,body,method){
 const opt={method:method||(body?"POST":"GET"),credentials:"same-origin",headers:{"Content-Type":"application/json"}};
 if(body)opt.body=JSON.stringify(body);
 const r=await fetch(url,opt),j=await r.json().catch(()=>({}));
 if(!r.ok)throw new Error(j.error||r.statusText);
 return j;
}

$("#dl").innerHTML=DISTRICTS.map(d=>\`<option value="\${d}">\`).join("");
$("#emojis").innerHTML=EMO.map((e,i)=>\`<button type="button" class="emo" data-r="\${i+1}"><span>\${e[0]}</span><small>\${i+1} · \${e[1]}</small></button>\`).join("");
$("#fr").innerHTML+=EMO.map((e,i)=>\`<option value="\${i+1}">\${e[0]} \${i+1}</option>\`).join("");
$("#emojis").onclick=e=>{const b=e.target.closest(".emo");if(!b)return;rating=+b.dataset.r;$("#rl").textContent=EMO[rating-1][0]+" "+EMO[rating-1][1]+" – "+rating+"/5";document.querySelectorAll(".emo").forEach(x=>x.classList.toggle("on",x===b))};

function show(v){
 $("#v-review").classList.toggle("hide",v!=="review");$("#v-admin").classList.toggle("hide",v!=="admin");
 $("#t-review").classList.toggle("on",v==="review");$("#t-admin").classList.toggle("on",v==="admin");
 if(v==="admin")loadAdmin();
}
$("#t-review").onclick=()=>show("review");$("#t-admin").onclick=()=>show("admin");
function flash(t,ok){$("#fmsg").innerHTML=\`<div class="msg \${ok?"ok":"err"}">\${esc(t)}</div>\`}

["movie","name","district"].forEach(i=>$("#"+i).addEventListener("input",e=>e.target.classList.remove("bad")));
$("#text").addEventListener("input",()=>{$("#cnt").textContent=$("#text").value.length+"/500"});
$("#submit").onclick=async()=>{
 const movie=$("#movie").value.trim(),name=$("#name").value.trim(),district=$("#district").value.trim(),text=$("#text").value.trim();
 const g=document.querySelector('input[name="g"]:checked');
 ["movie","name","district"].forEach(i=>$("#"+i).classList.toggle("bad",!$("#"+i).value.trim()));if(!movie||!name||!district||!g||!rating)return flash("Please fill movie, name, district, gender and pick a rating emoji.",false);
 $("#submit").disabled=true;
 try{
  await api("/api/reviews",{movie,name,district,gender:g.value,rating,text});
  flash("Thank you, "+name+"! Your review for “"+movie+"” "+EMO[rating-1][0]+" was saved to the database.",true);
  ["movie","name","district","text"].forEach(i=>$("#"+i).value="");
  document.querySelectorAll('input[name="g"]').forEach(r=>r.checked=false);
  rating=0;document.querySelectorAll(".emo").forEach(x=>x.classList.remove("on"));$("#rl").textContent="";$("#cnt").textContent="0/500";
 }catch(e){flash(e.message||"Could not save your review.",false)}
 $("#submit").disabled=false;
};

function bars(el,data){
 const max=Math.max(1,...data.map(d=>d[1]));
 $(el).innerHTML=data.length?data.map(d=>\`<div class="bar"><i title="\${esc(d[0])}">\${esc(d[0])}</i><div><u style="width:\${d[1]/max*100}%"></u></div><em>\${d[2]??d[1]}</em></div>\`).join(""):'<span class="mut">No data yet</span>';
}
const tally=(arr,f)=>{const m={};arr.forEach(r=>{const k=f(r);m[k]=(m[k]||0)+1});return Object.entries(m).sort((a,b)=>b[1]-a[1])};

async function loadAdmin(){
 try{loggedIn=(await api("/api/me")).admin}catch(e){loggedIn=false}
 if(loggedIn){try{reviews=await api("/api/reviews")}catch(e){loggedIn=false}}
 renderAdmin();
}
function renderAdmin(){
 const ok=loggedIn;
 $("#lock").classList.toggle("hide",ok);$("#dash").classList.toggle("hide",!ok);
 if(!ok){
  $("#lock").innerHTML='<h3>🔒 Admin login</h3><input id="un" placeholder="Username" autocomplete="username"><br><input id="pw" type="password" placeholder="Password" autocomplete="current-password"><br><button class="btn" id="login">Login</button><div id="lmsg"></div>';
  const go=async()=>{try{await api("/api/login",{username:$("#un").value.trim(),password:$("#pw").value});await loadAdmin()}catch(e){$("#lmsg").innerHTML='<div class="msg err">'+esc(e.message)+'</div>'}};
  $("#login").onclick=go;$("#pw").onkeydown=e=>{if(e.key==="Enter")go()};
  return;
 }
 const n=reviews.length,avg=n?reviews.reduce((a,r)=>a+r.rating,0)/n:0;
 const fav=tally(reviews,r=>r.movie)[0],topD=tally(reviews,r=>r.district)[0];
 $("#stats").innerHTML=[[n,"Total reviews"],[n?avg.toFixed(2)+" "+EMO[Math.round(avg)-1][0]:"–","Average rating"],[fav?esc(fav[0]):"–","Most reviewed movie"],[topD?esc(topD[0]):"–","Top district"]].map(s=>\`<div class="stat"><b>\${s[0]}</b><span>\${s[1]}</span></div>\`).join("");
 bars("#c-rate",EMO.map((e,i)=>[e[0]+" "+(i+1),reviews.filter(r=>r.rating===i+1).length]).reverse());
 bars("#c-gender",tally(reviews,r=>r.gender));
 bars("#c-dist",tally(reviews,r=>r.district).slice(0,8));
 const mm={};reviews.forEach(r=>{(mm[r.movie]=mm[r.movie]||[]).push(r.rating)});
 bars("#c-movie",Object.entries(mm).map(([k,v])=>[k,v.reduce((a,b)=>a+b,0)/v.length,(v.reduce((a,b)=>a+b,0)/v.length).toFixed(1)]).sort((a,b)=>b[1]-a[1]).slice(0,6));
 extras();renderRows();
}
let page=1;const PS=10;
function extras(){
 const n=reviews.length||1,pos=reviews.filter(r=>r.rating>=4).length,neu=reviews.filter(r=>r.rating===3).length,neg=reviews.filter(r=>r.rating<=2).length;
 $("#c-sent").innerHTML=\`<div class="donut" style="background:conic-gradient(var(--ok) 0 \${pos/n*100}%,var(--pri) 0 \${(pos+neu)/n*100}%,var(--pri2) 0 100%)"><span>\${reviews.length?Math.round(pos/n*100)+"%":"–"}</span></div><div class="legend"><div>🤩 Positive (4–5): <b>\${pos}</b></div><div>😐 Neutral (3): <b>\${neu}</b></div><div>😡 Negative (1–2): <b>\${neg}</b></div></div>\`;
 const days=[];for(let i=6;i>=0;i--){const d=new Date();d.setHours(0,0,0,0);d.setDate(d.getDate()-i);days.push(d)}
 const cnt=days.map(d=>reviews.filter(r=>r.ts>=d.getTime()&&r.ts<d.getTime()+864e5).length),mx=Math.max(1,...cnt);
 $("#c-trend").innerHTML='<div class="spark">'+cnt.map((c,i)=>\`<div title="\${days[i].toLocaleDateString()}: \${c}"><small>\${c}</small><div class="bw"><u style="height:\${c/mx*100}%"></u></div><em>\${days[i].toLocaleDateString(undefined,{weekday:"short"})}</em></div>\`).join("")+'</div>';
 const dm={};reviews.forEach(r=>{(dm[r.district]=dm[r.district]||[]).push(r.rating)});
 bars("#c-davg",Object.entries(dm).map(([k,v])=>{const a=v.reduce((x,y)=>x+y,0)/v.length;return[k,a,a.toFixed(1)]}).sort((a,b)=>b[1]-a[1]).slice(0,8));
 const sel=$("#fd"),cur=sel.value;sel.innerHTML='<option value="">All districts</option>'+[...new Set(reviews.map(r=>r.district))].sort().map(d=>\`<option>\${esc(d)}</option>\`).join("");sel.value=cur;
}
function filtered(){
 const q=$("#q").value.toLowerCase(),fg=$("#fg").value,fr=$("#fr").value,fd=$("#fd").value;
 const d1=$("#d1").value?new Date($("#d1").value).getTime():0,d2=$("#d2").value?new Date($("#d2").value).getTime()+864e5:Infinity;
 const cmp={new:(a,b)=>b.ts-a.ts,old:(a,b)=>a.ts-b.ts,hi:(a,b)=>b.rating-a.rating||b.ts-a.ts,lo:(a,b)=>a.rating-b.rating||b.ts-a.ts,az:(a,b)=>a.name.localeCompare(b.name)}[$("#sort").value];
 return reviews.filter(r=>(!fg||r.gender===fg)&&(!fr||r.rating==fr)&&(!fd||r.district===fd)&&r.ts>=d1&&r.ts<d2&&(!q||[r.name,r.movie,r.district,r.text].join(" ").toLowerCase().includes(q))).sort(cmp);
}
function renderRows(){
 const list=filtered(),pages=Math.max(1,Math.ceil(list.length/PS));if(page>pages)page=pages;if(page<1)page=1;
 $("#rows").innerHTML=list.slice((page-1)*PS,page*PS).map(r=>\`<tr><td>\${new Date(r.ts).toLocaleDateString()}</td><td>\${esc(r.name)}</td><td>\${esc(r.district)}</td><td>\${esc(r.gender)}</td><td>\${esc(r.movie)}</td><td style="font-size:1.4rem" title="\${r.rating}/5">\${EMO[r.rating-1][0]}</td><td>\${esc(r.text)}</td><td><button class="btn sec" data-del="\${r.id}" data-u="\${r.uid||""}">Delete</button></td></tr>\`).join("");
 $("#empty").textContent=list.length?"":"No reviews to show.";
 $("#pginfo").textContent=list.length+" review"+(list.length===1?"":"s")+" · page "+page+" of "+pages;
 $("#prev").disabled=page<=1;$("#next").disabled=page>=pages;
}
["#q","#fg","#fr","#fd","#sort","#d1","#d2"].forEach(s=>$(s).addEventListener("input",()=>{page=1;renderRows()}));
$("#prev").onclick=()=>{page--;renderRows()};$("#next").onclick=()=>{page++;renderRows()};
$("#rows").onclick=async e=>{
 const b=e.target.closest("[data-del]");if(!b||!confirm("Delete this review?"))return;
 try{await api("/api/reviews/"+b.dataset.del,null,"DELETE");await loadAdmin()}catch(err){alert(err.message)}
};
$("#dlcsv").onclick=()=>{location.href="/api/export/csv"};
$("#dldb").onclick=()=>{location.href="/api/export/db"};
$("#logout").onclick=async()=>{await api("/api/logout",{});loggedIn=false;renderAdmin()};
show("review");
</script>
</body>
</html>
`;

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Movie review system running at http://localhost:' + PORT));
