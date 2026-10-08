const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

// ---------- Stocks (real data) ----------
const SYMBOLS = {
  'Reliance': 'RELIANCE.NS',
  'TCS': 'TCS.NS',
  'Infosys': 'INFY.NS',
  'HDFC Bank': 'HDFCBANK.NS',
  'ITC': 'ITC.NS',
  'Bharti Airtel': 'BHARTIARTL.NS'
};

async function getStock(name, symbol) {
  const url = `https://query1.finance.yahoo.com/v8/finance/chart/${symbol}?range=1mo&interval=1d`;
  const res = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  if (!res.ok) throw new Error(symbol + ' returned status ' + res.status);
  const data = await res.json();
  const r = data.chart.result[0];
  const closes = r.indicators.quote[0].close.filter(v => v != null);
  return { name, price: r.meta.regularMarketPrice, hist: closes };
}

let stockCache = { t: 0, data: null };   // so we don't hit Yahoo on every page load

// ---------- Accounts database (a simple file for now) ----------
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'users.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
let db = { users: {}, sessions: {} };
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));

function saveDb() {
  fs.writeFileSync(DB_FILE + '.tmp', JSON.stringify(db));
  fs.renameSync(DB_FILE + '.tmp', DB_FILE);
}

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const hashPassword = async (pw, salt) => (await scrypt(pw, salt, 64)).toString('hex');
const failed = {};   // wrong-password counter per email

function cookieHeader(token, maxAge) {
  return `sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function getCookie(req, name) {
  const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
  return m ? m.slice(name.length + 1) : null;
}

function createSession(email) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { email, exp: Date.now() + 30 * 24 * 3600 * 1000 };
  saveDb();
  return token;
}

function getUser(req) {
  const token = getCookie(req, 'sid');
  if (!token) return null;
  const s = db.sessions[sha(token)];
  if (!s || s.exp < Date.now()) return null;
  return db.users[s.email] || null;
}

// Only accept sensible progress data from the browser
function cleanState(s) {
  const balance = Number(s && s.balance);
  if (!Number.isFinite(balance) || balance < 0 || balance > 1e12) return null;
  const out = { balance, holdings: {}, trades: [] };
  for (const [name, h] of Object.entries((s && s.holdings) || {})) {
    if (!SYMBOLS[name]) continue;
    const q = Math.floor(Number(h.qty)), a = Number(h.avg);
    if (Number.isFinite(q) && q > 0 && Number.isFinite(a) && a > 0) out.holdings[name] = { qty: q, avg: a };
  }
  const trades = Array.isArray(s.trades) ? s.trades.slice(-200) : [];
  out.trades = trades.map(t => ({ t: Number(t.t) || 0, name: String(t.name).slice(0, 30), side: t.side === 'sell' ? 'sell' : 'buy' }));
  return out;
}

function readJson(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => { body += c; if (body.length > 50000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { resolve({}); } });
  });
}

function sendJson(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(obj));
}

const types = { '.html': 'text/html', '.png': 'image/png' };

// ---------- The server ----------
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  try {
    if (url === '/api/stocks') {
      if (!stockCache.data || Date.now() - stockCache.t > 60000) {
        stockCache.data = await Promise.all(Object.entries(SYMBOLS).map(([n, s]) => getStock(n, s)));
        stockCache.t = Date.now();
      }
      return sendJson(res, 200, stockCache.data);
    }

    if (url === '/api/me' && req.method === 'GET') {
      const user = getUser(req);
      if (!user) return sendJson(res, 401, { error: 'Not logged in.' });
      return sendJson(res, 200, { name: user.name, email: user.email, state: user.state });
    }

    if (url === '/api/signup' && req.method === 'POST') {
      const body = await readJson(req);
      const email = String(body.email || '').trim().toLowerCase();
      const name = String(body.name || '').trim().slice(0, 40);
      const password = String(body.password || '');
      if (!name) return sendJson(res, 400, { error: 'Please enter your name.' });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendJson(res, 400, { error: 'Please enter a valid email.' });
      if (password.length < 8) return sendJson(res, 400, { error: 'Your password needs at least 8 characters.' });
      if (password.length > 200) return sendJson(res, 400, { error: 'That password is too long.' });
      if (db.users[email]) return sendJson(res, 409, { error: 'That email already has an account. Try logging in.' });

      const salt = crypto.randomBytes(16).toString('hex');
      const user = {
        name, email, salt,
        hash: await hashPassword(password, salt),
        createdAt: Date.now(),
        state: { balance: 1000000, holdings: {}, trades: [] }
      };
      db.users[email] = user;
      const token = createSession(email);   // also saves the database
      return sendJson(res, 200, { name, email, state: user.state }, { 'Set-Cookie': cookieHeader(token, 30 * 24 * 3600) });
    }

    if (url === '/api/login' && req.method === 'POST') {
      const body = await readJson(req);
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '').slice(0, 200);
      const f = failed[email];
      if (f && f.count >= 5 && Date.now() - f.first < 10 * 60 * 1000) {
        return sendJson(res, 429, { error: 'Too many wrong attempts. Please wait a few minutes and try again.' });
      }
      const user = db.users[email];
      const hash = await hashPassword(password, user ? user.salt : 'dummysaltdummysalt');
      const ok = user && crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.hash, 'hex'));
      if (!ok) {
        const fresh = f && Date.now() - f.first < 10 * 60 * 1000;
        failed[email] = fresh ? { count: f.count + 1, first: f.first } : { count: 1, first: Date.now() };
        return sendJson(res, 401, { error: 'Wrong email or password.' });
      }
      delete failed[email];
      const token = createSession(email);
      return sendJson(res, 200, { name: user.name, email, state: user.state }, { 'Set-Cookie': cookieHeader(token, 30 * 24 * 3600) });
    }

    if (url === '/api/logout' && req.method === 'POST') {
      const token = getCookie(req, 'sid');
      if (token) { delete db.sessions[sha(token)]; saveDb(); }
      return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookieHeader('', 0) });
    }

    if (url === '/api/save' && req.method === 'POST') {
      const user = getUser(req);
      if (!user) return sendJson(res, 401, { error: 'Please log in again.' });
      const state = cleanState(await readJson(req));
      if (!state) return sendJson(res, 400, { error: 'Invalid data.' });
      user.state = state;
      saveDb();
      return sendJson(res, 200, { ok: true });
    }

    // Web pages: only index.html and the logo are ever handed out
    const name = url === '/' ? 'index.html' : path.basename(url);
    if (!types[path.extname(name)]) { res.writeHead(404); return res.end('Not found'); }
    fs.readFile(path.join(__dirname, name), (err, content) => {
      if (err) { res.writeHead(404); return res.end('Not found'); }
      res.writeHead(200, { 'Content-Type': types[path.extname(name)] });
      res.end(content);
    });
  } catch (e) {
    console.error(e);
    sendJson(res, 500, { error: e.message || 'Something went wrong.' });
  }
});

server.listen(3000, () => console.log('Finlect is running at http://localhost:3000'));