const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';
const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'access.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ members: [] }, null, 2));

function normalizeMember(m) {
  const status = m.status || (m.active ? 'approved' : (m.revokedAt ? 'revoked' : 'pending'));
  return {
    ...m,
    status,
    active: status === 'approved',
    normalizedEmail: cleanEmail(m.normalizedEmail || m.email),
    requestToken: m.requestToken || crypto.randomBytes(24).toString('base64url'),
    key: m.key || null,
    requestedAt: m.requestedAt || m.createdAt || Date.now(),
    approvedAt: m.approvedAt || (status === 'approved' ? (m.createdAt || Date.now()) : null),
    revokedAt: status === 'revoked' ? (m.revokedAt || Date.now()) : null,
  };
}
function loadDb() {
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (parsed && Array.isArray(parsed.members)) {
      let changed = false;
      const members = parsed.members.map(m => {
        const n = normalizeMember(m);
        if (!m.status || !m.requestToken || m.active !== n.active) changed = true;
        return n;
      });
      const db = { ...parsed, members };
      if (changed) saveDb(db);
      return db;
    }
  } catch (_) {}
  return { members: [] };
}
function saveDb(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
function corsHeaders(req) {
  const allowed = process.env.ALLOWED_ORIGIN || '*';
  const origin = req.headers.origin || '';
  const allowOrigin = allowed === '*' ? '*' : (origin === allowed ? origin : allowed);
  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,X-Admin-Password',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
function json(res, status, body, req) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...(req ? corsHeaders(req) : {})
  });
  res.end(JSON.stringify(body));
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function isAdmin(req) { return safeEqual(req.headers['x-admin-password'], ADMIN_PASSWORD); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => {
      raw += c;
      if (raw.length > 1024 * 1024) { reject(new Error('Body too large')); req.destroy(); }
    });
    req.on('end', () => {
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (_) { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}
function cleanName(v) { return String(v || '').trim().replace(/\s+/g, ' ').slice(0, 80); }
function cleanEmail(v) { return String(v || '').trim().toLowerCase().slice(0, 254); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function publicMember(m) {
  return {
    id: m.id,
    name: m.name || '',
    email: m.email || '',
    status: m.status || 'pending',
    active: m.status === 'approved',
    requestedAt: m.requestedAt || m.createdAt || null,
    createdAt: m.createdAt || m.requestedAt || null,
    approvedAt: m.approvedAt || null,
    revokedAt: m.revokedAt || null,
    lastAccessAt: m.lastAccessAt || null
  };
}
function findByEmail(db, email) {
  return db.members.find(m => cleanEmail(m.normalizedEmail || m.email) === email);
}
function contentType(file) {
  const ext = path.extname(file).toLowerCase();
  return ({ '.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon' })[ext] || 'application/octet-stream';
}
function serveFile(res, file) {
  if (!file.startsWith(PUBLIC_DIR)) return json(res, 403, { ok:false });
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { ok:false, message:'Not found' });
    res.writeHead(200, {
      'Content-Type': contentType(file),
      'Cache-Control': file.endsWith('.html') ? 'no-store' : 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, corsHeaders(req));
    return res.end();
  }
  if (pathname.startsWith('/api/')) {
    const originalWriteHead = res.writeHead.bind(res);
    res.writeHead = (statusCode, headers={}) => originalWriteHead(statusCode, { ...corsHeaders(req), ...headers });
  }

  try {
    if (req.method === 'GET' && pathname === '/health') return json(res, 200, { ok:true, service:'onlinenihogokyoshi-access-api' });
    if (req.method === 'POST' && pathname === '/api/access/register') {
      const body = await readBody(req);
      const name = cleanName(body.name);
      const email = cleanEmail(body.email);
      if (!name) return json(res, 400, { ok:false, status:'invalid', message:'名前を入力してください。' });
      if (!validEmail(email)) return json(res, 400, { ok:false, status:'invalid', message:'正しいメールアドレスを入力してください。' });

      const db = loadDb();
      let member = findByEmail(db, email);

      if (member) {
        member.name = name;
        member.email = email;
        member.normalizedEmail = email;
        if (!member.requestToken) member.requestToken = crypto.randomBytes(24).toString('base64url');

        if (member.status === 'approved') {
          if (!member.key) member.key = crypto.randomBytes(32).toString('base64url');
          saveDb(db);
          return json(res, 200, { ok:true, status:'approved', member: publicMember(member), key: member.key });
        }
        if (member.status === 'revoked') {
          saveDb(db);
          return json(res, 403, { ok:false, status:'revoked', message:'このメールアドレスのアクセスは停止されています。管理者にお問い合わせください。' });
        }

        saveDb(db);
        return json(res, 202, {
          ok:true,
          status:'pending',
          message:'アクセス申請は承認待ちです。管理者が承認すると利用できます。',
          member: publicMember(member),
          requestToken: member.requestToken
        });
      }

      member = normalizeMember({
        id: crypto.randomUUID(),
        name,
        email,
        normalizedEmail: email,
        status: 'pending',
        active: false,
        key: null,
        requestToken: crypto.randomBytes(24).toString('base64url'),
        requestedAt: Date.now(),
        createdAt: Date.now(),
        approvedAt: null,
        revokedAt: null,
        lastAccessAt: null
      });
      db.members.unshift(member);
      saveDb(db);
      return json(res, 202, {
        ok:true,
        status:'pending',
        message:'アクセス申請を受け付けました。管理者の承認後に利用できます。',
        member: publicMember(member),
        requestToken: member.requestToken
      });
    }

    if (req.method === 'POST' && pathname === '/api/access/status') {
      const body = await readBody(req);
      const requestToken = String(body.requestToken || '').trim();
      if (!requestToken) return json(res, 400, { ok:false, status:'invalid', message:'申請情報がありません。' });
      const db = loadDb();
      const member = db.members.find(m => m.requestToken && safeEqual(m.requestToken, requestToken));
      if (!member) return json(res, 404, { ok:false, status:'invalid', message:'申請情報が見つかりません。もう一度申請してください。' });
      if (member.status === 'revoked') return json(res, 403, { ok:false, status:'revoked', message:'この申請またはアクセスは管理者により停止されています。' });
      if (member.status !== 'approved') {
        return json(res, 200, { ok:true, status:'pending', member: publicMember(member) });
      }
      if (!member.key) {
        member.key = crypto.randomBytes(32).toString('base64url');
        saveDb(db);
      }
      return json(res, 200, { ok:true, status:'approved', member: publicMember(member), key: member.key });
    }

    if (req.method === 'POST' && pathname === '/api/access/verify') {
      const body = await readBody(req);
      const key = String(body.key || '').trim();
      if (!key) return json(res, 400, { ok:false, status:'invalid', message:'アクセス情報がありません。' });
      const db = loadDb();
      const member = db.members.find(m => m.key && safeEqual(m.key, key));
      if (!member) return json(res, 403, { ok:false, status:'invalid', message:'アクセス情報が無効です。もう一度名前とメールで申請してください。' });
      if (member.status !== 'approved') return json(res, 403, { ok:false, status:'revoked', message:'このアカウントは現在アクセスできません。' });
      const now = Date.now();
      if (!member.lastAccessAt || now - member.lastAccessAt > 60000) {
        member.lastAccessAt = now;
        saveDb(db);
      }
      return json(res, 200, { ok:true, status:'approved', member: publicMember(member) });
    }

    if (pathname.startsWith('/api/admin/')) {
      if (!isAdmin(req)) return json(res, 401, { ok:false, message:'管理者パスワードが違います。' });

      if (req.method === 'GET' && pathname === '/api/admin/members') {
        const db = loadDb();
        const rank = { pending:0, approved:1, revoked:2 };
        const members = db.members.slice().sort((a,b) => {
          const sr = (rank[a.status] ?? 9) - (rank[b.status] ?? 9);
          if (sr) return sr;
          return (b.requestedAt || b.createdAt || 0) - (a.requestedAt || a.createdAt || 0);
        }).map(publicMember);
        return json(res, 200, { ok:true, members });
      }

      const m = pathname.match(/^\/api\/admin\/members\/([^/]+)\/(approve|revoke|reactivate)$/);
      if (req.method === 'POST' && m) {
        const db = loadDb();
        const member = db.members.find(x => x.id === m[1]);
        if (!member) return json(res, 404, { ok:false, message:'会員が見つかりません。' });
        const action = m[2];
        if (action === 'approve') {
          member.status = 'approved';
          member.active = true;
          member.approvedAt = Date.now();
          member.revokedAt = null;
          member.key = crypto.randomBytes(32).toString('base64url');
        } else if (action === 'revoke') {
          member.status = 'revoked';
          member.active = false;
          member.revokedAt = Date.now();
        } else {
          member.status = 'approved';
          member.active = true;
          member.approvedAt = member.approvedAt || Date.now();
          member.revokedAt = null;
          member.key = crypto.randomBytes(32).toString('base64url');
        }
        saveDb(db);
        return json(res, 200, { ok:true, member: publicMember(member) });
      }

      return json(res, 404, { ok:false, message:'Admin endpoint not found' });
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { ok:false, message:'Method not allowed' });
    if (pathname === '/' || pathname === '/onlinenihogokyoshi-classroom.html') return serveFile(res, path.join(PUBLIC_DIR, 'onlinenihogokyoshi-classroom.html'));
    if (pathname === '/admin' || pathname === '/onlinenihogokyoshi-admin.html') return serveFile(res, path.join(PUBLIC_DIR, 'onlinenihogokyoshi-admin.html'));

    const normalized = path.normalize(pathname).replace(/^([.][.][/\\])+/, '');
    const file = path.join(PUBLIC_DIR, normalized);
    return serveFile(res, file);
  } catch (err) {
    console.error(err);
    return json(res, 500, { ok:false, message:'Server error' });
  }
});

server.listen(PORT, HOST, () => {
  console.log(`onlinenihogokyoshi Classroom: http://localhost:${PORT}`);
  console.log(`onlinenihogokyoshi Admin: http://localhost:${PORT}/admin`);
  if (ADMIN_PASSWORD === 'change-me-now') console.warn('WARNING: Set ADMIN_PASSWORD before public deployment.');
});
