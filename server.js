'use strict';
/* Kowa Kowo – Sistem Absensi. Node.js 18+, tanpa library tambahan.
   Mendukung Upstash Redis (KV_REST_API_URL & KV_REST_API_TOKEN) di Vercel dan fallback data/db.json di lokal. */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const os = require('os');
const PORT = process.env.PORT || 3000;
const IS_VERCEL = Boolean(process.env.VERCEL);
const DATA = process.env.DATA_DIR || (IS_VERCEL ? path.join(os.tmpdir(), 'kowa-kowo-data') : path.join(__dirname, 'data'));
const TZ = +(process.env.TZ_OFFSET || 7); // WIB
const ADMIN_PIN = String(process.env.ADMIN_PIN || '1234');
if (!process.env.ADMIN_PIN) console.warn('PERINGATAN: ADMIN_PIN belum diatur, memakai 1234. Atur lewat environment variable ADMIN_PIN.');
fs.mkdirSync(DATA, { recursive: true });

/* ---------- kunci rahasia & database ---------- */
const KF = path.join(DATA, 'secret.key');
const SECRET = process.env.SECRET ? crypto.createHash('sha256').update(process.env.SECRET).digest()
  : (() => {
    try { return Buffer.from(fs.readFileSync(KF, 'utf8'), 'hex'); }
    catch (e) {
      if (IS_VERCEL) {
        console.warn('PERINGATAN: SECRET belum diatur di Vercel, memakai kunci sementara di memori.');
        return crypto.randomBytes(32);
      }
      const k = crypto.randomBytes(32);
      fs.writeFileSync(KF, k.toString('hex'), { mode: 0o600 });
      return k;
    }
  })();

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const USE_KV = Boolean(KV_URL && KV_TOKEN);
const KV_KEY = 'kowa-kowo-absensi:db';

const DBF = path.join(DATA, 'db.json');
const defaultDb = () => ({ employees: [], attendance: [], nextId: 1 });
const normalizeDb = raw => {
  const d = raw && typeof raw === 'object' ? raw : {};
  return {
    employees: Array.isArray(d.employees) ? d.employees : [],
    attendance: Array.isArray(d.attendance) ? d.attendance : [],
    nextId: Number.isFinite(d.nextId) && d.nextId > 0 ? d.nextId : 1
  };
};

let localDb = defaultDb();
try { localDb = normalizeDb(JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {}

async function kvCmd(args) {
  const r = await fetch(KV_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${KV_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(args)
  });
  if (!r.ok) throw new Error('KV HTTP ' + r.status);
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

async function loadDb() {
  if (!USE_KV) return localDb;
  const raw = await kvCmd(['GET', KV_KEY]);
  if (!raw) {
    const init = normalizeDb(localDb);
    await kvCmd(['SET', KV_KEY, JSON.stringify(init)]);
    return init;
  }
  return normalizeDb(typeof raw === 'string' ? JSON.parse(raw) : raw);
}

async function saveDb(db) {
  if (!USE_KV) {
    localDb = db;
    const t = DBF + '.tmp';
    fs.writeFileSync(t, JSON.stringify(db));
    fs.renameSync(t, DBF);
    return;
  }
  await kvCmd(['SET', KV_KEY, JSON.stringify(db)]);
}

/* password disimpan terenkripsi (AES-256-GCM), bisa dibaca admin, tidak tersimpan polos */
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', SECRET, iv); const b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), b].map(x => x.toString('base64')).join('.'); };
const dec = s => { try { const [iv, tag, b] = s.split('.').map(x => Buffer.from(x, 'base64')); const d = crypto.createDecipheriv('aes-256-gcm', SECRET, iv); d.setAuthTag(tag); return Buffer.concat([d.update(b), d.final()]).toString('utf8'); } catch (e) { return null; } };
const sign = p => { const b = Buffer.from(JSON.stringify(p)).toString('base64url'); return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); };
const verify = t => { try { const [b, s] = String(t).split('.'); const e = crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); if (!s || s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null; const p = JSON.parse(Buffer.from(b, 'base64url')); return p.exp > Date.now() ? p : null; } catch (e) { return null; } };
const same = (a, b) => { a = Buffer.from(String(a)); b = Buffer.from(String(b)); return a.length === b.length && crypto.timingSafeEqual(a, b); };

/* ---------- util ---------- */
const p2 = n => String(n).padStart(2, '0');
const wib = () => new Date(Date.now() + TZ * 36e5);
const ymd = d => d.getUTCFullYear() + '-' + p2(d.getUTCMonth() + 1) + '-' + p2(d.getUTCDate());
const hm = d => p2(d.getUTCHours()) + ':' + p2(d.getUTCMinutes());
const bd = () => ymd(new Date(Date.now() + (TZ - 6) * 36e5)); // hari kerja berganti 06.00
const mins = t => { const [a, b] = t.split(':'); return +a * 60 + +b; };
const dur = (i, o) => { if (!i || !o) return '-'; let m = mins(o) - mins(i); if (m < 0) m += 1440; return Math.floor(m / 60) + 'j ' + m % 60 + 'm'; };
const nk = s => String(s || '').trim().replace(/\s+/g, ' ').toLowerCase();
const cap = s => String(s || '').trim().replace(/\s+/g, ' ').replace(/(^|\s)(\S)/g, (m, a, b) => a + b.toUpperCase());
const normPw = s => String(s || '').replace(/\s/g, '').toUpperCase();
const genPw = () => { const c = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789', a = crypto.randomBytes(6); return [...a].map(x => c[x % c.length]).join(''); };
const NOTFOUND = 'Pengguna Tidak Ditemukan';

const fails = new Map();
const blocked = k => { const f = (fails.get(k) || []).filter(t => Date.now() - t < 6e5); fails.set(k, f); return f.length >= 8; };
const fail = k => fails.set(k, [...(fails.get(k) || []), Date.now()]);

const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(r => { let s = ''; req.on('data', c => { s += c; if (s.length > 1e5) req.destroy(); }); req.on('end', () => { try { r(JSON.parse(s || '{}')); } catch (e) { r({}); } }); });
const bearer = req => { const h = req.headers.authorization || ''; return h.startsWith('Bearer ') ? verify(h.slice(7)) : null; };
/* karyawan SELALU dicek ke database pada setiap permintaan: kalau sudah dihapus admin, langsung ditolak */
const empAuth = (req, db) => { const p = bearer(req); return p && p.t === 'emp' ? db.employees.find(e => e.id === p.id) || null : null; };
const admAuth = req => { const p = bearer(req); return !!p && p.t === 'adm'; };
const rowsOf = (db, month, empId) => db.attendance.filter(a => a.date.startsWith(month) && (!empId || a.emp === empId)).sort((a, b) => b.date.localeCompare(a.date));

/* ---------- API ---------- */
async function api(req, res, u, q) {
  const m = req.method, ip = req.socket.remoteAddress;

  if (m === 'POST' && u === '/api/admin/login') {
    const b = await readBody(req), key = ip + '|admin';
    if (blocked(key)) return json(res, 429, { error: 'Terlalu banyak percobaan. Coba lagi 10 menit lagi.' });
    if (!same(String(b.pin || ''), ADMIN_PIN)) { fail(key); return json(res, 401, { error: 'PIN salah' }); }
    return json(res, 200, { token: sign({ t: 'adm', exp: Date.now() + 30 * 864e5 }) });
  }

  const db = await loadDb();

  /* login karyawan: cari di database yang sama dengan panel admin */
  if (m === 'POST' && u === '/api/login') {
    const b = await readBody(req), key = ip + '|' + nk(b.name);
    if (blocked(key)) return json(res, 429, { error: 'Terlalu banyak percobaan. Coba lagi 10 menit lagi.' });
    const e = db.employees.find(x => nk(x.name) === nk(b.name));
    const plain = e ? dec(e.pw) : null;
    if (!e || !plain || !same(normPw(plain), normPw(b.password))) { fail(key); return json(res, 401, { error: NOTFOUND }); }
    return json(res, 200, { token: sign({ t: 'emp', id: e.id, exp: Date.now() + 30 * 864e5 }), name: e.name });
  }

  /* ----- area admin ----- */
  if (u.startsWith('/api/admin/')) {
    if (!admAuth(req)) return json(res, 401, { error: 'Belum login admin' });
    if (m === 'GET' && u === '/api/admin/employees')
      return json(res, 200, db.employees.map(e => ({ id: e.id, name: e.name, password: dec(e.pw) })));
    if (m === 'POST' && u === '/api/admin/employees') {
      const b = await readBody(req), name = cap(b.name), pw = b.password ? normPw(b.password) : genPw();
      if (name.length < 2) return json(res, 400, { error: 'Nama minimal 2 huruf' });
      if (!/^[A-Z0-9]{4,20}$/.test(pw)) return json(res, 400, { error: 'Password 4-20 karakter, hanya huruf dan angka' });
      if (db.employees.some(x => nk(x.name) === nk(name))) return json(res, 400, { error: 'Nama sudah dipakai karyawan lain' });
      const e = { id: db.nextId++, name, pw: enc(pw) }; db.employees.push(e); await saveDb(db);
      return json(res, 200, { id: e.id, name, password: pw });
    }
    const mm = u.match(/^\/api\/admin\/employees\/(\d+)$/);
    if (mm) {
      const e = db.employees.find(x => x.id === +mm[1]);
      if (!e) return json(res, 404, { error: NOTFOUND });
      if (m === 'PUT') {
        const b = await readBody(req);
        if (b.name !== undefined) {
          const name = cap(b.name);
          if (name.length < 2) return json(res, 400, { error: 'Nama minimal 2 huruf' });
          if (db.employees.some(x => x.id !== e.id && nk(x.name) === nk(name))) return json(res, 400, { error: 'Nama sudah dipakai karyawan lain' });
          e.name = name;
        }
        if (b.password) {
          const pw = normPw(b.password);
          if (!/^[A-Z0-9]{4,20}$/.test(pw)) return json(res, 400, { error: 'Password 4-20 karakter, hanya huruf dan angka' });
          e.pw = enc(pw); // password lama langsung tidak berlaku
        }
        await saveDb(db); return json(res, 200, { id: e.id, name: e.name, password: dec(e.pw) });
      }
      if (m === 'DELETE') { // hapus akun + riwayatnya; login dan sesi karyawan itu langsung mati
        db.employees = db.employees.filter(x => x.id !== e.id);
        db.attendance = db.attendance.filter(a => a.emp !== e.id);
        await saveDb(db); return json(res, 200, { ok: true });
      }
    }
    if (m === 'GET' && u === '/api/admin/dashboard') {
      const d = bd(), t = db.attendance.filter(a => a.date === d), n = wib(), nowM = n.getUTCHours() * 60 + n.getUTCMinutes();
      const name = id => (db.employees.find(e => e.id === id) || {}).name || '';
      return json(res, 200, {
        date: d, total: db.employees.length,
        hadir: t.filter(a => a.status === 'Hadir').length, izin: t.filter(a => a.status !== 'Hadir').length,
        belum: db.employees.filter(e => !t.some(a => a.emp === e.id)).map(e => e.name),
        bertugas: t.filter(a => a.in && !a.out).map(a => { let x = nowM - mins(a.in); if (x < 0) x += 1440; return { name: name(a.emp), in: a.in, lama: Math.floor(x / 60) + 'j ' + x % 60 + 'm' }; }),
        izinList: t.filter(a => a.status !== 'Hadir').map(a => ({ name: name(a.emp), status: a.status }))
      });
    }
    if (m === 'GET' && u === '/api/admin/riwayat') {
      const month = q.get('month') || ymd(wib()).slice(0, 7), id = +q.get('emp') || 0;
      return json(res, 200, rowsOf(db, month, id).map(a => ({ date: a.date, name: (db.employees.find(e => e.id === a.emp) || {}).name || '', in: a.in, out: a.out, dur: dur(a.in, a.out), status: a.status })));
    }
    return json(res, 404, { error: 'Tidak ditemukan' });
  }

  /* ----- area karyawan (wajib masih terdaftar di database) ----- */
  const e = empAuth(req, db);
  if (!e) return json(res, 401, { error: NOTFOUND });
  const today = () => db.attendance.find(a => a.emp === e.id && a.date === bd());
  if (m === 'GET' && u === '/api/me') { const t = today(); return json(res, 200, { name: e.name, date: bd(), today: t ? { in: t.in, out: t.out, status: t.status } : null }); }
  if (m === 'GET' && u === '/api/me/riwayat') {
    const rows = rowsOf(db, q.get('month') || ymd(wib()).slice(0, 7), e.id);
    return json(res, 200, { hadir: rows.filter(a => a.status === 'Hadir').length, izin: rows.filter(a => a.status !== 'Hadir').length, rows: rows.map(a => ({ date: a.date, in: a.in, out: a.out, dur: dur(a.in, a.out), status: a.status })) });
  }
  if (m === 'POST' && u === '/api/absen/masuk') {
    if (today()) return json(res, 400, { error: 'Kamu sudah absen hari ini' });
    const t = hm(wib()); db.attendance.push({ emp: e.id, date: bd(), in: t, out: '', status: 'Hadir' }); await saveDb(db); return json(res, 200, { in: t });
  }
  if (m === 'POST' && u === '/api/absen/pulang') {
    const t = today(); if (!t || !t.in) return json(res, 400, { error: 'Kamu belum absen masuk hari ini' });
    if (t.out) return json(res, 400, { error: 'Kamu sudah absen pulang' });
    t.out = hm(wib()); await saveDb(db); return json(res, 200, { out: t.out });
  }
  if (m === 'POST' && u === '/api/absen/izin') {
    const b = await readBody(req); if (!['Izin', 'Sakit'].includes(b.status)) return json(res, 400, { error: 'Status tidak valid' });
    if (today()) return json(res, 400, { error: 'Data hari ini sudah ada' });
    db.attendance.push({ emp: e.id, date: bd(), in: '', out: '', status: b.status }); await saveDb(db); return json(res, 200, { ok: true });
  }
  return json(res, 404, { error: 'Tidak ditemukan' });
}

/* ---------- file statis ---------- */
const PUB = path.join(__dirname, 'public');
const FILES = {
  '/': 'karyawan.html',
  '/karyawan': 'karyawan.html',
  '/admin': 'admin.html',
  '/style.css': 'style.css',
  '/logo.png': 'logo.png',
  '/manifest.json': 'manifest.json',
  '/sw.js': 'sw.js'
};
const TYPES = {
  html: 'text/html; charset=utf-8',
  css: 'text/css; charset=utf-8',
  png: 'image/png',
  json: 'application/json; charset=utf-8',
  js: 'application/javascript; charset=utf-8'
};

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'), u = url.pathname.replace(/(.)\/+$/, '$1');
    if (u.startsWith('/api/')) return await api(req, res, u, url.searchParams);
    const f = FILES[u]; if (!f) { res.writeHead(404); return res.end('Halaman tidak ditemukan'); }
    res.writeHead(200, { 'Content-Type': TYPES[f.split('.').pop()], 'Cache-Control': f.endsWith('.html') ? 'no-store' : 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' });
    fs.createReadStream(path.join(PUB, f)).pipe(res);
  } catch (e) { console.error(e); json(res, 500, { error: 'Kesalahan server' }); }
}).listen(PORT, () => console.log('Kowa Kowo Absensi berjalan di http://localhost:' + PORT + '  (karyawan: /   admin: /admin)'));