'use strict';
/* نظام إدارة المعارض - سيرفر Node.js بدون أي مكتبات خارجية */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PUB = path.join(__dirname, 'public');
fs.mkdirSync(path.join(DATA, 'docs'), { recursive: true });

/* ---------- الصلاحيات (تُمنح بالـ ID من حساب الإدارة) ---------- */
const PERM_LIST = [
  ['view', 'عرض السيارات المتاحة'],
  ['reserve', 'حجز السيارات وقائمة الانتظار'],
  ['discount', 'طلب خصم'],
  ['stock', 'إدخال سيارات (برقم الشاسيه)'],
  ['purchase', 'المشتريات: إضافة سيارات جار الوصول والأسعار'],
  ['confirm', 'تأكيد العربون ورفض الحجز'],
  ['sell', 'تسجيل البيع (كاش / بنك)'],
  ['reports', 'المبيعات والتصدير'],
  ['dash', 'لوحة المؤشرات والمخزون الكامل وسعر الشراء'],
  ['approve', 'الموافقة على طلبات الخصم'],
];
const PERM_KEYS = PERM_LIST.map(p => p[0]);
const PERM_LABEL = Object.fromEntries(PERM_LIST);
const MK = ['خليجي', 'سعودي'];

/* ---------- التخزين (ملفات JSON بكتابة آمنة) ---------- */
const F = { db: path.join(DATA, 'db.json'), hist: path.join(DATA, 'history.json'), ses: path.join(DATA, 'sessions.json') };
const readJ = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return d; } };
const writeJ = (f, o) => { const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(o)); fs.renameSync(t, f); };
let db = readJ(F.db, null) || { rev: 1, nuid: 1001, nid: 1, users: [], cars: [], reqs: [], disc: [], sales: [], wait: [], notes: [] };
let hist = readJ(F.hist, []);
let sess = readJ(F.ses, {});
for (const k of Object.keys(sess)) if (sess[k].exp < Date.now()) delete sess[k];
const persist = withHist => { writeJ(F.db, db); if (withHist) writeJ(F.hist, hist); };
const saveSess = () => writeJ(F.ses, sess);

const KEYS = ['nid', 'cars', 'reqs', 'disc', 'sales', 'wait', 'notes'];
const snapshot = () => JSON.stringify(Object.fromEntries(KEYS.map(k => [k, db[k]])));
const restore = s => { const o = JSON.parse(s); KEYS.forEach(k => { db[k] = o[k]; }); };
const hid = () => crypto.randomBytes(6).toString('hex');
const pushHist = (user, tx, snap, info) => { hist.unshift({ id: hid(), ts: Date.now(), uid: user.id, who: user.name, tx, snap, info: !!info }); if (hist.length > 60) hist.length = 60; };

/* ينفّذ تعديلاً على البيانات: fn تُرجع [نص السجل, النتيجة]. عند الخطأ يُرجع كل شيء كما كان */
function mutate(user, fn) {
  const before = snapshot();
  let out;
  try { out = fn(); } catch (e) { restore(before); throw e; }
  pushHist(user, out[0], before, false);
  db.rev++; persist(true);
  return out[1];
}
function logInfo(user, tx) { pushHist(user, tx, snapshot(), true); db.rev++; persist(true); }

/* ---------- أدوات ---------- */
class ApiErr extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const bad = (m, c = 400) => { throw new ApiErr(c, m); };
const has = (u, p) => u.admin || u.perms.includes(p);
const need = (u, ...ps) => { if (!ps.some(p => has(u, p))) bad('لا تملك صلاحية لهذا الإجراء', 403); };
const S = (v, max = 100, req = true, label = 'الحقل') => {
  v = String(v ?? '').trim().replace(/\s+/g, ' ');
  if (req && !v) bad(label + ' مطلوب');
  if (v.length > max) bad(label + ' طويل جداً');
  return v;
};
const N = (v, label, min = 0, max = 1e9) => {
  const n = Number(v);
  if (v === '' || v == null || !Number.isFinite(n) || n < min || n > max) bad(label + ' غير صحيح');
  return n;
};
const nem = e => String(e || '').trim().toLowerCase();
const nph = p => String(p || '').replace(/\D/g, '').slice(-9);
const EM = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const nm = c => `${c.b} ${c.m} ${c.t}`;
const kf = c => [c.b, c.m, c.t, c.k, c.c, c.y, c.h, c.n, c.o].join('|');
const note = (uid, text) => db.notes.unshift({ id: db.nid++, uid, text, ts: Date.now() });
const AD = c => db.disc.find(x => !x.used && x.uid === c.rvid && x.key === kf(c) && (x.st === 'ok' || x.st === 'auto'));
const parseIds = s => { const a = String(s).split(',').map(Number); if (!a.length || a.length > 300 || a.some(n => !Number.isInteger(n))) bad('طلب غير صالح'); return a; };
const carsOf = ids => ids.map(i => db.cars.find(c => c.id === i) || bad('السيارة غير موجودة', 404));

/* ---------- كلمات المرور والجلسات ---------- */
const hashPw = (pw, salt = crypto.randomBytes(16).toString('hex')) => ({ salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') });
const checkPw = (pw, o) => { const h = crypto.scryptSync(pw, o.salt, 64), e = Buffer.from(o.hash, 'hex'); return e.length === h.length && crypto.timingSafeEqual(h, e); };
const DUMMY = hashPw('dummy-password');
const tokH = t => crypto.createHash('sha256').update(t).digest('hex');
function newSession(uid, remember) {
  const t = crypto.randomBytes(32).toString('hex');
  sess[tokH(t)] = { uid, exp: Date.now() + (remember ? 30 * 864e5 : 12 * 36e5), r: remember ? 1 : 0 };
  saveSess(); return t;
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split('=')).filter(a => a[0]).map(a => [a[0], a.slice(1).join('=')]));
const getUser = req => {
  const c = cookies(req).sid; if (!c) return null;
  const k = tokH(c), s = sess[k]; if (!s) return null;
  if (s.exp < Date.now()) { delete sess[k]; saveSess(); return null; }
  const u = db.users.find(x => x.id === s.uid);
  return u && u.active ? u : null;
};
const isHttps = req => !!req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https';
const setSid = (req, res, tok, remember) => res.setHeader('Set-Cookie', `sid=${tok}; HttpOnly; SameSite=Lax; Path=/${remember ? '; Max-Age=' + 30 * 86400 : ''}${isHttps(req) ? '; Secure' : ''}`);
const killSessions = (uid, exceptKey) => { for (const k of Object.keys(sess)) if (sess[k].uid === uid && k !== exceptKey) delete sess[k]; saveSess(); };

const fails = new Map();
const limited = k => { const f = fails.get(k); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0; };
const addFail = (k, max = 5) => { const f = fails.get(k) || { n: 0, until: 0 }; if (++f.n >= max) { f.n = 0; f.until = Date.now() + 60000; } fails.set(k, f); };
setInterval(() => fails.clear(), 10 * 60 * 1000).unref();
const regs = new Map();
setInterval(() => regs.clear(), 60 * 60 * 1000).unref();
const ipOf = req => (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || '?';

const pub = u => ({ id: u.id, name: u.name, email: u.email, phone: u.phone, admin: u.admin, active: u.active, perms: u.perms });

/* ---------- ما يراه كل مستخدم حسب صلاحياته ---------- */
function proj(c, u) {
  const full = has(u, 'dash'), own = c.addedBy === u.id;
  const o = { id: c.id, b: c.b, m: c.m, t: c.t, k: c.k, c: c.c, y: c.y, h: c.h, n: c.n, o: c.o, s: c.s, g: c.g, by: c.by, mine: own, a: Math.floor((Date.now() - c.dt) / 864e5) };
  if (c.s === 'reserved' && (full || has(u, 'confirm') || has(u, 'sell') || c.rvid === u.id)) { o.rv = c.rv; o.rs = c.rs; o.rvid = c.rvid; }
  if (full || own) { o.p = c.p; o.vin = c.vin; o.dt = c.dt; o.docs = c.docs; }
  if (full || has(u, 'purchase')) { o.sup = c.sup; o.sph = c.sph; }
  if (c.s === 'reserved' && (full || has(u, 'sell') || has(u, 'confirm'))) { const d = AD(c); if (d) o.ad = { id: d.id, amt: d.amt }; }
  return o;
}
function visible(c, u) {
  if (has(u, 'dash')) return true;
  if ((has(u, 'view') || has(u, 'reserve') || has(u, 'discount')) && (c.s === 'available' || c.s === 'incoming')) return true;
  if (c.addedBy === u.id && c.s !== 'sold') return true;
  if (has(u, 'purchase') && c.s !== 'sold') return true;
  if ((has(u, 'confirm') || has(u, 'sell')) && c.s === 'reserved') return true;
  return c.s === 'reserved' && c.rvid === u.id;
}
function buildState(u) {
  const o = { rev: db.rev, me: pub(u), permList: PERM_LIST };
  o.cars = db.cars.filter(c => visible(c, u)).map(c => proj(c, u));
  const allReq = has(u, 'confirm') || has(u, 'sell') || has(u, 'dash');
  o.reqs = db.reqs.filter(r => allReq || r.uid === u.id);
  o.disc = db.disc.filter(d => has(u, 'approve') || has(u, 'dash') || d.uid === u.id).map(({ key, ...d }) => d);
  o.sales = has(u, 'reports') || has(u, 'dash') ? db.sales : [];
  o.notes = db.notes.filter(n => n.uid === u.id);
  if (has(u, 'sell')) o.reps = db.users.filter(x => x.active && (x.admin || x.perms.includes('reserve'))).map(x => ({ id: x.id, name: x.name }));
  o.pendingReqs = has(u, 'confirm') ? db.reqs.filter(r => r.st === 'pending').length : 0;
  o.pendingDisc = has(u, 'approve') ? db.disc.filter(d => d.st === 'pending').length : 0;
  if (u.admin) {
    o.users = db.users.map(x => ({ ...pub(x), created: x.created }));
    o.hist = hist.map(h => ({ id: h.id, ts: h.ts, who: h.who, tx: h.tx, info: h.info }));
  }
  return o;
}

/* ---------- المستندات (صور / PDF) ---------- */
const DOC_RE = /^data:(image\/(?:jpeg|png|webp)|application\/pdf);base64,([A-Za-z0-9+/=]+)$/;
function checkDocs(arr) {
  if (!Array.isArray(arr)) return [];
  if (arr.length > 8) bad('الحد الأقصى 8 مستندات');
  return arr.map(d => {
    const m = DOC_RE.exec(String(d && d.d || ''));
    if (!m) bad('نوع المستند غير مسموح (صور أو PDF فقط)');
    const buf = Buffer.from(m[2], 'base64');
    if (buf.length > 1.5e6) bad('حجم المستند كبير');
    return { n: S(d.n, 80, false) || 'مستند', t: m[1], buf };
  });
}

/* ---------- واجهة الـ API ---------- */
async function api(req, res, url, p) {
  const user = getUser(req);
  let body = {};
  if (req.method === 'POST') {
    const o = req.headers.origin;
    if (o) { let ok = false; try { ok = new URL(o).host === req.headers.host; } catch { } if (!ok) bad('طلب غير مسموح', 403); }
    if (!String(req.headers['content-type'] || '').startsWith('application/json')) bad('طلب غير صالح');
    body = await readBody(req);
  }
  const m = req.method + ' ' + p;

  /* --- عام: تسجيل وحسابات --- */
  if (m === 'POST /api/register') {
    const ip = ipOf(req), r = regs.get(ip) || 0;
    if (r >= 10) bad('محاولات تسجيل كثيرة، حاول لاحقاً', 429);
    const name = S(body.name, 60, true, 'الاسم'), email = nem(body.email), phone = String(body.phone || '').replace(/[^\d+]/g, ''), pw = String(body.password || '');
    if (!EM.test(email) || email.length > 120) bad('البريد الإلكتروني غير صحيح');
    if (nph(phone).length < 9 || phone.length > 16) bad('رقم الجوال غير صحيح');
    if (pw.length < 6 || pw.length > 100) bad('كلمة المرور 6 أحرف على الأقل');
    if (db.users.some(x => x.email === email)) bad('هذا البريد مسجل مسبقاً', 409);
    if (db.users.some(x => nph(x.phone) === nph(phone))) bad('رقم الجوال مسجل مسبقاً', 409);
    regs.set(ip, r + 1);
    const first = db.users.length === 0;
    const u = { id: db.nuid++, name, email, phone, pw: hashPw(pw), active: true, admin: first, perms: [], created: Date.now() };
    db.users.push(u);
    logInfo(u, first ? `إنشاء أول حساب (إدارة): ${name}` : `تسجيل حساب جديد: ${name} (ID ${u.id})`);
    const rem = !!body.remember;
    setSid(req, res, newSession(u.id, rem), rem);
    return send(res, 200, { user: pub(u) });
  }
  if (m === 'POST /api/login') {
    const idn = S(body.uid, 120, true, 'البريد أو رقم الجوال'), pw = String(body.password || '');
    const k1 = 'ip:' + ipOf(req), k2 = 'id:' + idn.toLowerCase();
    const w = Math.max(limited(k1), limited(k2));
    if (w) bad(`محاولات كثيرة، انتظر ${w} ثانية`, 429);
    const u = idn.includes('@') ? db.users.find(x => x.email === nem(idn)) : (nph(idn).length >= 9 ? db.users.find(x => nph(x.phone) === nph(idn)) : null);
    const ok = u ? checkPw(pw, u.pw) : (checkPw(pw, DUMMY), false);
    if (!u || !ok) { addFail(k1, 30); addFail(k2, 5); bad('بيانات الدخول غير صحيحة', 401); }
    if (!u.active) bad('هذا الحساب موقوف، تواصل مع الإدارة', 403);
    fails.delete(k1); fails.delete(k2);
    const rem = !!body.remember;
    setSid(req, res, newSession(u.id, rem), rem);
    return send(res, 200, { user: pub(u) });
  }
  if (m === 'POST /api/logout') {
    const c = cookies(req).sid; if (c) { delete sess[tokH(c)]; saveSess(); }
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    return send(res, 200, { ok: true });
  }
  if (m === 'GET /api/me') return send(res, 200, { user: user ? pub(user) : null });

  if (!user) bad('يلزم تسجيل الدخول', 401);

  if (m === 'GET /api/state') {
    if (url.searchParams.get('rev') === String(db.rev)) return send(res, 200, { same: true });
    return send(res, 200, buildState(user));
  }
  if (m === 'POST /api/password') {
    const np = String(body.new || '');
    if (!checkPw(String(body.old || ''), user.pw)) bad('كلمة المرور الحالية غير صحيحة');
    if (np.length < 6 || np.length > 100) bad('كلمة المرور الجديدة 6 أحرف على الأقل');
    user.pw = hashPw(np);
    killSessions(user.id, tokH(cookies(req).sid));
    db.rev++; persist(false);
    return send(res, 200, { ok: true });
  }

  /* --- المستندات --- */
  const dm = p.match(/^\/api\/docs\/([\w.-]+)$/);
  if (dm && req.method === 'GET') {
    const c = db.cars.find(x => (x.docs || []).some(d => d.k === dm[1]));
    if (!c) bad('غير موجود', 404);
    if (!(has(user, 'dash') || c.addedBy === user.id)) bad('لا تملك صلاحية', 403);
    const d = c.docs.find(x => x.k === dm[1]);
    let buf; try { buf = fs.readFileSync(path.join(DATA, 'docs', d.k)); } catch { bad('الملف غير موجود', 404); }
    res.writeHead(200, { 'Content-Type': d.t, 'Content-Length': buf.length, 'Cache-Control': 'private, max-age=3600', 'Content-Disposition': `${url.searchParams.get('dl') ? 'attachment' : 'inline'}; filename*=UTF-8''${encodeURIComponent(d.n)}` });
    return res.end(buf);
  }

  /* --- إضافة سيارة --- */
  if (m === 'POST /api/cars') {
    const inc = body.mode === 'incoming';
    need(user, inc ? 'purchase' : 'stock');
    let b = S(body.b, 40, true, 'الماركة');
    const mo = S(body.m, 40, true, 'الموديل'), t = S(body.t, 40, true, 'الفئة'), col = S(body.c, 30, true, 'اللون');
    const k = MK.includes(body.k) ? body.k : bad('المواصفات غير صحيحة');
    const y = N(body.y, 'سنة الصنع', 1990, 2100), p = N(body.p, 'سعر الشراء'), h = N(body.h, 'سعر الكاش'), n = N(body.n, 'سعر البنك');
    const o = S(body.o, 120, false);
    let vin = '', g = '', sup = '', sph = '', qty = 1;
    if (inc) { g = S(body.g, 60, true, 'مرحلة الوصول'); sup = S(body.sup, 80, true, 'اسم الجهة'); sph = S(body.sph, 30, true, 'رقم تواصل الجهة'); qty = Math.floor(N(body.qty ?? 1, 'العدد', 1, 50)); }
    else { vin = S(body.vin, 40, true, 'رقم الشاسيه'); if (db.cars.some(c => c.vin && c.vin.toLowerCase() === vin.toLowerCase())) bad('رقم الشاسيه مسجل مسبقاً', 409); }
    const docs = checkDocs(body.docs);
    return send(res, 200, mutate(user, () => {
      const ex = db.cars.find(c => c.b.toLowerCase() === b.toLowerCase()); if (ex) b = ex.b;
      const first = db.nid;
      for (let i = 0; i < qty; i++) {
        const id = db.nid++;
        const dl = docs.map((d, j) => {
          const key = `d${id}_${j}_${crypto.randomBytes(4).toString('hex')}`;
          fs.writeFileSync(path.join(DATA, 'docs', key), d.buf);
          return { k: key, n: d.n, t: d.t };
        });
        db.cars.push({ id, b, m: mo, t, k, c: col, y, p, h, n, s: inc ? 'incoming' : 'available', o, g, by: inc ? 'purchase' : 'stock', vin, dt: Date.now(), docs: dl, sup, sph, addedBy: user.id, rv: '', rvid: 0, rs: '' });
      }
      return [`إضافة ${b} ${mo} ${t}${qty > 1 ? ' (×' + qty + ')' : ''}${vin ? ' · شاسيه ' + vin : ''}${docs.length ? ' · ' + docs.length + ' مستند' : ''}`, { ok: true, first }];
    }));
  }

  let mm;
  /* --- عمليات على سيارات / مجموعات --- */
  if ((mm = p.match(/^\/api\/cars\/([\d,]+)\/(prices|arrive|delete|reserve|cancel|sell|discount|waitlist)$/)) && req.method === 'POST') {
    const ids = parseIds(mm[1]), act = mm[2];

    if (act === 'prices') {
      need(user, 'purchase');
      const g = carsOf(ids), h = N(body.h, 'سعر الكاش'), n = N(body.n, 'سعر البنك');
      const stage = body.g === undefined ? null : S(body.g, 60, false);
      if (g.some(c => c.s === 'sold')) bad('لا يمكن تعديل سيارة مباعة');
      return send(res, 200, mutate(user, () => {
        const c0 = g[0], old = `كاش ${c0.h} ← ${h} · بنك ${c0.n} ← ${n}`;
        g.forEach(c => { c.h = h; c.n = n; if (stage !== null && c.s === 'incoming') c.g = stage; });
        return [`تحديث ${nm(c0)}${g.length > 1 ? ' (×' + g.length + ')' : ''}: ${old}${stage ? ' · المرحلة: ' + stage : ''}`, { ok: true }];
      }));
    }
    if (act === 'arrive') {
      need(user, 'purchase');
      const g = carsOf(ids); if (g.some(c => c.s !== 'incoming')) bad('السيارة ليست بحالة جار الوصول');
      return send(res, 200, mutate(user, () => {
        const c0 = g[0];
        g.forEach(c => { c.s = 'available'; c.g = ''; c.dt = Date.now(); });
        const hit = db.wait.filter(w => w.b === c0.b && w.m === c0.m);
        hit.forEach(w => note(w.uid, `وصلت ${nm(c0)} المطلوبة للعميل ${w.cu}`));
        db.wait = db.wait.filter(w => !hit.includes(w));
        return [`وصول ${nm(c0)}${g.length > 1 ? ' (×' + g.length + ')' : ''}`, { ok: true }];
      }));
    }
    if (act === 'delete') {
      need(user, 'purchase');
      const g = carsOf(ids);
      if (g.some(c => c.by !== 'purchase' || (c.addedBy !== user.id && !user.admin))) bad('لا يمكنك حذف سيارة لم تضفها', 403);
      if (g.some(c => c.s === 'reserved' || c.s === 'sold')) bad('لا يمكن حذف سيارة محجوزة أو مباعة');
      return send(res, 200, mutate(user, () => { db.cars = db.cars.filter(c => !ids.includes(c.id)); return [`حذف ${nm(g[0])}${g.length > 1 ? ' (×' + g.length + ')' : ''}`, { ok: true }]; }));
    }
    if (ids.length !== 1) bad('طلب غير صالح');
    const c0 = carsOf(ids)[0];

    if (act === 'reserve') {
      need(user, 'reserve');
      if (c0.s !== 'available') bad('السيارة غير متاحة للحجز');
      const bu = S(body.bu, 80, false), ph = S(body.ph, 30, false), det = S(body.det, 120, false);
      const dep = body.dep === 'yes' ? 'yes' : 'no', amt = dep === 'yes' ? N(body.amt, 'المبلغ المحوّل', 1) : 0;
      return send(res, 200, mutate(user, () => {
        const k = kf(c0), c = db.cars.filter(x => x.s === 'available' && kf(x) === k).sort((a, b) => a.dt - b.dt)[0];
        if (!c) bad('لم تعد السيارة متاحة، حجزها مندوب آخر', 409);
        c.s = 'reserved'; c.rv = user.name; c.rvid = user.id; c.rs = 'pending';
        db.reqs.unshift({ id: db.nid++, cid: c.id, nm: `${nm(c)} · ${c.c}`, rep: user.name, uid: user.id, bu, ph, dep, amt, det, st: 'pending', ts: Date.now() });
        return [`طلب حجز ${nm(c)} · ${c.c}`, { ok: true }];
      }));
    }
    if (act === 'cancel') {
      if (!user.admin) bad('إلغاء الحجز للإدارة فقط', 403);
      if (c0.s !== 'reserved') bad('السيارة ليست محجوزة');
      return send(res, 200, mutate(user, () => {
        const r = db.reqs.find(x => x.cid === c0.id && (x.st === 'pending' || x.st === 'held')); if (r) r.st = 'cx';
        if (c0.rvid) note(c0.rvid, `أُلغي حجز ${nm(c0)} · ${c0.c}`);
        c0.s = 'available'; c0.rv = ''; c0.rvid = 0; c0.rs = '';
        return [`إلغاء حجز ${nm(c0)}`, { ok: true }];
      }));
    }
    if (act === 'sell') {
      need(user, 'sell');
      if (c0.s !== 'reserved') bad('السيارة ليست محجوزة');
      const type = ['كاش', 'بنك'].includes(body.type) ? body.type : bad('اختر طريقة البيع: كاش أو بنك');
      const price = N(body.price, 'سعر البيع');
      const rep = db.users.find(x => x.id === Number(body.repId)) || bad('اختر المندوب');
      return send(res, 200, mutate(user, () => {
        const dd = AD(c0); if (dd) dd.used = true;
        const rq = db.reqs.find(x => x.cid === c0.id && (x.st === 'held' || x.st === 'pending')); if (rq) rq.st = 'sold';
        c0.s = 'sold'; c0.rs = '';
        db.sales.unshift({ id: db.nid++, cid: c0.id, nm: `${nm(c0)} · ${c0.c}`, rep: rep.name, repId: rep.id, price, p: c0.p, type, disc: dd ? dd.amt : 0, ts: Date.now() });
        note(rep.id, `تم بيع ${nm(c0)} · ${c0.c} (${type})`);
        return [`بيع ${nm(c0)} · ${c0.c} (${type}) بسعر ${price.toLocaleString('en-US')}`, { ok: true }];
      }));
    }
    if (act === 'discount') {
      need(user, 'discount');
      if (c0.s !== 'available') bad('الخصم يُطلب على سيارة متاحة');
      const amt = N(body.amt, 'مبلغ الخصم', 1, c0.h), why = S(body.why, 120, true, 'السبب');
      return send(res, 200, mutate(user, () => {
        db.disc.unshift({ id: db.nid++, cid: c0.id, key: kf(c0), nm: `${nm(c0)} · ${c0.c}`, rep: user.name, uid: user.id, amt, why, st: 'pending', ts: Date.now() });
        return [`طلب خصم ${amt.toLocaleString('en-US')} على ${nm(c0)}`, { ok: true }];
      }));
    }
    if (act === 'waitlist') {
      need(user, 'reserve');
      if (c0.s !== 'incoming') bad('السيارة متاحة بالفعل');
      const cu = S(body.cu, 80, true, 'اسم العميل');
      return send(res, 200, mutate(user, () => { db.wait.unshift({ b: c0.b, m: c0.m, cu, uid: user.id, ts: Date.now() }); return [`قائمة انتظار: ${cu} · ${c0.b} ${c0.m}`, { ok: true }]; }));
    }
  }

  /* --- طلبات الحجز (المحاسب) --- */
  if ((mm = p.match(/^\/api\/reqs\/(\d+)\/(confirm|reject)$/)) && req.method === 'POST') {
    need(user, 'confirm');
    const r = db.reqs.find(x => x.id === +mm[1]) || bad('الطلب غير موجود', 404);
    if (r.st !== 'pending') bad('تمت معالجة هذا الطلب مسبقاً');
    return send(res, 200, mutate(user, () => {
      const c = db.cars.find(x => x.id === r.cid);
      if (mm[2] === 'confirm') {
        r.st = 'held'; if (c) c.rs = 'held'; note(r.uid, `تم تأكيد حجز ${r.nm}`);
        return [`تأكيد حجز ${r.nm}`, { ok: true }];
      }
      r.st = 'rej'; if (c) { c.s = 'available'; c.rv = ''; c.rvid = 0; c.rs = ''; } note(r.uid, `رُفض حجز ${r.nm}`);
      return [`رفض حجز ${r.nm}`, { ok: true }];
    }));
  }

  /* --- الخصم (الإدارة) --- */
  if ((mm = p.match(/^\/api\/discounts\/(\d+)\/decide$/)) && req.method === 'POST') {
    need(user, 'approve');
    const d = db.disc.find(x => x.id === +mm[1]) || bad('الطلب غير موجود', 404);
    if (d.st !== 'pending') bad('تمت معالجة هذا الطلب مسبقاً');
    const ok = !!body.ok;
    return send(res, 200, mutate(user, () => {
      d.st = ok ? 'ok' : 'no';
      note(d.uid, `${ok ? 'تمت الموافقة على' : 'رُفض'} خصم ${d.amt.toLocaleString('en-US')} على ${d.nm}`);
      return [`${ok ? 'موافقة على' : 'رفض'} خصم ${d.amt.toLocaleString('en-US')} لـ ${d.rep} (${d.nm})`, { ok: true }];
    }));
  }

  /* --- الإشعارات --- */
  if ((mm = p.match(/^\/api\/notes\/(\d+)\/dismiss$/)) && req.method === 'POST') {
    db.notes = db.notes.filter(n => !(n.id === +mm[1] && n.uid === user.id));
    db.rev++; persist(false);
    return send(res, 200, { ok: true });
  }

  /* --- إدارة المستخدمين بالـ ID (للإدارة فقط) --- */
  if ((mm = p.match(/^\/api\/users\/(\d+)$/)) && req.method === 'POST') {
    if (!user.admin) bad('هذا الإجراء للإدارة فقط', 403);
    const t = db.users.find(x => x.id === +mm[1]) || bad('المستخدم غير موجود', 404);
    const self = t.id === user.id;
    const name = S(body.name, 60, true, 'الاسم'), email = nem(body.email), phone = String(body.phone || '').replace(/[^\d+]/g, '');
    if (!EM.test(email)) bad('البريد الإلكتروني غير صحيح');
    if (nph(phone).length < 9) bad('رقم الجوال غير صحيح');
    if (db.users.some(x => x.id !== t.id && (x.email === email || nph(x.phone) === nph(phone)))) bad('البريد أو الجوال مستخدم لحساب آخر', 409);
    const perms = (Array.isArray(body.perms) ? body.perms : []).filter(k => PERM_KEYS.includes(k));
    const admin = self ? true : !!body.admin, active = self ? true : !!body.active;
    if (body.password && (String(body.password).length < 6 || String(body.password).length > 100)) bad('كلمة المرور 6 أحرف على الأقل');
    if (!admin && t.admin && db.users.filter(x => x.admin && x.active && x.id !== t.id).length === 0) bad('يجب بقاء مدير واحد فعّال على الأقل');
    const ch = [];
    const added = perms.filter(k => !t.perms.includes(k)), removed = t.perms.filter(k => !perms.includes(k));
    if (added.length) ch.push('منح: ' + added.map(k => PERM_LABEL[k]).join('، '));
    if (removed.length) ch.push('سحب: ' + removed.map(k => PERM_LABEL[k]).join('، '));
    if (admin !== t.admin) ch.push(admin ? 'منح صلاحية الإدارة الكاملة' : 'سحب صلاحية الإدارة');
    if (active !== t.active) ch.push(active ? 'تفعيل الحساب' : 'إيقاف الحساب');
    if (body.password) ch.push('تغيير كلمة المرور');
    if (name !== t.name || email !== t.email || nph(phone) !== nph(t.phone)) ch.push('تعديل البيانات');
    Object.assign(t, { name, email, phone, perms, admin, active });
    if (body.password) { t.pw = hashPw(String(body.password)); killSessions(t.id, self ? tokH(cookies(req).sid) : undefined); }
    if (!active) killSessions(t.id);
    logInfo(user, `حساب ${t.name} (ID ${t.id}): ${ch.join(' · ') || 'بدون تغيير'}`);
    return send(res, 200, { ok: true });
  }

  /* --- سجل العمليات والاسترجاع (للإدارة فقط) --- */
  if ((mm = p.match(/^\/api\/history\/([0-9a-f]+)\/restore$/)) && req.method === 'POST') {
    if (!user.admin) bad('الاسترجاع للإدارة فقط', 403);
    const k = hist.findIndex(x => x.id === mm[1]); if (k < 0) bad('الخطوة غير موجودة', 404);
    const h = hist[k], before = body.when === 'before';
    const sn = before ? h.snap : (k > 0 ? hist[k - 1].snap : snapshot());
    const cur = snapshot();
    restore(sn);
    pushHist(user, (before ? 'تراجع عن: ' : 'رجوع إلى: ') + h.tx, cur, false);
    db.rev++; persist(true);
    return send(res, 200, { ok: true });
  }

  bad('غير موجود', 404);
}

function readBody(req, limit = 14e6) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', d => { n += d.length; if (n > limit) { no(new ApiErr(413, 'الحجم كبير جداً')); req.destroy(); return; } ch.push(d); });
    req.on('end', () => { try { ok(ch.length ? JSON.parse(Buffer.concat(ch).toString('utf8')) : {}); } catch { no(new ApiErr(400, 'طلب غير صالح')); } });
    req.on('error', no);
  });
}
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };

/* ---------- الملفات الثابتة ---------- */
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
function serveStatic(req, res, p) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  if (p === '/') p = '/index.html';
  const f = path.join(PUB, path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
  if (!f.startsWith(PUB + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(f, (e, buf) => {
    if (e) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('الصفحة غير موجودة'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : buf);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  try {
    const url = new URL(req.url, 'http://x'), p = decodeURIComponent(url.pathname);
    if (p.startsWith('/api/')) return await api(req, res, url, p);
    serveStatic(req, res, p);
  } catch (e) {
    if (e instanceof ApiErr) { if (!res.headersSent) send(res, e.code, { error: e.message }); }
    else { console.error(e); if (!res.headersSent) send(res, 500, { error: 'خطأ في الخادم' }); }
  }
});
server.listen(PORT, HOST, () => console.log(`نظام إدارة المعارض يعمل على http://localhost:${PORT}  (البيانات في ${DATA})`));
