'use strict';
/* REDTIPE Performance Lab — servidor (sem dependências, Node 18+).
   O servidor NUNCA vê dados de pacientes em texto: o cofre e os arquivos chegam já
   cifrados (AES-256-GCM) pelo navegador; as triagens chegam cifradas com a chave pública RSA. */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';
const TOKEN_TTL = 12 * 3600 * 1000;
const MAX_JSON = 12 * 1024 * 1024, MAX_TRIAGEM = 256 * 1024, MAX_FILE = 30 * 1024 * 1024, MAX_INBOX = 500;

/* ---------- armazenamento: disco local OU Supabase Storage (gratuito, persistente) ---------- */
const SB_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, ''), SB_KEY = process.env.SUPABASE_SERVICE_KEY || '', SB_BUCKET = process.env.SUPABASE_BUCKET || 'redtipe';
const CLOUD = !!(SB_URL && SB_KEY);
const store = CLOUD ? {
  nome: 'Supabase Storage (bucket "' + SB_BUCKET + '")',
  h: () => (SB_KEY.startsWith('sb_') ? { apikey: SB_KEY } : { Authorization: 'Bearer ' + SB_KEY, apikey: SB_KEY }),
  u: k => SB_URL + '/storage/v1/object/' + encodeURIComponent(SB_BUCKET) + '/' + k.split('/').map(encodeURIComponent).join('/'),
  async read(k) { const r = await fetch(this.u(k), { headers: this.h() }); if (r.status === 404 || r.status === 400) return null; if (!r.ok) throw new Error('storage read ' + r.status); return Buffer.from(await r.arrayBuffer()); },
  async write(k, b) { const r = await fetch(this.u(k), { method: 'POST', headers: { ...this.h(), 'x-upsert': 'true', 'Content-Type': 'application/octet-stream' }, body: b }); if (!r.ok) throw new Error('storage write ' + r.status + ' ' + (await r.text()).slice(0, 120)); },
  async del(k) { const r = await fetch(this.u(k), { method: 'DELETE', headers: this.h() }); if (!r.ok && r.status !== 404 && r.status !== 400) throw new Error('storage del ' + r.status); },
  async list(prefix) { const r = await fetch(SB_URL + '/storage/v1/object/list/' + encodeURIComponent(SB_BUCKET), { method: 'POST', headers: { ...this.h(), 'Content-Type': 'application/json' }, body: JSON.stringify({ prefix, limit: 1000, offset: 0 }) }); if (!r.ok) throw new Error('storage list ' + r.status); return (await r.json()).filter(x => x.id !== null && x.name).map(x => x.name); }
} : {
  nome: 'disco local (' + DATA + ')',
  async read(k) { try { return fs.readFileSync(path.join(DATA, k)); } catch (e) { return null; } },
  async write(k, b) { fs.mkdirSync(path.dirname(path.join(DATA, k)), { recursive: true }); writeAtomic(path.join(DATA, k), b); },
  async del(k) { try { fs.unlinkSync(path.join(DATA, k)); } catch (e) { /* já não existe */ } },
  async list(prefix) { try { return fs.readdirSync(path.join(DATA, prefix)); } catch (e) { return []; } }
};
function writeAtomic(file, data) { const t = file + '.tmp' + process.pid; fs.writeFileSync(t, data); fs.renameSync(t, file); }

let state = { setup: false };
async function saveState() {
  const txt = Buffer.from(JSON.stringify(state));
  await store.write('state.json', txt);
  try {
    const day = new Date().toISOString().slice(0, 10);
    await store.write(`backups/state-${day}.json`, txt);
    const all = (await store.list('backups')).filter(f => /^state-\d{4}-\d{2}-\d{2}\.json$/.test(f)).sort();
    for (const f of all.slice(0, Math.max(0, all.length - 30))) await store.del('backups/' + f);
  } catch (e) { console.warn('backup:', e.message); }
}

/* ---------- segredos ---------- */
let SECRET, SETUP_CODE = process.env.SETUP_CODE || '';
async function init() {
  if (CLOUD) { try { await store.list(''); } catch (e) { console.error('ERRO: não consegui acessar o Supabase Storage:', e.message, '\nConfira SUPABASE_URL, SUPABASE_SERVICE_KEY e se o bucket "' + SB_BUCKET + '" existe.'); process.exit(1); } }
  else { fs.mkdirSync(DATA, { recursive: true }); }
  const st = await store.read('state.json'); if (st) { try { state = JSON.parse(st.toString('utf8')); } catch (e) { console.error('state.json corrompido'); process.exit(1); } }
  if (process.env.TOKEN_SECRET) SECRET = crypto.createHash('sha256').update(process.env.TOKEN_SECRET).digest();
  else { SECRET = await store.read('secret.key'); if (!SECRET) { SECRET = crypto.randomBytes(32); await store.write('secret.key', SECRET); } }
  if (!state.setup) {
    if (!SETUP_CODE) { const c = await store.read('codigo-de-configuracao.txt'); SETUP_CODE = c ? c.toString().trim() : crypto.randomBytes(5).toString('hex').toUpperCase(); }
    await store.write('codigo-de-configuracao.txt', Buffer.from(SETUP_CODE + '\n'));
    console.log('\n=====================================================');
    console.log(' CÓDIGO DE CONFIGURAÇÃO (primeiro acesso): ' + SETUP_CODE);
    console.log('=====================================================\n');
  } else { await store.del('codigo-de-configuracao.txt'); }
}

const b64u = b => Buffer.from(b).toString('base64url');
function sign(p) { return crypto.createHmac('sha256', SECRET).update(p).digest('base64url'); }
function newToken() { const p = b64u(JSON.stringify({ exp: Date.now() + TOKEN_TTL, g: state.gen || 0 })); return p + '.' + sign(p); }
function tokenOk(req) {
  const m = /^Bearer ([\w-]+)\.([\w-]+)$/.exec(req.headers.authorization || ''); if (!m) return false;
  const good = sign(m[1]); const a = Buffer.from(m[2]), b = Buffer.from(good);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try { const j = JSON.parse(Buffer.from(m[1], 'base64url').toString()); return j.exp > Date.now() && j.g === (state.gen || 0); } catch (e) { return false; }
}
function hashAuth(auth, salt) { return crypto.scryptSync(auth, salt, 32).toString('hex'); }
function eq(a, b) { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); }

/* ---------- limitador de tentativas ---------- */
const fails = new Map();
function ipOf(req) { if (TRUST_PROXY) { const f = (req.headers['x-forwarded-for'] || '').split(',')[0].trim(); if (f) return f; } return req.socket.remoteAddress || '?'; }
function locked(ip) { const f = fails.get(ip); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0; }
function fail(ip) { const f = fails.get(ip) || { n: 0, until: 0 }; f.n++; if (f.n >= 5) { f.until = Date.now() + Math.min(900, 30 * 2 ** Math.floor(f.n / 5 - 1)) * 1000; } fails.set(ip, f); }
function okAuth(ip) { fails.delete(ip); }
const rate = new Map();
function rateHit(key, max, winMs) { const now = Date.now(); const a = (rate.get(key) || []).filter(t => now - t < winMs); if (a.length >= max) { rate.set(key, a); return false; } a.push(now); rate.set(key, a); return true; }
setInterval(() => { const now = Date.now(); for (const [k, f] of fails) if (f.until < now && now - (f.until || 0) > 3600e3) fails.delete(k); for (const [k, a] of rate) if (!a.some(t => now - t < 3600e3)) rate.delete(k); }, 600e3).unref();

/* ---------- utilidades HTTP ---------- */
function send(res, code, obj, extra) { const b = Buffer.from(JSON.stringify(obj)); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-store', ...(extra || {}) }); res.end(b); }
function readBody(req, limit) {
  return new Promise((ok, no) => {
    const ch = []; let n = 0, dead = false;
    req.on('data', c => { if (dead) return; n += c.length; if (n > limit) { dead = true; no({ status: 413 }); req.resume(); return; } ch.push(c); });
    req.on('end', () => { if (!dead) ok(Buffer.concat(ch)); });
    req.on('error', () => { if (!dead) { dead = true; no({ status: 400 }); } });
  });
}
async function readJson(req, limit) { const b = await readBody(req, limit); try { const j = JSON.parse(b.toString('utf8')); return j && typeof j === 'object' ? j : {}; } catch (e) { throw { status: 400 }; } }
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
const isHex = (s, n) => typeof s === 'string' && s.length === n && /^[0-9a-f]+$/.test(s);
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const vaultOk = v => v && isB64(v.iv, 32) && isB64(v.ct, MAX_JSON);

/* ---------- CID ---------- */
const norm = s => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
let CID10 = [], CID_FONTE = 'local';
function loadCid() {
  const csv = path.join(DATA, 'CID-10-SUBCATEGORIAS.CSV');
  try {
    const txt = fs.readFileSync(csv).toString('latin1').split(/\r?\n/).slice(1);
    const out = [];
    for (const ln of txt) { const f = ln.split(';'); if (!f[0] || !f[4] || !/^[A-Z]\d{2,3}/.test(f[0])) continue; const c = f[0].trim(); out.push({ code: c.length > 3 ? c.slice(0, 3) + '.' + c.slice(3) : c, name: f[4].trim() }); }
    if (out.length > 1000) { CID10 = out; CID_FONTE = 'datasus'; console.log('CID-10 DATASUS carregada:', out.length); return; }
  } catch (e) { /* sem CSV */ }
  try { CID10 = JSON.parse(fs.readFileSync(path.join(__dirname, 'cid10-catalogo.json'), 'utf8')); } catch (e) { CID10 = []; }
  CID_FONTE = 'local';
}
loadCid();
CID10.forEach(x => { x._n = norm(x.name); x._c = x.code.toLowerCase().replace('.', ''); });
function cidBusca10(q) {
  const nq = norm(q), cq = nq.replace('.', ''), toks = nq.split(/\s+/).filter(Boolean);
  const hits = [];
  for (const x of CID10) {
    if (x._c.startsWith(cq)) hits.push([0, x]);
    else if (toks.length && toks.every(t => x._n.includes(t))) hits.push([x._n.startsWith(toks[0]) ? 1 : 2, x]);
  }
  hits.sort((a, b) => a[0] - b[0] || a[1].code.localeCompare(b[1].code));
  return hits.slice(0, 30).map(([, x]) => ({ code: x.code, name: x.name }));
}
let whoTok = null;
async function cidBusca11(q) {
  const id = process.env.ICD_CLIENT_ID, sec = process.env.ICD_CLIENT_SECRET;
  if (!id || !sec) return { erro: 'sem_credenciais', items: [] };
  try {
    if (!whoTok || whoTok.exp < Date.now()) {
      const r = await fetch('https://icdaccounts.who.int/connect/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: id, client_secret: sec, scope: 'icdapi_access', grant_type: 'client_credentials' }) });
      if (!r.ok) throw new Error('token ' + r.status);
      const j = await r.json(); whoTok = { t: j.access_token, exp: Date.now() + (j.expires_in - 60) * 1000 };
    }
    const r = await fetch('https://id.who.int/icd/release/11/2025-01/mms/search?useFlexisearch=true&flatResults=true&q=' + encodeURIComponent(q), { headers: { Authorization: 'Bearer ' + whoTok.t, Accept: 'application/json', 'Accept-Language': 'pt', 'API-Version': 'v2' } });
    if (!r.ok) throw new Error('busca ' + r.status);
    const j = await r.json();
    const items = (j.destinationEntities || []).filter(e => e.theCode).slice(0, 30).map(e => ({ code: e.theCode, name: String(e.title || '').replace(/<[^>]+>/g, '') }));
    return { items, fonte: 'oms' };
  } catch (e) { console.warn('CID-11:', e.message); return { erro: 'indisponivel', items: [] }; }
}


/* ---------- mar, vento e notícias (via servidor, com cache) ----------
   Tempo e mar: Open-Meteo. O plano gratuito é só para uso NÃO comercial: para site comercial, contrate a chave
   e informe em OPEN_METEO_KEY. Notícias: RSS públicos dos veículos (só título e link, com a fonte). */
const OM_KEY = process.env.OPEN_METEO_KEY || '';
const OM_WX = process.env.OM_FORECAST_URL || (OM_KEY ? 'https://customer-api.open-meteo.com/v1/forecast' : 'https://api.open-meteo.com/v1/forecast');
const OM_MAR = process.env.OM_MARINE_URL || (OM_KEY ? 'https://customer-marine-api.open-meteo.com/v1/marine' : 'https://marine-api.open-meteo.com/v1/marine');
const FEEDS = (process.env.NEWS_FEEDS || 'Surfer Today|https://feeds.feedburner.com/surfertoday/surfing,UOL Esporte|https://rss.uol.com.br/feed/esporte.xml,Gazeta Esportiva|https://www.gazetaesportiva.com/feed/,ESPN Brasil|https://www.espn.com.br/espn/rss/news,ge globo|https://ge.globo.com/rss/ge/,Lance|https://www.lance.com.br/rss.xml,Surfline|https://www.surfline.com/surf-news/feed')
  .split(',').map(x => x.split('|')).filter(x => x.length === 2 && /^https?:\/\//.test(x[1].trim())).map(x => ({ nome: x[0].trim(), url: x[1].trim() }));
const memo = new Map();
async function cached(key, ttl, fn) {
  const c = memo.get(key); if (c && Date.now() - c.t < ttl) return c.v;
  try { const v = await fn(); memo.set(key, { t: Date.now(), v }); if (memo.size > 400) memo.delete(memo.keys().next().value); return v; }
  catch (e) { if (c) return c.v; throw e; }
}
async function getText(url, ms = 9000) {
  const ctl = new AbortController(), to = setTimeout(() => ctl.abort(), ms);
  try { const r = await fetch(url, { signal: ctl.signal, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; REDTIPE-site)', Accept: '*/*' } }); if (!r.ok) throw new Error('http ' + r.status); return await r.text(); }
  finally { clearTimeout(to); }
}
const num = v => (typeof v === 'number' && isFinite(v)) ? v : null;
const r1 = v => v == null ? null : Math.round(v * 10) / 10;
async function marEtempo(lat, lon) {
  const q = `latitude=${lat}&longitude=${lon}&timezone=auto&forecast_days=3` + (OM_KEY ? `&apikey=${encodeURIComponent(OM_KEY)}` : '');
  const [wx, mr] = await Promise.all([
    getText(`${OM_WX}?${q}&current=temperature_2m,weather_code,wind_speed_10m,wind_direction_10m,wind_gusts_10m&hourly=temperature_2m,weather_code,wind_speed_10m,wind_direction_10m,wind_gusts_10m,precipitation_probability&daily=weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max,sunrise,sunset`).then(JSON.parse),
    getText(`${OM_MAR}?${q}&hourly=wave_height,wave_period,wave_direction,swell_wave_height,swell_wave_period,swell_wave_direction,ocean_current_velocity,ocean_current_direction,sea_surface_temperature`).then(JSON.parse).catch(() => null)
  ]);
  if (!wx || !wx.hourly || !wx.hourly.time) throw new Error('sem dados de tempo');
  const off = wx.utc_offset_seconds || 0, agora = new Date(Date.now() + off * 1000).toISOString().slice(0, 13) + ':00';
  const T = wx.hourly.time; let i0 = T.findIndex(t => t >= agora); if (i0 < 0) i0 = 0;
  const mt = mr && mr.hourly && mr.hourly.time ? new Map(mr.hourly.time.map((t, i) => [t, i])) : null;
  const mval = (k, t) => (mt && mt.has(t) && mr.hourly[k]) ? num(mr.hourly[k][mt.get(t)]) : null;
  const ponto = i => { const t = T[i]; return {
    t, h: t.slice(11, 16), temp: r1(num(wx.hourly.temperature_2m[i])), cod: num(wx.hourly.weather_code[i]), vento: r1(num(wx.hourly.wind_speed_10m[i])), ventoDir: num(wx.hourly.wind_direction_10m[i]), rajada: r1(num(wx.hourly.wind_gusts_10m[i])), chuva: num(wx.hourly.precipitation_probability && wx.hourly.precipitation_probability[i]),
    onda: r1(mval('wave_height', t)), periodo: r1(mval('wave_period', t)), ondaDir: mval('wave_direction', t), swell: r1(mval('swell_wave_height', t)), swellPer: r1(mval('swell_wave_period', t)), swellDir: mval('swell_wave_direction', t),
    corrente: r1(mval('ocean_current_velocity', t)), correnteDir: mval('ocean_current_direction', t), agua: r1(mval('sea_surface_temperature', t)) }; };
  const horas = []; for (let k = 0; k < 24 && i0 + k < T.length; k++) horas.push(ponto(i0 + k));
  const c = wx.current || {}, atual = { ...horas[0] };
  if (num(c.temperature_2m) != null) { atual.temp = r1(c.temperature_2m); atual.cod = num(c.weather_code); atual.vento = r1(num(c.wind_speed_10m)); atual.ventoDir = num(c.wind_direction_10m); atual.rajada = r1(num(c.wind_gusts_10m)); }
  const d = wx.daily || {}, dias = (d.time || []).map((t, i) => ({ d: t, cod: num(d.weather_code[i]), max: r1(num(d.temperature_2m_max[i])), min: r1(num(d.temperature_2m_min[i])), chuva: num(d.precipitation_probability_max && d.precipitation_probability_max[i]), nasce: d.sunrise ? String(d.sunrise[i]).slice(11, 16) : null, poe: d.sunset ? String(d.sunset[i]).slice(11, 16) : null }));
  const temMar = horas.some(h => h.onda != null || h.corrente != null || h.agua != null);
  return { atualizado: new Date().toISOString(), fonte: 'Open-Meteo', temMar, atual, horas, dias };
}
const dec = s => String(s).replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#0*39;|&apos;/g, "'").replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(+n); } catch (e) { return ''; } }).replace(/\s+/g, ' ').trim();
const tag = (x, n) => { const m = new RegExp('<' + n + '(?:\\s[^>]*)?>([\\s\\S]*?)</' + n + '>', 'i').exec(x); return m ? m[1] : ''; };
function lerFeed(xml, nome) {
  const blocos = xml.match(/<item[\s>][\s\S]*?<\/item>|<entry[\s>][\s\S]*?<\/entry>/gi) || [], out = [];
  for (const b of blocos.slice(0, 15)) {
    const t = dec(tag(b, 'title')); let u = dec(tag(b, 'link')); if (!u) { const m = /<link[^>]*href=["']([^"']+)["']/i.exec(b); u = m ? m[1] : ''; }
    const dt = Date.parse(dec(tag(b, 'pubDate') || tag(b, 'updated') || tag(b, 'published') || tag(b, 'dc:date'))) || 0;
    if (t.length < 8 || !/^https?:\/\//i.test(u)) continue;
    out.push({ t: t.slice(0, 180), u, f: nome, d: dt });
  }
  return out;
}
async function noticias() {
  const res = await Promise.all(FEEDS.map(async f => { try { const it = lerFeed(await getText(f.url, 7000), f.nome); if (!it.length) throw new Error('vazio'); return { ok: true, f, it }; } catch (e) { return { ok: false, f, e: e.message }; } }));
  console.log('Notícias:', res.map(r => (r.ok ? 'ok ' : 'FALHOU ') + r.f.nome + (r.ok ? ' (' + r.it.length + ')' : ' [' + r.e + ']')).join(' | '));
  const bons = res.filter(r => r.ok); if (!bons.length) { const er = new Error('nenhuma fonte respondeu'); er.detalhe = res.map(r => r.f.nome + ': ' + r.e); throw er; }
  const vistos = new Set(), todos = [];
  bons.forEach(r => r.it.slice(0, 10).forEach(i => { const k = i.t.toLowerCase().slice(0, 60); if (!vistos.has(k)) { vistos.add(k); todos.push(i); } }));
  todos.sort((a, b) => b.d - a.d);
  return { atualizado: new Date().toISOString(), fontes: bons.map(r => r.f.nome), itens: todos.slice(0, 30) };
}
/* ---------- API ---------- */
async function api(req, res, url) {
  const p = url.pathname.slice(4) || '/', m = req.method, ip = ipOf(req);
  const need = () => { if (!tokenOk(req)) { send(res, 401, { erro: 'nao_autorizado' }); return false; } return true; };

  if (p === '/status' && m === 'GET') return send(res, 200, { setup: !!state.setup, salt: state.setup ? state.salt : null });

  if (p === '/pubkey' && m === 'GET') return state.pub ? send(res, 200, { pub: state.pub }) : send(res, 404, { erro: 'sem_chave' });

  if (p === '/setup' && m === 'POST') {
    const w = locked(ip); if (w) return send(res, 429, { retry: w });
    const j = await readJson(req, MAX_JSON);
    if (state.setup) return send(res, 409, { erro: 'ja_configurado' });
    if (!eq(String(j.code || '').trim().toUpperCase(), SETUP_CODE.toUpperCase())) { fail(ip); return send(res, 403, { erro: 'codigo' }); }
    if (!isHex(j.salt, 32) || !isHex(j.auth, 64) || !vaultOk(j.vault) || !j.pub || j.pub.kty !== 'RSA' || !isB64Url(j.pub.n) || !isB64Url(j.pub.e)) return send(res, 400, { erro: 'dados' });
    const salt = crypto.randomBytes(16).toString('hex');
    state = { setup: true, salt: j.salt, authSalt: salt, authHash: hashAuth(j.auth, salt), pub: { kty: 'RSA', n: j.pub.n, e: j.pub.e }, vault: { iv: j.vault.iv, ct: j.vault.ct, version: 1 }, gen: 0, criadoEm: new Date().toISOString() };
    await saveState(); okAuth(ip); await store.del('codigo-de-configuracao.txt').catch(() => {});
    return send(res, 200, { token: newToken() });
  }

  if (p === '/login' && m === 'POST') {
    const w = locked(ip); if (w) return send(res, 429, { retry: w });
    const j = await readJson(req, 4096);
    if (!state.setup || !isHex(j.auth, 64)) { fail(ip); return send(res, 401, { erro: 'credenciais' }); }
    if (!eq(hashAuth(j.auth, state.authSalt), state.authHash)) { fail(ip); const w2 = locked(ip); return w2 ? send(res, 429, { retry: w2 }) : send(res, 401, { erro: 'credenciais' }); }
    okAuth(ip); return send(res, 200, { token: newToken() });
  }

  if (p === '/triagem' && m === 'POST') {
    if (!state.setup) return send(res, 404, { erro: 'sem_chave' });
    if (!rateHit('tri:' + ip, 10, 3600e3)) return send(res, 429, { retry: 600 });
    const j = await readJson(req, MAX_TRIAGEM);
    if (!isB64(j.k, 700) || !isB64(j.iv, 32) || !isB64(j.ct, 200000)) return send(res, 400, { erro: 'dados' });
    if ((await store.list('inbox')).length >= MAX_INBOX) return send(res, 503, { erro: 'caixa_cheia' });
    const id = Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
    await store.write('inbox/' + id + '.json', Buffer.from(JSON.stringify({ id, k: j.k, iv: j.iv, ct: j.ct })));
    return send(res, 200, { ok: true });
  }

  if (p === '/mar' && m === 'GET') {
    if (!rateHit('mar:' + ip, 60, 3600e3)) return send(res, 429, { retry: 300 });
    const lat = Math.round(parseFloat(url.searchParams.get('lat')) * 100) / 100, lon = Math.round(parseFloat(url.searchParams.get('lon')) * 100) / 100;
    if (!isFinite(lat) || !isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return send(res, 400, { erro: 'coordenadas' });
    try { return send(res, 200, await cached('mar:' + lat + ',' + lon, 30 * 60e3, () => marEtempo(lat, lon)), { 'Cache-Control': 'public, max-age=300' }); }
    catch (e) { console.warn('mar:', e.message); return send(res, 502, { erro: 'indisponivel' }); }
  }
  if (p === '/noticias' && m === 'GET') {
    if (!rateHit('not:' + ip, 120, 3600e3)) return send(res, 429, { retry: 300 });
    try { return send(res, 200, await cached('noticias', 10 * 60e3, noticias), { 'Cache-Control': 'public, max-age=120' }); }
    catch (e) { console.warn('noticias:', e.message); return send(res, 502, { erro: 'indisponivel', detalhe: e.detalhe || [e.message] }); }
  }

  /* --- a partir daqui: autenticado --- */
  if (!need()) return;

  if (p === '/vault' && m === 'GET') return send(res, 200, state.vault);
  if (p === '/vault' && m === 'PUT') {
    const j = await readJson(req, MAX_JSON);
    if (!vaultOk(j) || !Number.isInteger(j.base)) return send(res, 400, { erro: 'dados' });
    if (j.base !== state.vault.version) return send(res, 409, state.vault);
    state.vault = { iv: j.iv, ct: j.ct, version: state.vault.version + 1 }; await saveState();
    return send(res, 200, { version: state.vault.version });
  }

  if (p === '/password' && m === 'PUT') {
    const j = await readJson(req, MAX_JSON);
    if (!isHex(j.salt, 32) || !isHex(j.auth, 64) || !vaultOk(j.vault) || !Number.isInteger(j.base)) return send(res, 400, { erro: 'dados' });
    if (j.base !== state.vault.version) return send(res, 409, state.vault);
    const as = crypto.randomBytes(16).toString('hex');
    state.salt = j.salt; state.authSalt = as; state.authHash = hashAuth(j.auth, as);
    state.vault = { iv: j.vault.iv, ct: j.vault.ct, version: state.vault.version + 1 }; await saveState();
    return send(res, 200, { version: state.vault.version });
  }

  let mm;
  if ((mm = /^\/files\/([\w-]+)$/.exec(p)) && ID_RE.test(mm[1])) {
    const key = 'files/' + mm[1];
    if (m === 'PUT') { const b = await readBody(req, MAX_FILE); if (b.length < 28) return send(res, 400, { erro: 'dados' }); await store.write(key, b); return send(res, 200, { ok: true }); }
    if (m === 'GET') { const b = await store.read(key); if (!b) return send(res, 404, { erro: 'nao_encontrado' }); res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': b.length, 'Cache-Control': 'no-store' }); return res.end(b); }
    if (m === 'DELETE') { await store.del(key); return send(res, 200, { ok: true }); }
  }

  if (p === '/inbox' && m === 'GET') {
    const items = [];
    for (const f of (await store.list('inbox')).filter(x => x.endsWith('.json')).sort().slice(0, 100)) { try { const b = await store.read('inbox/' + f); if (b) items.push(JSON.parse(b.toString('utf8'))); } catch (e) { /* ignora */ } }
    return send(res, 200, { items });
  }
  if ((mm = /^\/inbox\/([\w-]+)$/.exec(p)) && m === 'DELETE' && ID_RE.test(mm[1])) { await store.del('inbox/' + mm[1] + '.json'); return send(res, 200, { ok: true }); }

  if (p === '/cid' && m === 'GET') {
    const q = (url.searchParams.get('q') || '').slice(0, 80), v = url.searchParams.get('v') === '11' ? '11' : '10';
    if (q.trim().length < 2) return send(res, 200, { items: [], fonte: CID_FONTE });
    if (v === '11') return send(res, 200, await cidBusca11(q));
    return send(res, 200, { items: cidBusca10(q), fonte: CID_FONTE });
  }
  return send(res, 404, { erro: 'rota' });
}
function isB64Url(s) { return typeof s === 'string' && s.length > 0 && s.length < 1000 && /^[A-Za-z0-9_-]+$/.test(s); }

/* ---------- estáticos ---------- */
const _MIME_UNUSED = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp', '.txt': 'text/plain; charset=utf-8', '.json': 'application/json' };
const PAGES = { '/': 'index.html', '/index.html': 'index.html', '/painel.html': 'painel.html', '/painel': 'painel.html', '/triagem.html': 'triagem.html', '/triagem': 'triagem.html', '/en': 'en.html', '/en.html': 'en.html', '/es': 'es.html', '/es.html': 'es.html' };
/* endereço público do site: SITE_URL (opcional) ou o que veio na requisição; funciona com qualquer domínio */
function siteOrigin(req) {
  const env = (process.env.SITE_URL || '').trim().replace(/\/+$/, '');
  if (/^https?:\/\/[a-z0-9.-]+(:\d+)?$/i.test(env)) return env;
  const host = String(req.headers['host'] || 'localhost').toLowerCase();
  const okHost = /^[a-z0-9.-]+(:\d{1,5})?$/.test(host) ? host : 'localhost';
  const xf = TRUST_PROXY ? String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim() : '';
  const proto = xf === 'https' || (!/^localhost|^127\./.test(okHost) && xf !== 'http' && process.env.FORCE_HTTPS_URLS !== '0') ? 'https' : 'http';
  return proto + '://' + okHost;
}
function gsvTag() { const v = (process.env.GOOGLE_SITE_VERIFICATION || '').trim(); return /^[A-Za-z0-9_-]{20,100}$/.test(v) ? '<meta name="google-site-verification" content="' + v + '">' : ''; }
function listPublicPages() {
  let files = []; try { files = fs.readdirSync(__dirname); } catch (_) {}
  return files.filter(f => /^(index|en|es|triagem)\.html$/.test(f) || /^(esporte|en|es)-[a-z0-9-]+\.html$/.test(f)).sort();
}
function pageUrl(origin, f) { return f === 'index.html' ? origin + '/' : f === 'en.html' ? origin + '/en' : f === 'es.html' ? origin + '/es' : origin + '/' + f; }
function sitemapXml(origin) {
  const pages = listPublicPages(), set = new Set(pages);
  const alt = f => {
    let m;
    if (f === 'index.html' || f === 'en.html' || f === 'es.html') return [['pt-BR', 'index.html'], ['en', 'en.html'], ['es', 'es.html']];
    if ((m = /^(?:esporte|en|es)-(.+)\.html$/.exec(f))) return [['pt-BR', 'esporte-' + m[1] + '.html'], ['en', 'en-' + m[1] + '.html'], ['es', 'es-' + m[1] + '.html']];
    return [];
  };
  const esc = x => x.replace(/&/g, '&amp;').replace(/</g, '&lt;');
  let out = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n';
  for (const f of pages) {
    out += '<url><loc>' + esc(pageUrl(origin, f)) + '</loc>';
    const a = alt(f).filter(x => set.has(x[1]));
    if (a.length) { for (const [l, g] of a) out += '<xhtml:link rel="alternate" hreflang="' + l + '" href="' + esc(pageUrl(origin, g)) + '"/>'; out += '<xhtml:link rel="alternate" hreflang="x-default" href="' + esc(pageUrl(origin, a[0][1])) + '"/>'; }
    out += '</url>\n';
  }
  return out + '</urlset>\n';
}
function serveStatic(req, res, url) {
  const origin = siteOrigin(req);
  if (url.pathname === '/robots.txt') {
    const b = Buffer.from('User-agent: *\nAllow: /\nDisallow: /painel\nDisallow: /painel.html\nDisallow: /api/\n\nSitemap: ' + origin + '/sitemap.xml\n');
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'public, max-age=3600' }); return res.end(req.method === 'HEAD' ? undefined : b);
  }
  if (url.pathname === '/sitemap.xml') {
    const b = Buffer.from(sitemapXml(origin));
    res.writeHead(200, { 'Content-Type': 'application/xml; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'public, max-age=3600' }); return res.end(req.method === 'HEAD' ? undefined : b);
  }
  if (url.pathname === '/og.png') {
    return fs.readFile(path.join(__dirname, 'og.png'), (err, b) => {
      if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
      res.writeHead(200, { 'Content-Type': 'image/png', 'Content-Length': b.length, 'Cache-Control': 'public, max-age=86400' }); res.end(req.method === 'HEAD' ? undefined : b);
    });
  }
  /* só as páginas listadas são públicas (server.js, dados e demais arquivos nunca são servidos) */
  const name = PAGES[url.pathname] || (/^\/(esporte|en|es)-[a-z0-9-]+\.html$/.test(url.pathname) ? url.pathname.slice(1) : null);
  if (!name) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
  fs.readFile(path.join(__dirname, name), (err, b0) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Não encontrado'); }
    const b = name === 'painel.html' ? b0 : Buffer.from(b0.toString('utf8').split('__SITE__').join(origin).split('__GSV__').join(gsvTag()));
    const h = { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-cache' };
    if (name === 'painel.html') h['X-Robots-Tag'] = 'noindex, nofollow';
    res.writeHead(200, h);
    res.end(req.method === 'HEAD' ? undefined : b);
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (req.headers['x-forwarded-proto'] === 'https' || process.env.FORCE_HSTS === '1') res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/healthz') return send(res, 200, { ok: true });
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
    return serveStatic(req, res, url);
  } catch (e) {
    if (e && e.status) return send(res, e.status, { erro: 'requisicao' });
    console.error(e); if (!res.headersSent) send(res, 500, { erro: 'interno' }); else res.end();
  }
});
server.requestTimeout = 120000;
init().then(() => server.listen(PORT, () => console.log(`REDTIPE no ar: http://localhost:${PORT}  (dados em ${store.nome})`))).catch(e => { console.error('Falha ao iniciar:', e); process.exit(1); });
