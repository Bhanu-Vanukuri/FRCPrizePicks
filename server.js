'use strict';
// FPP Fantasy — multiplayer game server.
// Run: node server.js   (env: PORT, TIME_SCALE, MOD_USERNAME,
//      TURSO_DATABASE_URL e.g. libsql://xxx.turso.io or file:./game.db, TURSO_AUTH_TOKEN)
require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@libsql/client');
const { argon2id, argon2Verify } = require('hash-wasm');

const PORT = +process.env.PORT || 3000, S = +process.env.TIME_SCALE || 1;

const RANKS = ['S+','S','S-','A+','A','A-','B+','B','B-','C+','C','C-','D+','D','D-','F+','F','F-'];
const PRICES = [10000,9000,8500,8000,7500,7000,6500,6000,5500,5000,4500,4000,3500,3000,2500,2000,1500,1000];
const price = r => PRICES[RANKS.indexOf(r)];
const DIVS = ['Newton','Galileo','Curie','Hopper','Milstein','Archimedes','Daly','Johnson'];
const TRAITS = ['trench_dumper','trench_turret','bump_dumper','bump_turret','hopperless','shooterless','fast','defense_bot','shotblocker','circular','slow','l1_climb','l2_climb','l3_climb'];
const STARTING = 6000;

// ---------- persistence ----------
// Everything lives in Turso/libSQL: accounts in users/user_auth/sessions tables,
// and the whole game-state object as a single JSON document in `gamestate`.
// `db.users`/`db.sessions` are in-memory mirrors hydrated from the DB on boot.
let db = { users: {}, sessions: {}, robots: {}, events: {}, season: { id: 1, name: '2026', game: 'REBUILT' }, seasons: [], points: {}, history: [], seq: 1 };
let saveT = null;
const save = () => { if (saveT) return; saveT = setTimeout(() => { saveT = null; persistState().catch(e => console.error('state save failed:', e)); flushUsers().catch(e => console.error('user save failed:', e)); }, 800); };
const shutdown = async () => { try { await persistState(); await flushUsers(); } catch (e) {} process.exit(0); };
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
const id = () => String(db.seq++);
const now = () => Date.now();
const shuffle = a => { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const pick1 = a => a[Math.floor(Math.random() * a.length)];

function mkRobot(o) {
  const r = { id: id(), number: +o.number, name: o.name || '', rank: o.rank, epa: +o.epa || 0, dp: +o.dp || 0, capacity: +o.capacity || 0,
    location: o.location || '', rookie: +o.rookie || 0, traits: (o.traits || []).filter(t => TRAITS.includes(t)), image: o.image || '' };
  db.robots[r.id] = r; return r;
}
// ---------- users / auth ----------
// Accounts live in Turso/libSQL (SQLite): users holds profile fields as JSON in `profile`;
// credentials live in user_auth (Argon2id); sessions hold random tokens with expiry.
// The whole game-state object persists as one JSON doc in `gamestate`.
// `db.users` is an in-memory mirror hydrated from the DB on boot. All queries parameterized.
const client = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:' + path.join(__dirname, 'game.db'),
  authToken: process.env.TURSO_AUTH_TOKEN || undefined
});
const randBytes = n => crypto.randomBytes(n); // Buffer is a Uint8Array — fine for argon2 salt
const qrun = (q, p) => client.execute({ sql: q, args: p || [] });
const qget = async (q, p) => (await client.execute({ sql: q, args: p || [] })).rows[0] || null;
const qall = async (q, p) => (await client.execute({ sql: q, args: p || [] })).rows;

const profileOf = u => { const p = {}; for (const k in u) if (!['id', 'username', 'email', 'lastSeen', 'salt', 'pw'].includes(k)) p[k] = u[k]; return p; };
const userHash = new Map(); // uid -> profile JSON last flushed; skip unchanged users on save
async function hydrateUsers() {
  db.users = {}; userHash.clear();
  for (const r of await qall('SELECT id, username, email, profile FROM users')) {
    const u = Object.assign({ id: String(r.id), username: r.username, email: r.email || '', lastSeen: 0 }, JSON.parse(r.profile || '{}'));
    db.users[String(r.id)] = u;
    userHash.set(u.id, JSON.stringify(profileOf(u)));
  }
}
async function flushUsers() {
  const up = 'INSERT INTO users (id, username, email, profile, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, email = excluded.email, profile = excluded.profile';
  for (const u of Object.values(db.users)) {
    const prof = JSON.stringify(profileOf(u));
    if (userHash.get(u.id) === prof) continue; // unchanged since last flush — don't rewrite (also protects manual DB edits)
    userHash.set(u.id, prof);
    await qrun(up, [+u.id, u.username, u.email || '', prof, new Date(u.joined || now()).toISOString()]);
  }
}
async function persistState() {
  const out = Object.assign({}, db); delete out.users; delete out.sessions;
  await qrun('INSERT INTO gamestate (id, state) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET state = excluded.state', [JSON.stringify(out)]);
}

// Argon2id (RFC 9101) via hash-wasm. PHC-encoded hash stored in user_auth.password_hash.
async function hashPassword(pw) {
  return argon2id({ password: pw, salt: randBytes(16), parallelism: 1, memorySize: 19456, iterations: 2, hashLength: 32, outputType: 'encoded' });
}
const verifyPassword = (pw, phc) => argon2Verify({ password: pw, hash: phc });

// register_user(username, email, password, profile) -> user id (string)
// Inserts users + user_auth rows in a transaction; throws a safe error on unique conflicts.
async function register_user(username, email, password, profile) {
  const phc = await hashPassword(password);
  const tx = await client.transaction('write');
  try {
    await tx.execute({ sql: 'INSERT INTO users (username, email, profile, created_at) VALUES (?, ?, ?, ?)', args: [username, email || '', JSON.stringify(profile || {}), new Date().toISOString()] });
    const uid = (await tx.execute('SELECT last_insert_rowid() AS id')).rows[0].id;
    await tx.execute({ sql: 'INSERT INTO user_auth (user_id, password_hash) VALUES (?, ?)', args: [uid, phc] });
    await tx.commit();
    return String(uid);
  } catch (e) {
    try { await tx.rollback(); } catch (_) {}
    if (/constraint|unique/i.test(String(e && e.message))) throw new HttpErr(400, 'Username or email already registered');
    throw e;
  }
}
// authenticate_user(username, password) -> user id (string); always throws the same
// non-revealing 'Invalid username or password' on any failure.
async function authenticate_user(username, password) {
  const row = await qget('SELECT u.id AS id, a.password_hash AS phc FROM users u JOIN user_auth a ON a.user_id = u.id WHERE u.username = ?', [String(username || '')]);
  const ok = row && await verifyPassword(String(password || ''), row.phc);
  if (!ok) throw new HttpErr(401, 'Invalid username or password');
  await qrun('UPDATE user_auth SET last_login = ? WHERE user_id = ?', [new Date().toISOString(), row.id]);
  return String(row.id);
}
// Session cache: token -> { uid, exp(ms) }. Sessions change rarely, so an in-memory
// hit avoids 2 Turso round-trips on every API call (clients poll ~1/sec).
const sessCache = new Map();
let sessPurgeT = 0;
// validate_session(token) -> user id (string) or null; verifies expires_at.
// Expired-row purge runs at most once per minute, only on cache misses.
async function validate_session(token) {
  if (!token) return null;
  const t = now(), hit = sessCache.get(token);
  if (hit) {
    if (hit.exp > t) return hit.uid;
    sessCache.delete(token);
    await qrun('DELETE FROM sessions WHERE session_token = ?', [token]);
    return null;
  }
  if (t - sessPurgeT > 60000) { sessPurgeT = t; await qrun('DELETE FROM sessions WHERE expires_at <= ?', [new Date(t).toISOString()]); }
  const row = await qget('SELECT user_id, expires_at FROM sessions WHERE session_token = ?', [token]);
  if (!row) return null;
  const exp = Date.parse(row.expires_at);
  if (!(exp > t)) { await qrun('DELETE FROM sessions WHERE session_token = ?', [token]); return null; }
  sessCache.set(token, { uid: String(row.user_id), exp });
  return String(row.user_id);
}
// logout_user(token) -> deletes the session row + cache entry.
async function logout_user(token) { if (token) { sessCache.delete(token); await qrun('DELETE FROM sessions WHERE session_token = ?', [token]); } }
// create_session(uid) -> issues a cryptographically random token with a 30-day expiry.
async function create_session(uid) {
  const tok = crypto.randomBytes(24).toString('hex');
  const exp = now() + 2592000000;
  await qrun('INSERT INTO sessions (session_token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)', [tok, +uid, new Date().toISOString(), new Date(exp).toISOString()]);
  sessCache.set(tok, { uid: String(uid), exp });
  return { 'Set-Cookie': 'sid=' + tok + '; HttpOnly; Path=/; SameSite=Lax; Max-Age=2592000' };
}

// Boot: create schema, load persisted game state + user profiles, seed starter robots.
const booted = (async () => {
  await qrun('PRAGMA foreign_keys = ON');
  try { await qrun('PRAGMA journal_mode = WAL'); } catch (e) {}
  await qrun(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL DEFAULT '',
    profile TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
  )`);
  await qrun(`CREATE UNIQUE INDEX IF NOT EXISTS users_email_uniq ON users(email) WHERE email <> ''`);
  await qrun(`CREATE TABLE IF NOT EXISTS user_auth (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    last_login TEXT
  )`);
  await qrun(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    session_token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  )`);
  await qrun('CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)');
  await qrun(`CREATE TABLE IF NOT EXISTS gamestate (
    id INTEGER PRIMARY KEY,
    state TEXT NOT NULL
  )`);
  const gs = await qget('SELECT state FROM gamestate WHERE id = 1');
  if (gs && gs.state) { try { db = Object.assign(db, JSON.parse(gs.state)); } catch (e) {} }
  await hydrateUsers();
  if (!Object.keys(db.robots).length) {
    mkRobot({ number: 3506, rank: 'B-', epa: 140, capacity: 60, location: 'Charlotte, North Carolina', rookie: 2011 });
    mkRobot({ number: 2056, rank: 'A', epa: 302, capacity: 65, location: 'Stoney Creek, Ontario', rookie: 2007 });
    await persistState();
  }
})();
booted.catch(e => console.error('database init failed:', e));

const userByName = n => Object.values(db.users).find(u => u.username.toLowerCase() === String(n).toLowerCase());
const active = u => u && now() - (u.lastSeen || 0) < 20000;
const season = () => db.season;
function pubUser(u) { return { id: u.id, username: u.username, division: u.division, isMod: !!u.mod, active: active(u) }; }

// ---------- scoring engine ----------
function eff(ev, m, u) {
  const rb = db.robots[robotOf(ev, u)], T = new Set(rb.traits || []), st = m.strat[u], cl = m.climbs[u] || {};
  let epa = T.has('shooterless') ? 0 : rb.epa; if (st === 'scorer') epa *= 1.09;
  const lvl = T.has('l3_climb') ? 30 : T.has('l2_climb') ? 20 : T.has('l1_climb') ? 10 : 0;
  let cp = 0; if (lvl) { if (cl.a) cp += 15; if (cl.e) cp += lvl; }
  return { u, rb, T, st, epa, cap: rb.capacity || 0, slow: T.has('slow'), cp };
}
const givenDP = a => { // DP this robot hands the opposing alliance as a liability
  if (a.slow) return 0; let d = 0, T = a.T;
  if (T.has('bump_dumper')) d += a.cap * 1.10;
  if (T.has('circular')) d += a.cap * 0.5; else if (T.has('bump_turret')) d += a.cap * 0.75;
  if (T.has('hopperless')) d += 70; return d;
};
const defense = (a, B) => { // DP this robot contributes to its own alliance against alliance B
  if (a.slow || a.st === 'scorer') return 0;
  let d = a.rb.dp || 0; if (a.st === 'blended') d += 20; const T = a.T;
  if (T.has('defense_bot')) {
    for (const b of B) { const t = b.T;
      if (t.has('trench_dumper')) d += 40; if (t.has('trench_turret')) d += 15; if (t.has('hopperless')) d += 30;
      if (t.has('bump_dumper')) d += b.cap * 1.10;
      if (t.has('circular')) d += b.cap * 0.5; else if (t.has('bump_turret')) d += b.cap * 0.75; }
    if (T.has('fast')) d += 50;
  }
  if (T.has('shotblocker')) for (const b of B) if (b.T.has('trench_dumper')) d += (T.has('defense_bot') ? 0.7 : 0.3) * b.epa;
  return d;
};
const reduction = a => (a.slow || a.st === 'scorer') ? 0 : (a.T.has('trench_turret') ? 20 : 0) + (a.T.has('fast') ? 20 : 0);
const rand60 = () => 1 + Math.floor(Math.random() * 60); // human player points, 1-60
function calc(A, B, hp) {
  const epa = A.reduce((s, a) => s + a.epa, 0), climb = A.reduce((s, a) => s + a.cp, 0);
  const oppDP = B.reduce((s, b) => s + defense(b, A), 0) + A.reduce((s, a) => s + givenDP(a), 0);
  const red = A.reduce((s, a) => s + reduction(a), 0), net = Math.max(0, oppDP - red);
  const score = Math.ceil(Math.max(0, epa - net) + climb + hp - 1e-9), r1 = x => Math.round(x * 10) / 10; // final scores round UP to whole numbers
  return { epa: r1(epa), climb, oppDP: r1(oppDP), reduction: red, netDP: r1(net), human: hp, score };
}

// ---------- events ----------
const robotOf = (ev, u) => (ev.entries.find(e => e.uid === u) || {}).robotId;
const entryUser = u => db.users[u];
const DUR = () => ({ q: 60000 / S, a: 20000 / S, t: 90000 / S, e: 30000 / S, g: 12000 / S });
function phaseOf(m, t) {
  const D = DUR(), d = t - m.t0, q = D.q, a = q + D.a, tp = a + D.t, e = tp + D.e, g = e + D.g;
  if (d < q) return ['queue', m.t0 + q]; if (d < a) return ['auto', m.t0 + a]; if (d < tp) return ['teleop', m.t0 + tp];
  if (d < e) return ['endgame', m.t0 + e]; return d < g ? ['done', m.t0 + g] : ['over', 0];
}
function newMatch(ev, o) { return Object.assign({ id: id(), phase: 'pending', t0: null, strat: {}, climbs: {}, started: false, final: false, result: null }, o); }
function genQuals(ev) {
  const uids = ev.entries.map(e => e.uid);
  let slots = [], ok = false;
  for (let attempt = 0; attempt < 200 && !ok; attempt++) {
    slots = [];
    for (let r = 0; r < ev.qualRounds; r++) shuffle(uids.slice()).forEach(u => slots.push({ u, s: false }));
    while (slots.length % 6) slots.push({ u: pick1(uids), s: true }); // surrogates fill the last match
    const nm = slots.length / 6, teamsIn = c => slots.slice(c * 6, c * 6 + 6).map(x => x.u);
    for (let pass = 0; pass < 400; pass++) { // repair matches that contain the same player twice, without breaking per-player counts
      let bad = 0;
      for (let c = 0; c < nm; c++) {
        const seen = new Set(); let di = -1;
        for (let i = 0; i < 6; i++) { const u = slots[c * 6 + i].u; if (seen.has(u)) { di = c * 6 + i; break; } seen.add(u); }
        if (di < 0) continue; bad++;
        const cand = []; for (let j = 0; j < slots.length; j++) { const d = Math.floor(j / 6); if (d === c) continue;
          if (!seen.has(slots[j].u) && !teamsIn(d).includes(slots[di].u)) cand.push(j); }
        const j = cand.length ? pick1(cand) : Math.floor(Math.random() * slots.length);
        [slots[di], slots[j]] = [slots[j], slots[di]];
      }
      if (!bad) { ok = true; break; }
    }
  }
  const nm = slots.length / 6; ev.quals = [];
  for (let c = 0; c < nm; c++) { const t = slots.slice(c * 6, c * 6 + 6);
    ev.quals.push(newMatch(ev, { label: 'Qual ' + (c + 1), kind: 'qual', red: t.slice(0, 3).map(x => x.u), blue: t.slice(3).map(x => x.u), sur: t.map(x => x.s) })); }
}
function rankings(ev) {
  const st = ev.stats || {};
  return ev.entries.map(e => { const s = st[e.uid] || { rp: 0, played: 0, score: 0 };
    return { uid: e.uid, rp: s.rp, played: s.played, avg: s.played ? s.score / s.played : 0, tb: (ev.tb || {})[e.uid] || 0 }; })
    .sort((a, b) => b.rp - a.rp || b.avg - a.avg || a.tb - b.tb);
}
const allowedStrats = (ev, u) => { const rb = db.robots[robotOf(ev, u)]; return rb && rb.traits.includes('defense_bot') ? ['scorer', 'defense', 'blended'] : ['scorer', 'blended']; };

function finalize(ev, m) {
  const A = m.red.map(u => eff(ev, m, u)), B = m.blue.map(u => eff(ev, m, u));
  const r = calc(A, B, rand60()), b = calc(B, A, rand60()), res = { red: r, blue: b };
  res.winner = r.score > b.score ? 'red' : b.score > r.score ? 'blue' : 'tie';
  if (res.winner === 'tie' && m.kind === 'playoff') res.tiebreak = pick1(['red', 'blue']); // bracket ties are decided at random
  const rpFor = (side, o, me) => { let rp = res.winner === side ? 3 : res.winner === 'tie' ? 1 : 0;
    const bn = { energized: me.score > 250, supercharged: me.score > 360, traversal: me.climb >= 50 };
    rp += (bn.energized ? 1 : 0) + (bn.supercharged ? 1 : 0) + (bn.traversal ? 1 : 0); return { rp, bonus: bn }; };
  res.rp = { red: rpFor('red', b, r), blue: rpFor('blue', r, b) };
  const sides = [['red', m.red, m.blue, 0], ['blue', m.blue, m.red, 3]];
  ev.stats = ev.stats || {};
  for (const [side, mine, opp, off] of sides) {
    mine.forEach((u, i) => {
      if (m.sur && m.sur[off + i]) return;
      const out = res.winner === 'tie' ? 'T' : res.winner === side ? 'W' : 'L', us = db.users[u]; if (!us) return;
      if (m.kind === 'qual') { const s = ev.stats[u] = ev.stats[u] || { rp: 0, played: 0, score: 0, w: 0, t: 0, l: 0 };
        s.rp += res.rp[side].rp; s.played++; s.score += res[side].score; s[out.toLowerCase()]++; }
      if (out === 'W') us.tokens += 200; else if (out === 'T') us.tokens += 50;
      db.history.push({ uid: u, robotId: robotOf(ev, u), eid: ev.id, mid: m.id, kind: m.kind, res: out, mates: mine.filter(x => x !== u), opps: opp.slice(), season: season().id, at: now() });
    });
  }
  m.result = res; m.final = true; save();
}

// ----- Discord notifications (optional; disabled when DISCORD_WEBHOOK_URL is unset) -----
const HOOK = process.env.DISCORD_WEBHOOK_URL || '', DH_MENTION = process.env.DISCORD_MENTION || '', SITE = process.env.SITE_URL || '';
const hasReal = list => list.some(u => { const x = db.users[u]; return x && !x.test; });
function notify(text, eid) {
  if (!HOOK) return;
  const content = (DH_MENTION ? DH_MENTION + ' ' : '') + text + (SITE && eid ? '\n' + SITE + '/#/event/' + eid : '');
  fetch(HOOK, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'FPP Fantasy', content: content.slice(0, 1990), allowed_mentions: { parse: ['users'].concat(DH_MENTION ? ['everyone'] : []) } }) }).catch(() => {});
}
function startQuals(ev) {
  if (ev.entries.length < 6) { ev.status = 'cancelled'; return; }
  ev.tb = {}; ev.entries.forEach(e => ev.tb[e.uid] = Math.random()); ev.stats = {};
  genQuals(ev); ev.status = 'quals'; ev.cur = 0; ev.quals[0].t0 = now(); ev.quals[0].phase = 'queue';
}
function tickMatch(ev, m) { // returns true when match fully over
  const [ph, end] = phaseOf(m, now());
  if (!m.started && ph !== 'queue') { m.started = true;
    if (m.alliances) refreshLineup(ev, m);
    [...m.red, ...m.blue].forEach(u => { if (!m.strat[u]) m.strat[u] = pick1(allowedStrats(ev, u)); });
    if (ph === 'auto' && (hasReal(m.red) || hasReal(m.blue))) notify(`⚔️ **${ev.name}** · ${m.label}\n🔴 ${m.red.map(un).join(', ')}\n🔵 ${m.blue.map(un).join(', ')}`, ev.id); }
  if (!m.final && (ph === 'done' || ph === 'over')) finalize(ev, m);
  if (ph === 'queue' && !m.stratPing) { m.stratPing = true; // once per match: ping linked players to pick strategies
    const ment = side => side.map(u => { const x = db.users[u]; return x && x.discord ? `<@${x.discord}> ${x.username}` : null; }).filter(Boolean);
    const r = ment(m.red), b = ment(m.blue);
    if (r.length || b.length) notify(`🎯 **${ev.name}** · ${m.label} — strategy draft is open!\n${r.length ? '🔴 ' + r.join('  ') + '\n' : ''}${b.length ? '🔵 ' + b.join('  ') : ''}`, ev.id); }
  m.phase = ph; m.end = end; return ph === 'over';
}
function refreshLineup(ev, m) {
  const [A, B] = m.alliances.map(aid => ev.sel.alliances.find(a => a.id === aid));
  m.red = A.lineup.slice(); m.blue = B.lineup.slice();
}

// ----- alliance selection -----
const activeUid = u => active(db.users[u]);
function pool(ev, forAid) {
  const s = ev.sel, inAll = new Set(); s.alliances.forEach(a => a.picks.forEach(u => inAll.add(u)));
  const capsOpen = new Set(s.alliances.filter(a => a.picks.length === 1 && a.id !== forAid && s.round === 1).map(a => a.captain));
  return ev.entries.map(e => e.uid).filter(u => !s.declined.includes(u) && (!inAll.has(u) || capsOpen.has(u)));
}
const orderFor = s => { const ids = s.alliances.filter(a => !a.empty).map(a => a.id); return s.round === 2 ? ids.reverse() : ids; };
function initSelection(ev) {
  const rk = rankings(ev), n = Math.min(8, Math.floor(ev.entries.length / 3));
  const als = rk.slice(0, n).map((r, i) => ({ id: 'A' + (i + 1), captain: r.uid, picks: [r.uid] }));
  for (let i = n; i < 8; i++) als.push({ id: 'A' + (i + 1), captain: null, picks: [], empty: true }); // surrogate alliance: no robots, automatically loses
  ev.sel = { everCaptains: rk.slice(0, n).map(r => r.uid), alliances: als, round: 1, rounds: ev.thirdRound ? 3 : 2, order: [], skipped: [], declined: [], log: [], cur: null, anum: n + 1 };
  ev.sel.order = orderFor(ev.sel); ev.status = 'selection'; nextTurn(ev);
}
function nextTurn(ev, afterSkip) {
  const s = ev.sel; s.cur = null;
  for (let first = true; ; first = false) {
    let aid = (s.skipped.length && !(afterSkip && first)) ? s.skipped.shift() : s.order.shift();
    if (aid == null) {
      if (s.round >= s.rounds) return finishSel(ev);
      s.round++; s.order = orderFor(s); s.log.push('— Round ' + s.round + ' —'); continue;
    }
    const al = s.alliances.find(a => a.id === aid); if (!al || al.empty || al.picks.length >= s.round + 1) continue;
    if (!pool(ev, aid).length) return finishSel(ev);
    const first = al.picks.length === 1 && s.round === 1;
    s.cur = { aid, phase: 'pick', started: now(), deadline: now() + (first ? 45000 : 90000) / S, first };
    return;
  }
}
function doPick(ev, aid, uid) {
  const s = ev.sel, c = s.cur; c.phase = 'invite'; c.invitee = uid;
  c.inviteDeadline = now() + (activeUid(uid) ? 30000 : 6000) / S;
  s.log.push(un(s.alliances.find(a => a.id === aid).captain) + "'s alliance invites " + un(uid));
}
function respond(ev, accept) {
  const s = ev.sel, c = s.cur, al = s.alliances.find(a => a.id === c.aid), uid = c.invitee;
  if (accept) {
    s.log.push(un(uid) + ' accepted');
    const other = s.alliances.find(a => a.id !== al.id && a.captain === uid && a.picks.length === 1);
    al.picks.push(uid);
    if (other) {
      s.alliances = s.alliances.filter(a => a.id !== other.id); s.order = s.order.filter(x => x !== other.id); s.skipped = s.skipped.filter(x => x !== other.id);
      const inAll = new Set(); s.alliances.forEach(a => a.picks.forEach(u => inAll.add(u)));
      const nc = rankings(ev).map(r => r.uid).find(u => !inAll.has(u) && !s.declined.includes(u));
      const real = s.alliances.filter(a => !a.empty), empt = s.alliances.filter(a => a.empty); let na = null;
      if (nc) { na = { id: 'tmp', captain: nc, picks: [nc] }; real.push(na); (s.everCaptains = s.everCaptains || []).push(nc); s.log.push(un(nc) + ' moves up as a new captain'); } else empt.push({ id: 'tmp', captain: null, picks: [], empty: true });
      s.alliances = real.concat(empt); renumber(s); // alliances stay listed A1..A8 in order
      if (na && s.round === 1) s.order.push(na.id);
    }
    nextTurn(ev);
  } else {
    s.declined.push(uid); s.log.push(un(uid) + ' declined');
    c.phase = 'pick'; c.invitee = null; c.started = now(); c.deadline = now() + (c.first ? 45000 : 90000) / S;
  }
}
const un = u => (db.users[u] || {}).username || '?';
function renumber(s) {
  const map = {}; s.alliances.forEach((a, i) => { const nid = 'A' + (i + 1); if (a.id !== 'tmp') map[a.id] = nid; a.id = nid; });
  s.order = s.order.map(x => map[x] || x); s.skipped = s.skipped.map(x => map[x] || x); if (s.cur && map[s.cur.aid]) s.cur.aid = map[s.cur.aid];
}
const isEmptyAl = (ev, id) => { const a = ev.sel.alliances.find(x => x.id === id); return !a || !!a.empty; };
function autoMatch(ev, n, A, B) { // a match against a surrogate alliance is an automatic win, nothing is played
  const ea = isEmptyAl(ev, A), eb = isEmptyAl(ev, B), winner = ea && !eb ? 'blue' : 'red', w = winner === 'red' ? A : B, l = winner === 'red' ? B : A;
  const m = newMatch(ev, { label: 'Match ' + n, kind: 'playoff', alliances: [A, B], red: [], blue: [], auto: true, final: true, phase: 'over', bn: n, result: { winner, red: { score: 0 }, blue: { score: 0 }, rp: { red: { rp: 0, bonus: {} }, blue: { rp: 0, bonus: {} } } } });
  ev.po.matches.push(m); ev.po.res[n] = { w, l };
}
function finishSel(ev) {
  const s = ev.sel; s.cur = null; s.alliances.forEach(a => { a.lineup = a.picks.slice(0, 3); a.backup = a.picks[3] || null; });
  initBracket(ev, false); ev.status = 'playoffs';
}
function tickSelection(ev) {
  const s = ev.sel, c = s.cur; if (!c) return;
  const al = s.alliances.find(a => a.id === c.aid);
  if (c.phase === 'pick') {
    if (now() > c.deadline || (!activeUid(al.captain) && now() > c.started + 3000 / S)) {
      const p = pool(ev, al.id), nonCap = p.filter(u => !s.alliances.some(a => a.captain === u)), u = pick1(nonCap.length ? nonCap : p);
      if (u) doPick(ev, al.id, u);
    }
  } else if (now() > c.inviteDeadline) respond(ev, true);
}

// ----- playoffs -----
const DEFS = [[1,{al:0},{al:7}],[2,{al:3},{al:4}],[3,{al:1},{al:6}],[4,{al:2},{al:5}],[5,{L:1},{L:2}],[6,{L:3},{L:4}],[7,{W:1},{W:2}],[8,{W:3},{W:4}],[9,{L:7},{W:6}],[10,{L:8},{W:5}],[11,{W:7},{W:8}],[12,{W:9},{W:10}],[13,{L:11},{W:12}]];
function initBracket(ev, finalsOnly) {
  ev.po = { defs: finalsOnly ? [] : DEFS, res: {}, idx: 0, cur: null, matches: [], fin: { w: [0, 0], n: 0 }, stage: finalsOnly ? 'finals' : 'bracket', done: false };
}
function resolve(ev, ref) {
  const s = ev.sel, po = ev.po;
  if (ref.al != null) return (s.alliances[ref.al] || {}).id || null;
  if (ref.W) return po.res[ref.W].w; return po.res[ref.L].l;
}
function playPO(ev, label, A, B, extra) {
  const m = newMatch(ev, Object.assign({ label, kind: 'playoff', alliances: [A, B], red: [], blue: [] }, extra || {}));
  refreshLineup(ev, m); m.t0 = now(); m.phase = 'queue'; ev.po.cur = m; ev.po.matches.push(m); return m;
}
function tickPlayoffs(ev) {
  const po = ev.po; if (po.done) return;
  if (po.cur) {
    if (!tickMatch(ev, po.cur)) return;
    const m = po.cur, w = m.result.tiebreak || m.result.winner; po.cur = null;
    const win = m.alliances[w === 'red' ? 0 : 1], lose = m.alliances[w === 'red' ? 1 : 0];
    if (m.bn) po.res[m.bn] = { w: win, l: lose };
    else { po.fin.w[w === 'red' ? 0 : 1]++; po.fin.n++; }
  }
  for (;;) {
    if (po.stage === 'bracket') {
      if (po.idx >= po.defs.length) { po.stage = 'finals'; continue; }
      const [n, ra, rb] = po.defs[po.idx++], A = resolve(ev, ra), B = resolve(ev, rb);
      if (!A || !B) { po.res[n] = { w: A || B || null, l: null }; continue; }
      if (isEmptyAl(ev, A) || isEmptyAl(ev, B)) { autoMatch(ev, n, A, B); continue; }
      playPO(ev, 'Match ' + n, A, B, { bn: n }); return;
    }
    const A = po.fa || (po.fa = po.defs.length ? resolve(ev, { W: 11 }) : ev.sel.alliances[0].id), B = po.fb || (po.fb = po.defs.length ? resolve(ev, { W: 13 }) : ev.sel.alliances[1].id);
    if (!A || !B) { po.champ = A || B; po.final2 = null; return endEvent(ev); }
    if (po.defs.length && (isEmptyAl(ev, A) || isEmptyAl(ev, B))) { po.champ = isEmptyAl(ev, A) ? B : A; po.final2 = po.champ === A ? B : A; return endEvent(ev); }
    if (po.fin.w[0] >= 2 || po.fin.w[1] >= 2) { po.champ = po.fin.w[0] >= 2 ? A : B; po.final2 = po.champ === A ? B : A; return endEvent(ev); }
    playPO(ev, 'Finals ' + (po.fin.n + 1), A, B); return;
  }
}
function endEvent(ev) {
  const po = ev.po, s = ev.sel; po.done = true; ev.status = 'complete';
  const al = id => s.alliances.find(a => a.id === id), members = a => a ? a.picks.slice() : [];
  const champ = al(po.champ), fin = al(po.final2);
  const third = po.res[13] && al(po.res[13].l), fourth = po.res[12] && al(po.res[12].l);
  ev.result = { champion: members(champ), finalist: members(fin) };
  const game = season().game;
  const award = (a, type, title) => members(a).forEach(u => { const us = db.users[u]; if (us) us.awards.push({ type, title, eventName: ev.name, game, season: season().name, eventId: ev.id, at: now() }); });
  award(champ, 'banner', 'Champions'); award(fin, 'finalist', 'Finalist');
  if (ev.type === 'district' || ev.type === 'dcmp') {
    const P = db.points[season().id] = db.points[season().id] || {};
    const give = (a, p) => members(a).forEach(u => P[u] = (P[u] || 0) + p);
    give(champ, 5); give(fin, 4); give(third, 2); give(fourth, 1);
  }
  if (ev.type === 'conference') {
    ev.champAlliance = members(champ).slice(0, 3);
    const sibs = Object.values(db.events).filter(e => e.cmpGroup === ev.cmpGroup && e.type === 'conference');
    if (sibs.length === 2 && sibs.every(e => e.status === 'complete')) createCmpFinals(sibs);
  }
  save();
}
function createCmpFinals(confs) {
  const e = { id: id(), name: 'FPP Fantasy Championship', type: 'cmpfinals', division: 'Championship', seasonId: season().id, startAt: now() + 300000 / S, status: 'scheduled', maxTeams: 6, qualRounds: 0, thirdRound: false, entries: [], cmpGroup: confs[0].cmpGroup };
  const als = confs.map((c, i) => { const a = c.sel.alliances.find(x => x.picks[0] === c.champAlliance[0]) || c.sel.alliances[0];
    a.picks.forEach(u => { if (!e.entries.some(x => x.uid === u)) e.entries.push({ uid: u, robotId: robotOf(c, u) }); });
    return { id: 'C' + (i + 1), label: c.name.replace(/^FPP Fantasy /, '').replace(/ Conference$/, ''), captain: a.captain, picks: a.picks.slice(), lineup: a.lineup.slice(), backup: a.backup }; });
  e.sel = { alliances: als, declined: [], log: [], round: 3, rounds: 3, order: [], skipped: [], cur: null };
  db.events[e.id] = e;
}

function tickEvent(ev) {
  const t = now();
  if (ev.status === 'scheduled') {
    if (t < ev.startAt) return;
    const real = ev.entries.some(e => { const x = db.users[e.uid]; return x && !x.test; });
    if (ev.type === 'cmpfinals') { initBracket(ev, true); ev.status = 'playoffs'; if (real) notify(`🏆 **${ev.name}** — championship finals are set!`, ev.id); return; }
    startQuals(ev);
    if (ev.status === 'quals' && real) notify(`🟢 **${ev.name}** is live!\n${ev.division} · ${ev.type === 'dcmp' ? 'district championship' : 'district event'}`, ev.id);
    return;
  }
  if (ev.status === 'quals') {
    const m = ev.quals[ev.cur];
    if (tickMatch(ev, m)) {
      if (ev.cur + 1 < ev.quals.length) { ev.cur++; const n = ev.quals[ev.cur]; n.t0 = now(); n.phase = 'queue'; }
      else { ev.status = 'wait'; ev.waitUntil = now() + 300000 / S; }
    }
  } else if (ev.status === 'wait') { if (t >= ev.waitUntil) initSelection(ev); }
  else if (ev.status === 'selection') tickSelection(ev);
  else if (ev.status === 'playoffs') tickPlayoffs(ev);
}
setInterval(() => { try { const evs = Object.values(db.events); evs.forEach(tickEvent); if (evs.some(e => !['scheduled', 'complete', 'cancelled'].includes(e.status))) save(); } catch (e) { console.error(e); } }, 400);

// ---------- views ----------
const robotBrief = r => r && ({ id: r.id, number: r.number, rank: r.rank, epa: r.epa, dp: r.dp, capacity: r.capacity, traits: r.traits, image: r.image ? true : false });
function teamBrief(ev, u) { const us = db.users[u]; const rb = db.robots[robotOf(ev, u)]; return { uid: u, username: us ? us.username : '?', robot: robotBrief(rb), active: active(us) }; }
function matchView(ev, m, me) {
  if (!m) return null;
  const done = m.phase === 'done' || m.phase === 'over';
  const mine = m.red.includes(me) ? 'red' : m.blue.includes(me) ? 'blue' : null;
  const v = { id: m.id, label: m.label, kind: m.kind, phase: m.phase, end: m.end, t0: m.t0, red: m.red.map(u => teamBrief(ev, u)), blue: m.blue.map(u => teamBrief(ev, u)), mine, alliances: m.alliances || null };
  if (mine) { v.myStrategies = {}; (mine === 'red' ? m.red : m.blue).forEach(u => v.myStrategies[u] = m.strat[u] || null);
    v.climbed = m.climbs[me] || {}; v.canClimb = !!db.robots[robotOf(ev, me)].traits.some(t => /_climb$/.test(t));
    v.allowed = allowedStrats(ev, me); }
  v.allowedBy = {}; (mine === 'red' ? m.red : mine === 'blue' ? m.blue : []).forEach(u => v.allowedBy[u] = allowedStrats(ev, u));
  if (done && m.result) v.result = m.result; else v.scorePending = true;
  return v;
}
function sumMatch(ev, m) { const done = m.final; return { id: m.id, label: m.label, red: m.red, blue: m.blue, phase: m.phase, red_s: done && !m.auto ? m.result.red.score : null, blue_s: done && !m.auto ? m.result.blue.score : null, winner: done ? (m.result.tiebreak || m.result.winner) : null, tie: !!(done && m.result.winner === 'tie'), auto: !!m.auto, rp: done ? { red: m.result.rp.red, blue: m.result.rp.blue } : null, alliances: m.alliances || null, sur: m.sur || null }; }
function eventView(ev, me) {
  const names = {}; ev.entries.forEach(e => names[e.uid] = teamBrief(ev, e.uid));
  const v = { now: now(), id: ev.id, name: ev.name, type: ev.type, division: ev.division, status: ev.status, startAt: ev.startAt, maxTeams: ev.maxTeams, qualRounds: ev.qualRounds, thirdRound: ev.thirdRound, game: season().game,
    teams: names, entries: ev.entries.map(e => e.uid), mine: ev.entries.find(e => e.uid === me) || null, waitUntil: ev.waitUntil || null,
    rankings: ev.stats ? rankings(ev).map((r, i) => ({ rank: i + 1, uid: r.uid, rp: r.rp, played: r.played, avg: Math.round(r.avg * 10) / 10, w: ((ev.stats || {})[r.uid] || {}).w || 0, t: ((ev.stats || {})[r.uid] || {}).t || 0, l: ((ev.stats || {})[r.uid] || {}).l || 0 })) : [] };
  if (ev.quals) { v.schedule = ev.quals.map(m => sumMatch(ev, m)); if (ev.status === 'quals') v.current = matchView(ev, ev.quals[ev.cur], me); }
  if (ev.sel) { const s = ev.sel;
    v.selection = { round: s.round, rounds: s.rounds, declined: s.declined, log: s.log.slice(-14), alliances: s.alliances.map((a, i) => ({ id: a.id, label: confLabel(ev, a), rank: i + 1, empty: !!a.empty, captain: a.captain, picks: a.picks, backup: a.backup || null, lineup: a.lineup || null })),
      cur: s.cur ? Object.assign({}, s.cur, { captain: (s.alliances.find(a => a.id === s.cur.aid) || {}).captain, canSkip: s.order.length > 0 }) : null,
      available: s.cur ? pool(ev, s.cur.aid) : [] }; }
  if (ev.po) { v.playoffs = { stage: ev.po.stage, matches: ev.po.matches.map(m => sumMatch(ev, m)), fin: ev.po.fin, res: ev.po.res, champ: ev.po.champ || null, current: matchView(ev, ev.po.cur, me) };
    if (ev.po.cur) v.current = v.playoffs.current; }
  if (ev.result) v.result = ev.result;
  if (v.mine && ev.status === 'scheduled') v.canWithdraw = true;
  return v;
}


async function mkTest(div, rb) { // quick moderator test account: password is always test1234
  let n = db.testSeq || 0, nm; do { nm = 'test' + String(++n).padStart(3, '0'); } while (userByName(nm)); db.testSeq = n;
  const prof = { division: div, tokens: Math.max(0, STARTING - price(rb.rank)), inventory: [rb.id], friends: [], awards: [], joined: now(), mod: false, test: true };
  const uid = await register_user(nm, '', 'test1234', prof);
  const u = Object.assign({ id: uid, username: nm, email: '', lastSeen: 0 }, prof);
  db.users[uid] = u; return u;
}
async function delTest(u) {
  if (Object.values(db.events).some(e => !['scheduled', 'complete', 'cancelled'].includes(e.status) && e.entries.some(x => x.uid === u.id))) return false; // mid-event: leave alone
  Object.values(db.events).forEach(e => { if (e.status === 'scheduled') e.entries = e.entries.filter(x => x.uid !== u.id); });
  await qrun('DELETE FROM users WHERE id = ?', [+u.id]); // ON DELETE CASCADE removes user_auth + sessions rows
  for (const [tok, s] of sessCache) if (s.uid === String(u.id)) sessCache.delete(tok);
  Object.values(db.users).forEach(x => { x.friends = (x.friends || []).filter(f => f !== u.id); });
  db.history = db.history.filter(h => h.uid !== u.id); db.history.forEach(h => { h.mates = h.mates.filter(x => x !== u.id); h.opps = h.opps.filter(x => x !== u.id); });
  Object.values(db.points).forEach(p => { delete p[u.id]; }); delete db.users[u.id]; userHash.delete(u.id); return true;
}

// ---------- per-player event history ----------
const ELIM_ROUND = { 5: 2, 6: 2, 9: 3, 10: 3, 12: 4, 13: 5 }; // lower-bracket matches where the loser is out
const confLabel = (ev, a) => a.label || (ev.type === 'cmpfinals' ? (a.id === 'C1' ? 'Albany' : 'Kettering') : null); // older championship data has no stored label
function eventHistory(u) {
  return Object.values(db.events).filter(ev => ['quals', 'wait', 'selection', 'playoffs', 'complete'].includes(ev.status) && ev.entries.some(e => e.uid === u.id))
    .sort((a, b) => b.startAt - a.startAt).map(ev => {
      const h = { id: ev.id, name: ev.name, status: ev.status, type: ev.type }, st = ev.stats && ev.stats[u.id];
      const al = ev.sel && ev.po && ev.sel.alliances.find(a => !a.empty && a.picks.includes(u.id));
      if (ev.type === 'cmpfinals') { // a playoff between two conference winners: no qualification results
        const rb = db.robots[(ev.entries.find(e => e.uid === u.id) || {}).robotId], dr = ranksFor(u.division).find(x => x.uid === u.id);
        h.finals = { epa: rb ? rb.epa : 0, robot: rb ? rb.number : null, district: u.division, districtRank: dr ? dr.rank : null, districtPoints: dr ? dr.points : 0,
          banners: u.awards.filter(a => a.type === 'banner' && a.eventId !== ev.id && a.season === season().name).map(a => a.eventName) };
      } else if (st) { // captains, and everyone who didn't reach the bracket, get their qualification rank and record
        const caps = ev.sel ? (ev.sel.everCaptains || ev.sel.alliances.map(a => a.captain)) : [];
        if (caps.includes(u.id) || !al) h.qual = { rank: rankings(ev).findIndex(r => r.uid === u.id) + 1, w: st.w || 0, t: st.t || 0, l: st.l || 0 };
      }
      if (al) { const po = ev.po, idx = al.picks.indexOf(u.id);
        h.playoff = { role: (ev.type === 'cmpfinals' ? ['Captain', '1st Pick', '2nd Pick', 'Backup'] : ['Captain', 'First Pick', 'Second Pick', 'Backup Robot'])[idx] || 'Pick', alliance: al.id.replace(/^[A-Z]/, ''), conf: confLabel(ev, al), outcome: 'active' };
        if (po.done) { if (po.champ === al.id) h.playoff.outcome = 'won'; else if (po.final2 === al.id) h.playoff.outcome = 'finals';
          else { const n = Object.keys(ELIM_ROUND).find(k => po.res[k] && po.res[k].l === al.id); if (n) { h.playoff.outcome = 'bracket'; h.playoff.round = ELIM_ROUND[n]; } } } }
      return h; });
}

// ---------- stats ----------
function profile(u) {
  const H = db.history.filter(h => h.uid === u.id), cnt = f => { const m = {}; H.forEach(h => f(h).forEach(x => m[x] = (m[x] || 0) + 1)); return m; };
  const top = m => { let b = null, bv = 0; for (const k in m) if (m[k] > bv) { b = k; bv = m[k]; } return b ? { username: un(b), count: bv } : null; };
  const w = H.filter(h => h.res === 'W').length, t = H.filter(h => h.res === 'T').length, l = H.filter(h => h.res === 'L').length;
  return { username: u.username, division: u.division, joined: u.joined, isMod: !!u.mod, tokens: undefined,
    record: { w, t, l }, winPct: H.length ? Math.round(1000 * w / H.length) / 10 : 0, played: H.length,
    robots: u.inventory.map(id => robotBrief(db.robots[id])).filter(Boolean).map(r => Object.assign(r, { image: undefined })),
    awards: u.awards, banners: u.awards.filter(a => a.type === 'banner'), friends: u.friends.map(un),
    lostToMost: top(cnt(h => h.res === 'L' ? h.opps : [])), wonVsMost: top(cnt(h => h.res === 'W' ? h.opps : [])), wonWithMost: top(cnt(h => h.res === 'W' ? h.mates : [])),
    points: (db.points[season().id] || {})[u.id] || 0, eventHistory: eventHistory(u) };
}
const ranksFor = div => Object.values(db.users).filter(u => u.division === div).map(u => ({ uid: u.id, username: u.username, points: (db.points[season().id] || {})[u.id] || 0 })).sort((a, b) => b.points - a.points || a.username.localeCompare(b.username)).map((r, i) => Object.assign(r, { rank: i + 1 }));

// ---------- HTTP ----------
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.jpg': 'image/jpeg', '.svg': 'image/svg+xml' };
const send = (res, code, obj, hdr) => { res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, hdr || {})); res.end(JSON.stringify(obj)); };
class HttpErr extends Error { constructor(c, m) { super(m); this.code = c; } }
const need = (c, m) => { if (!c) throw new HttpErr(400, m); };
function body(req) { return new Promise((ok, no) => { let b = '', n = 0; req.on('data', d => { n += d.length; if (n > 4e6) { no(new HttpErr(413, 'Too large')); req.destroy(); } else b += d; }); req.on('end', () => { try { ok(b ? JSON.parse(b) : {}); } catch (e) { no(new HttpErr(400, 'Bad JSON')); } }); }); }
const cookie = (req, k) => (req.headers.cookie || '').split(/;\s*/).map(c => c.split('=')).find(c => c[0] === k)?.[1];
function me(u) { return { champ: Object.values(db.events).some(e => e.seasonId === season().id && (e.type === 'conference' || e.type === 'cmpfinals')), id: u.id, username: u.username, email: u.email || '', discord: u.discord || '', division: u.division, tokens: u.tokens, isMod: !!u.mod, inventory: u.inventory.map(i => robotBrief(db.robots[i])), friends: u.friends.map(un), season: season() }; }

async function api(req, res, url) {
  const m = req.method, p = url.pathname, q = url.searchParams;
  const sid = cookie(req, 'sid');
  const user = (sid && db.users[await validate_session(sid)]) || null;
  if (user) user.lastSeen = now();
  const B = (m === 'POST' || m === 'PUT' || m === 'DELETE') ? await body(req) : {};
  const auth = () => { if (!user) throw new HttpErr(401, 'Sign in required'); return user; };
  const mod = () => { if (!auth().mod) throw new HttpErr(403, 'Moderators only'); return user; };
  let r;
  if (m === 'GET' && p === '/api/ping') return send(res, 200, { ok: true, t: now() });
  if (m === 'GET' && p === '/api/public') return send(res, 200, { robots: Object.values(db.robots).map(r => Object.assign({}, r, { image: r.image ? true : false, price: price(r.rank) })), ranks: RANKS.map((r, i) => ({ rank: r, price: PRICES[i] })), season: season(), divisions: DIVS, traits: TRAITS, starting: STARTING, scale: S });
  if (m === 'GET' && (r = p.match(/^\/api\/robot-image\/(\d+)$/))) { const rb = db.robots[r[1]]; if (!rb || !rb.image) { res.writeHead(404); return res.end(); } const mm = rb.image.match(/^data:(.+?);base64,(.*)$/); res.writeHead(200, { 'Content-Type': mm[1], 'Cache-Control': 'max-age=60' }); return res.end(Buffer.from(mm[2], 'base64')); }
  if (m === 'POST' && p === '/api/register') {
    const un_ = String(B.username || '').trim(), pw = String(B.password || '');
    need(/^[A-Za-z0-9_]{3,20}$/.test(un_), 'Username: 3-20 letters, numbers or _'); need(pw.length >= 6, 'Password must be at least 6 characters'); need(!userByName(un_), 'Username taken');
    const cart = [...new Set(B.cart || [])].map(i => db.robots[i]); need(cart.length && cart.every(Boolean), 'Buy at least one robot first');
    const cost = cart.reduce((s, r) => s + price(r.rank), 0); need(cost <= STARTING, 'Cart is over 6000 tokens');
    const MODU = (process.env.MOD_USERNAME || '').toLowerCase(), first = MODU ? MODU === un_.toLowerCase() : !Object.keys(db.users).length; // owner account = MOD_USERNAME, or the very first account if unset
    const email = String(B.email || '').slice(0, 120);
    const prof = { division: pick1(DIVS), tokens: STARTING - cost, inventory: cart.map(r => r.id), friends: [], awards: [], joined: now(), mod: !!first, test: false };
    const uid = await register_user(un_, email, pw, prof);
    const u = Object.assign({ id: uid, username: un_, email, lastSeen: 0 }, prof);
    db.users[uid] = u; save(); return send(res, 200, me(u), await create_session(uid));
  }
  if (m === 'POST' && p === '/api/login') {
    const uid = await authenticate_user(String(B.username || ''), String(B.password || ''));
    const u = db.users[uid]; if (!u) throw new HttpErr(401, 'Invalid username or password');
    return send(res, 200, me(u), await create_session(uid));
  }
  if (m === 'POST' && p === '/api/logout') { await logout_user(sid); return send(res, 200, {}, { 'Set-Cookie': 'sid=; Path=/; Max-Age=0' }); }
  if (m === 'GET' && p === '/api/me') return send(res, 200, user ? me(user) : null);
  if (m === 'POST' && p === '/api/me/email') { auth(); const em = String(B.email || '').slice(0, 120); try { await qrun('UPDATE users SET email = ? WHERE id = ?', [em, +user.id]); } catch (e) { throw new HttpErr(400, 'Email already in use'); } user.email = em; save(); return send(res, 200, me(user)); }
  if (m === 'POST' && p === '/api/me/discord') { auth(); const raw = String(B.discord || '').trim();
    if (!raw) { delete user.discord; save(); return send(res, 200, {}); }
    need(/^\d{5,25}$/.test(raw), 'Paste your numeric Discord user ID (Discord Settings → Advanced → Developer Mode, then right-click your name → Copy User ID)');
    user.discord = raw; save(); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/shop/buy') { auth(); const rb = db.robots[B.robotId]; need(rb, 'No such robot'); need(!user.inventory.includes(rb.id), 'Already owned'); need(user.tokens >= price(rb.rank), 'Not enough tokens'); user.tokens -= price(rb.rank); user.inventory.push(rb.id); save(); return send(res, 200, me(user)); }
  if (m === 'GET' && p === '/api/events') { auth(); const div = q.get('division') || user.division;
    return send(res, 200, Object.values(db.events).filter(e => e.seasonId === season().id).filter(e => e.division === div || e.type === 'cmpfinals' || e.cmpGroup && e.entries.some(x => x.uid === user.id)).sort((a, b) => b.startAt - a.startAt).map(e => ({ id: e.id, name: e.name, type: e.type, division: e.division, status: e.status, startAt: e.startAt, teams: e.entries.length, maxTeams: e.maxTeams, joined: e.entries.some(x => x.uid === user.id) }))); }
  if (m === 'GET' && (r = p.match(/^\/api\/events\/(\d+)$/))) { auth(); const ev = db.events[r[1]]; need(ev, 'No such event'); return send(res, 200, eventView(ev, user.id)); }
  if (m === 'GET' && (r = p.match(/^\/api\/events\/(\d+)\/match\/(\d+)$/))) { auth(); const ev = db.events[r[1]]; need(ev, 'No such event');
    const mt = [...(ev.quals || []), ...((ev.po && ev.po.matches) || [])].find(x => x.id === r[2]); need(mt && mt.final && !mt.auto, 'That match has no scoring details yet');
    const side = l => l.map(u => Object.assign(teamBrief(ev, u), { strategy: (mt.strat || {})[u] || null, climb: (mt.climbs || {})[u] || {} }));
    return send(res, 200, { label: mt.label, kind: mt.kind, alliances: mt.alliances || null, red: side(mt.red), blue: side(mt.blue), result: mt.result, sur: mt.sur || null }); }
  if (m === 'POST' && (r = p.match(/^\/api\/events\/(\d+)\/signup$/))) { auth(); const ev = db.events[r[1]]; need(ev, 'No such event'); need(ev.status === 'scheduled' && now() < ev.startAt, 'Signups are closed');
    need(user.inventory.includes(B.robotId), 'Pick a robot you own'); const ex = ev.entries.find(e => e.uid === user.id);
    if (ex) { ex.robotId = B.robotId; save(); return send(res, 200, {}); }
    need(ev.entries.length < ev.maxTeams, 'Event is full (' + ev.maxTeams + ' max)');
    if (ev.type === 'district' || ev.type === 'dcmp') need(user.division === ev.division, 'This event is for the ' + ev.division + ' division');
    if (ev.type === 'dcmp') need(ranksFor(ev.division).slice(0, 35).some(x => x.uid === user.id), 'Only the top 35 in district points qualify');
    need(ev.type === 'district' || ev.type === 'dcmp', 'Invite-only event'); ev.entries.push({ uid: user.id, robotId: B.robotId }); save(); return send(res, 200, {}); }
  if (m === 'DELETE' && (r = p.match(/^\/api\/events\/(\d+)\/signup$/))) { auth(); const ev = db.events[r[1]]; need(ev && ev.status === 'scheduled' && ev.type !== 'conference', 'Cannot withdraw'); ev.entries = ev.entries.filter(e => e.uid !== user.id); save(); return send(res, 200, {}); }
  if (m === 'POST' && (r = p.match(/^\/api\/events\/(\d+)\/(strategy|climb|pick|respond|skip|lineup)$/))) {
    auth(); const ev = db.events[r[1]]; need(ev, 'No such event'); const act = r[2];
    if (act === 'strategy' || act === 'climb') {
      const mt = ev.status === 'quals' ? ev.quals[ev.cur] : ev.status === 'playoffs' && ev.po.cur; need(mt, 'No active match');
      const tgt = act === 'strategy' && B.uid ? String(B.uid) : user.id;
      if (act === 'strategy') { need(mt.phase === 'queue', 'Strategy locks when the queue ends'); const side = mt.red.includes(user.id) ? mt.red : mt.blue.includes(user.id) ? mt.blue : null; need(side && side.includes(tgt), 'Not on that alliance');
        if (tgt !== user.id) need(!active(db.users[tgt]), 'Teammate is active — they pick their own strategy');
        need(allowedStrats(ev, tgt).includes(B.strategy), 'Strategy not available for that robot'); mt.strat[tgt] = B.strategy; return send(res, 200, {}); }
      need(mt.red.includes(user.id) || mt.blue.includes(user.id), 'Not in this match');
      need(db.robots[robotOf(ev, user.id)].traits.some(t => /_climb$/.test(t)), 'Your robot cannot climb');
      const D = DUR(), win = Math.min(2000, D.a), c = mt.climbs[user.id] = mt.climbs[user.id] || {}, t = now();
      const aEnd = mt.t0 + D.q + D.a, eEnd = mt.t0 + D.q + D.a + D.t + D.e;
      if (mt.phase === 'auto' && t >= aEnd - win) c.a = true; else if (mt.phase === 'endgame' && t >= eEnd - win) c.e = true; else throw new HttpErr(400, 'Climb opens in the last 2 seconds of Auto and Endgame');
      return send(res, 200, c);
    }
    if (act === 'lineup') { need(ev.sel && ev.status === 'playoffs', 'Not in playoffs'); const al = ev.sel.alliances.find(a => a.captain === user.id || ev.type === 'cmpfinals' && a.picks.includes(user.id) && a.captain === user.id); need(al, 'Captains only');
      const L = (B.uids || []).map(String); need(L.length === 3 && new Set(L).size === 3 && L.every(u => al.picks.includes(u)), 'Pick 3 alliance members');
      need(!ev.po.cur || ev.po.cur.phase === 'queue' || !ev.po.cur.alliances.includes(al.id), 'Lineup is locked during your match'); al.lineup = L; return send(res, 200, {}); }
    need(ev.status === 'selection' && ev.sel.cur, 'No selection in progress'); const c = ev.sel.cur, al = ev.sel.alliances.find(a => a.id === c.aid);
    if (act === 'pick') { need(c.phase === 'pick' && al.captain === user.id, "It's not your pick"); const u = String(B.uid); need(pool(ev, al.id).includes(u), 'That team is unavailable'); doPick(ev, al.id, u); return send(res, 200, {}); }
    if (act === 'skip') { need(c.phase === 'pick' && al.captain === user.id, "It's not your pick"); need(ev.sel.order.length > 0, 'You are the last alliance — you must pick'); ev.sel.skipped.push(c.aid); ev.sel.log.push(user.username + ' skipped'); nextTurn(ev, true); return send(res, 200, {}); }
    if (act === 'respond') { need(c.phase === 'invite' && c.invitee === user.id, 'No invite for you'); respond(ev, !!B.accept); return send(res, 200, {}); }
  }
  if (m === 'GET' && (r = p.match(/^\/api\/users\/([^/]+)$/))) { auth(); const u = userByName(decodeURIComponent(r[1])); need(u, 'No such player'); return send(res, 200, profile(u)); }
  if (m === 'GET' && p === '/api/users') { auth(); const s = (q.get('q') || '').toLowerCase(); return send(res, 200, Object.values(db.users).filter(u => u.username.toLowerCase().includes(s)).slice(0, 20).map(pubUser)); }
  if (m === 'POST' && p === '/api/friends') { auth(); const u = userByName(B.username || ''); need(u && u.id !== user.id, 'No such player'); if (!user.friends.includes(u.id)) user.friends.push(u.id); save(); return send(res, 200, {}); }
  if (m === 'GET' && (r = p.match(/^\/api\/robots\/(\d+)$/))) { auth(); const rb = db.robots[r[1]]; need(rb, 'No such robot');
    const H = db.history.filter(h => h.robotId === rb.id), evs = {}; H.forEach(h => { const e = evs[h.eid] = evs[h.eid] || { eid: h.eid, name: (db.events[h.eid] || {}).name, w: 0, t: 0, l: 0 }; e[h.res.toLowerCase()]++; });
    const owners = Object.values(db.users).filter(u => u.inventory.includes(rb.id)).map(u => u.username);
    return send(res, 200, { robot: Object.assign({}, rb, { image: rb.image ? true : false, price: price(rb.rank) }), owners, events: Object.values(evs), record: { w: H.filter(h => h.res === 'W').length, t: H.filter(h => h.res === 'T').length, l: H.filter(h => h.res === 'L').length } }); }
  if (m === 'GET' && (r = p.match(/^\/api\/district\/(\w+)$/))) { auth(); need(DIVS.includes(r[1]), 'Unknown division'); return send(res, 200, ranksFor(r[1])); }
  // moderator
  if (m === 'POST' && p === '/api/mod/robots') { mod(); need(B.number && RANKS.includes(B.rank), 'Number and rank required'); const rb = mkRobot(B); save(); return send(res, 200, { id: rb.id }); }
  if (m === 'PUT' && (r = p.match(/^\/api\/mod\/robots\/(\d+)$/))) { mod(); const rb = db.robots[r[1]]; need(rb, 'No such robot'); const keep = rb.image; Object.assign(rb, { number: +B.number, name: B.name || '', rank: RANKS.includes(B.rank) ? B.rank : rb.rank, epa: +B.epa || 0, dp: +B.dp || 0, capacity: +B.capacity || 0, location: B.location || '', rookie: +B.rookie || 0, traits: (B.traits || []).filter(t => TRAITS.includes(t)), image: B.image === undefined ? keep : B.image }); save(); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/mod/events') { mod(); need(B.name && B.startAt, 'Name and start time required'); const type = ['district', 'dcmp'].includes(B.type) ? B.type : 'district'; need(DIVS.includes(B.division), 'Pick a division');
    const e = { id: id(), name: String(B.name).slice(0, 80), type, division: B.division, seasonId: season().id, startAt: +B.startAt, status: 'scheduled', maxTeams: type === 'dcmp' ? 35 : 28, qualRounds: 12, thirdRound: type === 'dcmp', entries: [] }; db.events[e.id] = e; save(); return send(res, 200, { id: e.id }); }
  if (m === 'POST' && (r = p.match(/^\/api\/mod\/events\/(\d+)\/start$/))) { mod(); const ev = db.events[r[1]]; need(ev && ev.status === 'scheduled', 'Cannot start'); ev.startAt = now(); save(); return send(res, 200, {}); }
  if (m === 'POST' && (r = p.match(/^\/api\/mod\/events\/(\d+)\/close$/))) { mod(); const ev = db.events[r[1]]; need(ev, 'No such event'); need(!['complete', 'cancelled'].includes(ev.status), 'Event already finished'); ev.status = 'cancelled'; save(); return send(res, 200, {}); }
  if (m === 'DELETE' && (r = p.match(/^\/api\/mod\/events\/(\d+)$/))) { mod(); const ev = db.events[r[1]]; need(ev, 'No such event'); need(ev.status === 'scheduled', 'Only scheduled events can be deleted — close live events instead'); delete db.events[ev.id]; save(); return send(res, 200, {}); }
  if (m === 'POST' && (r = p.match(/^\/api\/mod\/events\/(\d+)\/division$/))) { mod(); const ev = db.events[r[1]]; need(ev, 'No such event'); need(ev.status === 'scheduled', 'District can only be changed before the event starts'); need(DIVS.includes(B.division), 'Unknown division'); ev.division = B.division; save(); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/mod/division') { mod(); const u = userByName(B.username || ''); need(u, 'No such player'); need(DIVS.includes(B.division), 'Unknown division'); u.division = B.division; save(); return send(res, 200, { username: u.username, division: u.division }); }
  if (m === 'POST' && p === '/api/mod/grant') { mod(); const u = userByName(B.username || ''); need(u, 'No such player'); u.mod = B.revoke ? false : true; save(); return send(res, 200, {}); }
  if (m === 'POST' && p === '/api/mod/tokens') { mod(); const u = userByName(B.username || ''); need(u, 'No such player');
    const amt = Math.trunc(+B.amount || 0); need(amt !== 0 && Math.abs(amt) <= 1000000, 'Amount must be non-zero, |amount| <= 1000000');
    u.tokens = Math.max(0, (u.tokens || 0) + amt); save(); return send(res, 200, { username: u.username, tokens: u.tokens }); }
  if (m === 'GET' && p === '/api/mod/test-accounts') { mod(); return send(res, 200, Object.values(db.users).filter(u => u.test).map(u => ({ username: u.username, division: u.division, robots: u.inventory.map(i => (db.robots[i] || {}).number) }))); }
  if (m === 'POST' && p === '/api/mod/test-accounts') { mod(); const rbs = Object.values(db.robots); need(rbs.length, 'No robots exist');
    let ev = null, n = Math.min(Math.max(1, +B.count || 1), 100);
    if (B.eventId) { ev = db.events[B.eventId]; need(ev && ev.status === 'scheduled', 'Pick a scheduled event'); // sign up EXISTING test accounts from this event's district, never new ones
      let pool = Object.values(db.users).filter(u => u.test && u.division === ev.division && !ev.entries.some(e => e.uid === u.id));
      if (ev.type === 'dcmp') { const zone = new Set(ranksFor(ev.division).slice(0, 35).map(x => x.uid)); pool = pool.filter(u => zone.has(u.id)); } // district championship: only the top 35 (DCMP zone)
      pool = shuffle(pool);
      n = Math.min(n, ev.maxTeams - ev.entries.length, pool.length); need(n > 0, ev.entries.length >= ev.maxTeams ? 'Event is full' : (ev.type === 'dcmp' ? 'No test accounts left in the DCMP zone (top 35 in district points) of the ' : 'No test accounts left in the ') + ev.division + ' district.' + (ev.type === 'dcmp' ? '' : ' Create some first.'));
      const out = pool.slice(0, n).map(u => { ev.entries.push({ uid: u.id, robotId: u.inventory[0] }); return { username: u.username, password: 'test1234', division: ev.division }; });
      save(); return send(res, 200, { created: out }); }
    else need(!B.division || B.division === 'random' || DIVS.includes(B.division), 'Unknown division');
    const out = []; for (let i = 0; i < n; i++) { const div = ev ? ev.division : DIVS.includes(B.division) ? B.division : pick1(DIVS), u = await mkTest(div, pick1(rbs));
      if (ev) ev.entries.push({ uid: u.id, robotId: u.inventory[0] }); out.push({ username: u.username, password: 'test1234', division: div }); }
    save(); return send(res, 200, { created: out }); }
  if (m === 'DELETE' && p === '/api/mod/test-accounts') { mod(); const list = B.all ? Object.values(db.users).filter(u => u.test) : [userByName(B.username || '')].filter(u => u && u.test); need(list.length, 'No matching test account');
    let deleted = 0, skipped = 0; for (const u of list) { if (await delTest(u)) deleted++; else skipped++; } save(); return send(res, 200, { deleted, skipped }); }
  if (m === 'POST' && p === '/api/mod/season') { mod(); need(B.name && B.game, 'Name and game required'); db.seasons.push(db.season); db.season = { id: db.season.id + 1, name: String(B.name), game: String(B.game) }; save(); return send(res, 200, db.season); }
  if (m === 'POST' && p === '/api/mod/championship') { mod(); const grp = id(), A = [], K = [];
    for (const d of DIVS) { const top = shuffle(ranksFor(d).slice(0, 16).map(x => x.uid)); top.forEach((u, i) => (i < 8 ? A : K).push(u)); }
    const startAt = +B.startAt || now() + 3600000 / S;
    [['Albany Conference', A], ['Kettering Conference', K]].forEach(([nm, list]) => { const last = uid => { const us = db.users[uid]; const h = [...db.history].reverse().find(x => x.uid === uid); return (h && us.inventory.includes(h.robotId) ? h.robotId : us.inventory[0]); };
      const e = { id: id(), name: 'FPP Fantasy ' + nm, type: 'conference', division: 'Championship', seasonId: season().id, startAt, status: 'scheduled', maxTeams: 64, qualRounds: 10, thirdRound: true, cmpGroup: grp, entries: list.map(u => ({ uid: u, robotId: last(u) })) }; db.events[e.id] = e; });
    save(); return send(res, 200, { albany: A.length, kettering: K.length }); }
  throw new HttpErr(404, 'Not found');
}

// ---------- HTTP ----------
const INDEX_HTML = path.join(__dirname, 'index.html');
http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  try {
    await booted;
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if ((req.method === 'GET' || req.method === 'HEAD') && (url.pathname === '/' || url.pathname === '/index.html')) {
      const html = fs.readFileSync(INDEX_HTML);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(req.method === 'HEAD' ? undefined : html);
    }
    res.writeHead(404); res.end('Not found');
  } catch (e) {
    if (res.headersSent) { try { res.end(); } catch (_) {} return; }
    const code = e instanceof HttpErr ? e.code : 500;
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: (e && e.message) || 'Server error' }));
  }
}).listen(PORT, () => console.log('FPP Fantasy listening on http://localhost:' + PORT + (S !== 1 ? ' (time scale ' + S + 'x)' : '')));
