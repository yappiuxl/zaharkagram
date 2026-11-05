import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;

const users = new Map();       // userId -> { id, email, username, name, bio, color, passHash, salt }
const sessions = new Map();    // token -> userId
const emails = new Map();      // email.toLowerCase() -> userId
const usernames = new Map();   // username.toLowerCase() -> userId
const chats = new Map();
const messages = new Map();

const GLOBAL_CHAT = 'global';
chats.set(GLOBAL_CHAT, { id: GLOBAL_CHAT, name: 'Общий чат', members: new Set() });
messages.set(GLOBAL_CHAT, []);

const app = express();
app.use(express.json({ limit: '64kb' }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(express.static(__dirname, { extensions: ['html'] }));

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + ':' + password).digest('hex');
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z][a-zA-Z0-9_]{4,31}$/;

function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, bio: u.bio, color: u.color };
}

function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  next();
}

// ---------- регистрация по email ----------
app.post('/api/auth/register', (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || !EMAIL_RE.test(email.trim())) {
    return res.status(400).json({ error: 'bad email' });
  }
  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({ error: 'short password' });
  }

  const lowerEmail = email.trim().toLowerCase();
  if (emails.has(lowerEmail)) return res.status(409).json({ error: 'email taken' });

  const salt = crypto.randomBytes(16).toString('hex');
  const userId = 'u_' + crypto.randomBytes(8).toString('hex');
  const user = {
    id: userId,
    email: email.trim(),
    username: null,
    name: null,
    bio: '',
    color: '#5288c1',
    salt,
    passHash: hashPassword(password, salt),
  };

  users.set(userId, user);
  emails.set(lowerEmail, userId);

  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  res.json({ token, user: publicUser(user), isNewUser: true });
});

// ---------- вход по email ----------
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'bad request' });
  }
  const userId = emails.get(email.trim().toLowerCase());
  if (!userId) return res.status(401).json({ error: 'invalid credentials' });

  const user = users.get(userId);
  if (hashPassword(password, user.salt) !== user.passHash) {
    return res.status(401).json({ error: 'invalid credentials' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  res.json({ token, user: publicUser(user), isNewUser: !user.username });
});

// ---------- профиль ----------
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: publicUser(users.get(req.userId)) });
});

// ---------- онбординг: username + name + bio ----------
app.post('/api/profile', authMiddleware, (req, res) => {
  const { username, name, bio } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'bad name' });
  }
  if (bio != null && typeof bio !== 'string') return res.status(400).json({ error: 'bad bio' });
  if ((bio || '').length > 120) return res.status(400).json({ error: 'bio too long' });

  const user = users.get(req.userId);
  if (!user) return res.status(404).json({ error: 'no user' });

  // юзернейм задаётся один раз
  if (!user.username) {
    if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'bad username' });
    }
    const lower = username.toLowerCase();
    if (usernames.has(lower)) return res.status(409).json({ error: 'username taken' });
    user.username = username;
    usernames.set(lower, user.id);
  }

  user.name = name.trim();
  user.bio = (bio || '').trim();

  const g = chats.get(GLOBAL_CHAT);
  if (!g.members.has(user.id)) g.members.add(user.id);

  res.json({ user: publicUser(user) });
});

// ---------- чаты ----------
app.get('/api/chats', authMiddleware, (req, res) => {
  const list = [];
  for (const c of chats.values()) {
    if (!c.members.has(req.userId)) continue;
    const last = messages.get(c.id).slice(-1)[0] || null;
    let name = c.name || null;
    let memberInfo = null;

    if (c.isDM) {
      for (const mid of c.members) {
        if (mid !== req.userId) {
          const other = users.get(mid);
          if (other) {
            memberInfo = publicUser(other);
            name = other.name || other.username;
          }
        }
      }
    }

    list.push({
      id: c.id, name, nameKey: c.nameKey || null,
      isDM: !!c.isDM, memberInfo, last,
    });
  }
  res.json({ chats: list });
});

app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const c = chats.get(req.params.id);
  if (!c || !c.members.has(req.userId)) return res.status(403).json({ error: 'forbidden' });
  const raw = messages.get(c.id) || [];
  res.json({
    messages: raw.map(m => {
      const u = users.get(m.userId);
      return { id: m.id, userId: m.userId, text: m.text, ts: m.ts, user: u ? publicUser(u) : null };
    }),
  });
});

app.get('/api/users', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const out = [];
  for (const u of users.values()) {
    if (u.id === req.userId) continue;
    if (!u.username || !u.name) continue;
    if (q && !u.username.toLowerCase().includes(q) && !u.name.toLowerCase().includes(q)) continue;
    out.push(publicUser(u));
    if (out.length >= 30) break;
  }
  res.json({ users: out });
});

app.post('/api/dialog', authMiddleware, (req, res) => {
  const otherId = req.body && req.body.userId;
  if (!otherId || !users.has(otherId)) return res.status(400).json({ error: 'no user' });
  if (otherId === req.userId) return res.status(400).json({ error: 'self dialog' });

  const ids = [req.userId, otherId].sort();
  const chatId = 'dm_' + ids[0] + '_' + ids[1];
  if (!chats.has(chatId)) {
    chats.set(chatId, { id: chatId, members: new Set([req.userId, otherId]), isDM: true });
    messages.set(chatId, []);
  }
  const other = users.get(otherId);
  res.json({ chat: { id: chatId, isDM: true, memberInfo: publicUser(other) } });
});

// ---------- WS ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Map();

function send(ws, packet) { if (ws.readyState === 1) ws.send(JSON.stringify(packet)); }
function sendToUser(userId, packet) {
  for (const [ws, ctx] of clients) {
    if (ctx.userId === userId && ws.readyState === 1) ws.send(JSON.stringify(packet));
  }
}
function broadcastToChat(chatId, packet) {
  const data = JSON.stringify(packet);
  for (const [ws, ctx] of clients) {
    if (ctx.chatId === chatId && ws.readyState === 1) ws.send(data);
  }
}

const activeCalls = new Map();

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const userId = sessions.get(msg.token);
      if (!userId) { ws.close(4001, 'unauthorized'); return; }
      const chatId = msg.chatId && chats.has(msg.chatId) && chats.get(msg.chatId).members.has(userId)
        ? msg.chatId : GLOBAL_CHAT;
      clients.set(ws, { userId, chatId });
      send(ws, { type: 'authed', userId, chatId });
      return;
    }

    const ctx = clients.get(ws);
    if (!ctx) return;

    if (msg.type === 'switch_chat') {
      const c = chats.get(msg.chatId);
      if (c && c.members.has(ctx.userId)) {
        ctx.chatId = msg.chatId;
        send(ws, { type: 'chat_switched', chatId: msg.chatId });
      }
      return;
    }

    if (msg.type === 'message') {
      const c = chats.get(ctx.chatId);
      if (!c || !c.members.has(ctx.userId)) return;
      const text = String(msg.text || '').slice(0, 4000).trim();
      if (!text) return;

      const entry = { id: crypto.randomBytes(8).toString('hex'), userId: ctx.userId, text, ts: Date.now() };
      messages.get(c.id).push(entry);
      if (messages.get(c.id).length > 1000) messages.get(c.id).shift();

      const u = users.get(ctx.userId);
      broadcastToChat(c.id, { type: 'message', chatId: c.id, message: entry, user: publicUser(u) });
      return;
    }

    if (msg.type === 'call_offer') {
      const { chatId, toUserId, callType, sdp } = msg;
      const c = chats.get(chatId);
      if (!c || !c.members.has(ctx.userId)) return;
      const callId = crypto.randomBytes(8).toString('hex');
      activeCalls.set(callId, { fromUserId: ctx.userId, toUserId, chatId, type: callType === 'video' ? 'video' : 'audio' });
      const u = users.get(ctx.userId);
      sendToUser(toUserId, { type: 'call_incoming', callId, chatId, fromUser: publicUser(u), callType: activeCalls.get(callId).type, sdp });
      send(ws, { type: 'call_ringing', callId });
      return;
    }

    if (msg.type === 'call_answer') {
      const call = activeCalls.get(msg.callId);
      if (!call || call.toUserId !== ctx.userId) return;
      if (msg.accepted) sendToUser(call.fromUserId, { type: 'call_accepted', callId: msg.callId, sdp: msg.sdp });
      else { sendToUser(call.fromUserId, { type: 'call_rejected', callId: msg.callId }); activeCalls.delete(msg.callId); }
      return;
    }

    if (msg.type === 'call_ice') {
      const call = activeCalls.get(msg.callId);
      if (!call) return;
      const other = call.fromUserId === ctx.userId ? call.toUserId : call.fromUserId;
      sendToUser(other, { type: 'call_ice', callId: msg.callId, candidate: msg.candidate });
      return;
    }

    if (msg.type === 'call_end') {
      const call = activeCalls.get(msg.callId);
      if (!call) return;
      const other = call.fromUserId === ctx.userId ? call.toUserId : call.fromUserId;
      sendToUser(other, { type: 'call_ended', callId: msg.callId });
      activeCalls.delete(msg.callId);
      return;
    }
  });

  ws.on('close', () => {
    const ctx = clients.get(ws);
    clients.delete(ws);
    if (ctx) {
      for (const [callId, call] of activeCalls) {
        if (call.fromUserId === ctx.userId || call.toUserId === ctx.userId) {
          const other = call.fromUserId === ctx.userId ? call.toUserId : call.fromUserId;
          sendToUser(other, { type: 'call_ended', callId, reason: 'disconnect' });
          activeCalls.delete(callId);
        }
      }
    }
  });
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);

server.listen(PORT, () => console.log(`ЗахаркаГрам server on :${PORT}`));
