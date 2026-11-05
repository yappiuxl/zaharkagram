import express from 'express';
import { WebSocketServer } from 'ws';
import { OAuth2Client } from 'google-auth-library';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = process.env.PORT || 3000;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// ---------- in-memory хранилище ----------
const users = new Map();       // userId -> { id, name, username, bio, email, picture, color }
const sessions = new Map();    // token -> userId
const usernames = new Map();   // username.toLowerCase() -> userId
const chats = new Map();       // chatId -> { id, nameKey?, name?, members:Set<userId> }
const messages = new Map();    // chatId -> [{ id, userId, text, ts }]

const GLOBAL_CHAT = 'global';
chats.set(GLOBAL_CHAT, { id: GLOBAL_CHAT, name: 'Общий чат', members: new Set() });
messages.set(GLOBAL_CHAT, []);

// ---------- express ----------
const app = express();
app.use(express.json({ limit: '64kb' }));

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// статика
app.use(express.static(__dirname, { extensions: ['html'] }));

// ---------- auth ----------
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  req.token = token;
  next();
}

// верификация Google id_token
app.post('/api/auth/google', async (req, res) => {
  const { credential } = req.body || {};
  if (!credential) return res.status(400).json({ error: 'no credential' });
  if (!GOOGLE_CLIENT_ID) return res.status(500).json({ error: 'google client id not configured' });

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID,
    });
    const p = ticket.getPayload();
    const googleId = p.sub;

    let user = users.get(googleId);
    let isNewUser = false;
    if (!user) {
      isNewUser = true;
      user = {
        id: googleId,
        email: p.email || null,
        picture: p.picture || null,
        name: null,
        username: null,
        bio: '',
        color: '#5288c1',
      };
      users.set(googleId, user);
    }

    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, googleId);

    res.json({ token, user, isNewUser });
  } catch (e) {
    console.error('google auth error', e.message);
    res.status(401).json({ error: 'invalid token' });
  }
});

// профиль
app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ user: users.get(req.userId) });
});

// завершение онбординга
app.post('/api/profile', authMiddleware, (req, res) => {
  const { name, username, bio } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) {
    return res.status(400).json({ error: 'bad name' });
  }
  if (typeof username !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_]{4,31}$/.test(username)) {
    return res.status(400).json({ error: 'bad username' });
  }
  if (bio != null && typeof bio !== 'string') {
    return res.status(400).json({ error: 'bad bio' });
  }
  if ((bio || '').length > 120) return res.status(400).json({ error: 'bio too long' });

  const user = users.get(req.userId);
  if (!user) return res.status(404).json({ error: 'no user' });

  const lower = username.toLowerCase();
  const owner = usernames.get(lower);
  if (owner && owner !== user.id) return res.status(409).json({ error: 'username taken' });

  if (user.username && user.username.toLowerCase() !== lower) {
    usernames.delete(user.username.toLowerCase());
  }

  user.name = name.trim();
  user.username = username;
  user.bio = (bio || '').trim();
  usernames.set(lower, user.id);

  // добавляем в общий чат
  const g = chats.get(GLOBAL_CHAT);
  if (!g.members.has(user.id)) g.members.add(user.id);

  res.json({ user });
});

// чаты пользователя
app.get('/api/chats', authMiddleware, (req, res) => {
  const list = [];
  for (const c of chats.values()) {
    if (!c.members.has(req.userId)) continue;
    const last = messages.get(c.id).slice(-1)[0] || null;
    list.push({
      id: c.id,
      name: c.name || null,
      nameKey: c.nameKey || null,
      last,
    });
  }
  res.json({ chats: list });
});

// сообщения чата
app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const c = chats.get(req.params.id);
  if (!c || !c.members.has(req.userId)) return res.status(403).json({ error: 'forbidden' });
  res.json({ messages: messages.get(c.id) || [] });
});

// список пользователей (простой, для теста)
app.get('/api/users', authMiddleware, (req, res) => {
  const out = [];
  for (const u of users.values()) {
    if (!u.username) continue;
    out.push({ id: u.id, name: u.name, username: u.username, bio: u.bio, color: u.color });
  }
  res.json({ users: out });
});

// ---------- ws ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Map(); // ws -> { userId, chatId }

function broadcastToChat(chatId, packet) {
  const data = JSON.stringify(packet);
  for (const [ws, ctx] of clients) {
    if (ctx.chatId === chatId && ws.readyState === 1) ws.send(data);
  }
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const userId = sessions.get(msg.token);
      if (!userId) { ws.close(4001, 'unauthorized'); return; }
      const chatId = msg.chatId && chats.has(msg.chatId) && chats.get(msg.chatId).members.has(userId)
        ? msg.chatId : GLOBAL_CHAT;
      clients.set(ws, { userId, chatId });
      ws.send(JSON.stringify({ type: 'authed', userId, chatId }));
      return;
    }

    const ctx = clients.get(ws);
    if (!ctx) return;

    if (msg.type === 'switch_chat') {
      const c = chats.get(msg.chatId);
      if (c && c.members.has(ctx.userId)) {
        ctx.chatId = msg.chatId;
        ws.send(JSON.stringify({ type: 'chat_switched', chatId: msg.chatId }));
      }
      return;
    }

    if (msg.type === 'message') {
      const c = chats.get(ctx.chatId);
      if (!c || !c.members.has(ctx.userId)) return;
      const text = String(msg.text || '').slice(0, 4000).trim();
      if (!text) return;

      const entry = {
        id: crypto.randomBytes(8).toString('hex'),
        userId: ctx.userId,
        text,
        ts: Date.now(),
      };
      messages.get(c.id).push(entry);
      if (messages.get(c.id).length > 1000) messages.get(c.id).shift();

      const u = users.get(ctx.userId);
      broadcastToChat(c.id, {
        type: 'message',
        chatId: c.id,
        message: entry,
        user: { id: u.id, name: u.name, username: u.username, color: u.color },
      });
    }
  });

  ws.on('close', () => clients.delete(ws));
});

// ping/pong
setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);

server.listen(PORT, () => {
  console.log(`ЗахаркаГрам server on :${PORT}`);
});