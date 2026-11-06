import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';

const users = new Map();
const sessions = new Map();
const telegramIds = new Map();
const usernames = new Map();
const chats = new Map();      // chatId -> { id, type, name, ownerId, members: Set, isPublic }
const messages = new Map();   // chatId -> [{ id, userId, text, ts }]

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

const USERNAME_RE = /^[a-zA-Z][a-zA-Z0-9_]{4,31}$/;

function publicUser(u) {
  return { id: u.id, username: u.username, name: u.name, bio: u.bio, color: u.color, avatarUrl: u.avatarUrl || null };
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = token && sessions.get(token);
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  next();
}

// ---------- Telegram ----------
app.post('/api/auth/telegram', (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(500).json({ error: 'telegram not configured' });
  const data = req.body || {};
  if (!data.id || !data.hash) return res.status(400).json({ error: 'bad data' });

  const { hash, ...fields } = data;
  const dataCheckString = Object.keys(fields).sort().map(k => `${k}=${fields[k]}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(TELEGRAM_BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hmac !== hash) return res.status(401).json({ error: 'invalid signature' });
  if (Date.now() - Number(fields.auth_date) * 1000 > 24 * 3600 * 1000) return res.status(401).json({ error: 'auth expired' });

  const telegramId = 'tg_' + fields.id;
  let userId = telegramIds.get(telegramId);
  let isNewUser = false;

  if (!userId) {
    isNewUser = true;
    userId = 'u_' + crypto.randomBytes(8).toString('hex');
    users.set(userId, {
      id: userId, telegramId: String(fields.id), telegramUsername: fields.username || null,
      username: null, name: [fields.first_name, fields.last_name].filter(Boolean).join(' ') || fields.username || 'User',
      bio: '', color: '#5288c1', avatarUrl: fields.photo_url || null,
    });
    telegramIds.set(telegramId, userId);
  }

  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, userId);
  res.json({ token, user: publicUser(users.get(userId)), isNewUser: isNewUser || !users.get(userId).username });
});

// ---------- Profile ----------
app.get('/api/me', authMiddleware, (req, res) => res.json({ user: publicUser(users.get(req.userId)) }));

app.post('/api/profile', authMiddleware, (req, res) => {
  const { username, name, bio } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) return res.status(400).json({ error: 'bad name' });
  if ((bio || '').length > 120) return res.status(400).json({ error: 'bio too long' });

  const user = users.get(req.userId);
  if (!user.username) {
    if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'bad username' });
    const lower = username.toLowerCase();
    if (usernames.has(lower)) return res.status(409).json({ error: 'username taken' });
    user.username = username;
    usernames.set(lower, user.id);
  }
  user.name = name.trim();
  user.bio = (bio || '').trim();
  res.json({ user: publicUser(user) });
});

// ---------- Группы и каналы ----------
app.post('/api/chat/create', authMiddleware, (req, res) => {
  const { type, name, isPublic } = req.body || {};
  if (!['group', 'channel'].includes(type)) return res.status(400).json({ error: 'bad type' });
  if (!name || name.trim().length < 2) return res.status(400).json({ error: 'bad name' });

  const chatId = (type === 'group' ? 'g_' : 'c_') + crypto.randomBytes(6).toString('hex');
  const members = new Set([req.userId]);
  
  if (type === 'channel') members.add(req.userId); // админ канала

  chats.set(chatId, {
    id: chatId,
    type,
    name: name.trim(),
    ownerId: req.userId,
    members,
    isPublic: isPublic !== false,
    createdAt: Date.now()
  });
  messages.set(chatId, []);

  res.json({ chat: { id: chatId, type, name: name.trim(), isPublic, ownerId: req.userId } });
});

app.post('/api/chat/join', authMiddleware, (req, res) => {
  const { chatId } = req.body || {};
  const chat = chats.get(chatId);
  if (!chat) return res.status(404).json({ error: 'chat not found' });
  if (!chat.isPublic) return res.status(403).json({ error: 'private chat' });

  chat.members.add(req.userId);
  res.json({ ok: true });
});

app.post('/api/chat/invite', authMiddleware, (req, res) => {
  const { chatId, userId } = req.body || {};
  const chat = chats.get(chatId);
  if (!chat || chat.type !== 'group') return res.status(404).json({ error: 'group not found' });
  if (!chat.members.has(req.userId)) return res.status(403).json({ error: 'not in group' });
  
  const target = users.get(userId);
  if (!target) return res.status(404).json({ error: 'user not found' });

  chat.members.add(userId);
  
  // Системное сообщение о входе
  const entry = { id: crypto.randomBytes(8).toString('hex'), userId: 'system', text: `👤 ${target.name} присоединился к группе`, ts: Date.now(), isSystem: true };
  messages.get(chatId).push(entry);
  broadcastToChat(chatId, { type: 'message', chatId, message: entry, user: { name: 'Система' } });

  res.json({ ok: true });
});

// ---------- Чаты ----------
app.get('/api/chats', authMiddleware, (req, res) => {
  const list = [];
  for (const c of chats.values()) {
    if (!c.members.has(req.userId)) continue;
    const last = messages.get(c.id).slice(-1)[0] || null;
    
    // Для личных переписок подтягиваем инфу о собеседнике
    let memberInfo = null;
    let name = c.name;
    if (c.type === 'dm') {
      for (const mid of c.members) {
        if (mid !== req.userId) {
          const other = users.get(mid);
          if (other) { memberInfo = publicUser(other); name = other.name || other.username; }
        }
      }
    }
    list.push({ id: c.id, type: c.type, name, memberInfo, last, isPublic: c.isPublic, ownerId: c.ownerId });
  }
  list.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));
  res.json({ chats: list });
});

app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const c = chats.get(req.params.id);
  if (!c || !c.members.has(req.userId)) return res.status(403).json({ error: 'forbidden' });
  const raw = messages.get(c.id) || [];
  res.json({ messages: raw.map(m => {
    const u = users.get(m.userId);
    return { id: m.id, userId: m.userId, text: m.text, ts: m.ts, user: u ? publicUser(u) : { name: 'Система' }, isSystem: m.isSystem };
  })});
});

// ---------- Поиск ----------
app.get('/api/search', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const foundUsers = [];
  const foundChats = [];

  for (const u of users.values()) {
    if (u.id === req.userId || !u.username || !u.name) continue;
    if (q && !u.username.toLowerCase().includes(q) && !u.name.toLowerCase().includes(q)) continue;
    foundUsers.push(publicUser(u));
    if (foundUsers.length >= 15) break;
  }

  for (const c of chats.values()) {
    if (c.type === 'dm' || !c.isPublic) continue;
    if (q && !c.name.toLowerCase().includes(q)) continue;
    foundChats.push({ id: c.id, type: c.type, name: c.name, membersCount: c.members.size });
    if (foundChats.length >= 15) break;
  }

  res.json({ users: foundUsers, chats: foundChats });
});

app.post('/api/dialog', authMiddleware, (req, res) => {
  const otherId = req.body && req.body.userId;
  if (!otherId || !users.has(otherId) || otherId === req.userId) return res.status(400).json({ error: 'bad' });
  const ids = [req.userId, otherId].sort();
  const chatId = 'dm_' + ids[0] + '_' + ids[1];
  if (!chats.has(chatId)) {
    chats.set(chatId, { id: chatId, type: 'dm', members: new Set([req.userId, otherId]) });
    messages.set(chatId, []);
  }
  const other = users.get(otherId);
  res.json({ chat: { id: chatId, type: 'dm', memberInfo: publicUser(other) } });
});

// ---------- WS ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Map();

function send(ws, p) { if (ws.readyState === 1) ws.send(JSON.stringify(p)); }
function sendToUser(userId, p) {
  for (const [ws, ctx] of clients) if (ctx.userId === userId && ws.readyState === 1) ws.send(JSON.stringify(p));
}
function broadcastToChat(chatId, p) {
  const data = JSON.stringify(p);
  for (const [ws, ctx] of clients) if (ctx.chatId === chatId && ws.readyState === 1) ws.send(data);
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
      clients.set(ws, { userId, chatId: msg.chatId || null });
      send(ws, { type: 'authed', userId });
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
      
      // Права: в канале писать могут только ownerId
      if (c.type === 'channel' && c.ownerId !== ctx.userId) return;

      const text = String(msg.text || '').slice(0, 4000).trim();
      if (!text) return;
      const entry = { id: crypto.randomBytes(8).toString('hex'), userId: ctx.userId, text, ts: Date.now() };
      messages.get(c.id).push(entry);
      if (messages.get(c.id).length > 1000) messages.get(c.id).shift();
      const u = users.get(ctx.userId);
      
      broadcastToChat(c.id, { type: 'message', chatId: c.id, message: entry, user: publicUser(u) });
      return;
    }

    // --- Звонки (только для DM) ---
    if (msg.type === 'call_offer') {
      const { chatId, toUserId, callType, sdp } = msg;
      const c = chats.get(chatId);
      if (!c || !c.members.has(ctx.userId) || c.type !== 'dm') return;
      const callId = crypto.randomBytes(8).toString('hex');
      activeCalls.set(callId, { fromUserId: ctx.userId, toUserId, chatId, type: callType });
      const u = users.get(ctx.userId);
      sendToUser(toUserId, { type: 'call_incoming', callId, chatId, fromUser: publicUser(u), callType, sdp });
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
  ws.on('close', () => clients.delete(ws));
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { ws.terminate(); continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);

server.listen(PORT, () => console.log(`ЗахаркаГрам server on :${PORT}`));
