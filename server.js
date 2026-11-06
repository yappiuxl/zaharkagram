import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const DB_FILE = path.join(__dirname, 'data.json');

// ---------- БАЗА ДАННЫХ В ФАЙЛЕ ----------
let db = { users: {}, sessions: {}, chats: {}, chat_members: {}, messages: {} };

// Загрузка при старте
if (fs.existsSync(DB_FILE)) {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    console.log('Database loaded from file');
  } catch (e) {
    console.error('Failed to load DB, starting fresh');
  }
}

// Сохранение в файл (с задержкой в 1 сек, чтобы не спамить диск)
let saveTimeout = null;
function saveDB() {
  clearTimeout(saveTimeout);
  saveTimeout = setTimeout(() => {
    fs.writeFileSync(DB_FILE, JSON.stringify(db), 'utf8');
  }, 1000);
}

const app = express();
app.use(express.json({ limit: '10mb' }));
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
  if (!u) return null;
  return { id: u.id, username: u.username, name: u.name, bio: u.bio, color: u.color, avatarUrl: u.avatarUrl };
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const userId = db.sessions[token];
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  req.userId = userId;
  next();
}

// ---------- AUTH ----------
app.post('/api/auth/telegram', (req, res) => {
  if (!TELEGRAM_BOT_TOKEN) return res.status(500).json({ error: 'telegram not configured' });
  const data = req.body || {};
  if (!data.id || !data.hash) return res.status(400).json({ error: 'bad data' });

  const { hash, ...fields } = data;
  const dataCheckString = Object.keys(fields).sort().map(k => `${k}=${fields[k]}`).join('\n');
  const secretKey = crypto.createHash('sha256').update(TELEGRAM_BOT_TOKEN).digest();
  const hmac = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

  if (hmac !== hash) return res.status(401).json({ error: 'invalid signature' });
  
  const tid = 'tg_' + fields.id;
  let user = Object.values(db.users).find(u => u.telegramId === tid);
  let isNewUser = false;

  if (!user) {
    isNewUser = true;
    const userId = 'u_' + crypto.randomBytes(8).toString('hex');
    const name = [fields.first_name, fields.last_name].filter(Boolean).join(' ') || fields.username || 'User';
    db.users[userId] = { id: userId, telegramId: tid, username: null, name, bio: '', color: '#5288c1', avatarUrl: fields.photo_url || null };
    user = db.users[userId];
    saveDB();
  }

  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = user.id;
  saveDB();
  
  res.json({ token, user: publicUser(user), isNewUser: isNewUser || !user.username });
});

// ---------- PROFILE ----------
app.get('/api/me', authMiddleware, (req, res) => res.json({ user: publicUser(db.users[req.userId]) }));

app.post('/api/profile', authMiddleware, (req, res) => {
  const { username, name, bio } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2) return res.status(400).json({ error: 'bad name' });

  const user = db.users[req.userId];
  if (!user.username) {
    if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'bad username' });
    const taken = Object.values(db.users).find(u => u.username && u.username.toLowerCase() === username.toLowerCase());
    if (taken) return res.status(409).json({ error: 'username taken' });
    user.username = username;
  }
  user.name = name.trim();
  user.bio = (bio || '').trim();
  saveDB();
  res.json({ user: publicUser(user) });
});

// ---------- CHATS ----------
app.post('/api/chat/create', authMiddleware, (req, res) => {
  const { type, name, isPublic } = req.body || {};
  if (!['group', 'channel'].includes(type) || !name) return res.status(400).json({ error: 'bad' });

  const chatId = (type === 'group' ? 'g_' : 'c_') + crypto.randomBytes(6).toString('hex');
  db.chats[chatId] = { id: chatId, type, name: name.trim(), ownerId: req.userId, isPublic: isPublic !== false };
  db.chat_members[chatId] = [req.userId];
  db.messages[chatId] = [];
  saveDB();
  res.json({ chat: db.chats[chatId] });
});

app.post('/api/chat/join', authMiddleware, (req, res) => {
  const { chatId } = req.body || {};
  if (!db.chats[chatId] || !db.chats[chatId].isPublic) return res.status(404).json({ error: 'not found' });
  if (!db.chat_members[chatId].includes(req.userId)) {
    db.chat_members[chatId].push(req.userId);
    saveDB();
  }
  res.json({ ok: true });
});

app.post('/api/chat/invite', authMiddleware, (req, res) => {
  const { chatId, userId } = req.body || {};
  if (!db.chats[chatId] || db.chats[chatId].type !== 'group') return res.status(404).json({ error: 'not found' });
  
  if (!db.chat_members[chatId].includes(req.userId)) return res.status(403).json({ error: 'forbidden' });
  const target = db.users[userId];
  if (!target) return res.status(404).json({ error: 'user not found' });

  if (!db.chat_members[chatId].includes(userId)) {
    db.chat_members[chatId].push(userId);
    const entry = { id: crypto.randomBytes(8).toString('hex'), userId: 'system', text: `👤 ${target.name} присоединился к группе`, ts: Date.now(), isSystem: true };
    db.messages[chatId].push(entry);
    broadcastToChat(chatId, { type: 'message', chatId, message: entry, user: { name: 'Система' } });
    saveDB();
  }
  res.json({ ok: true });
});

app.get('/api/chats', authMiddleware, (req, res) => {
  const list = [];
  for (const chatId in db.chats) {
    if (!db.chat_members[chatId] || !db.chat_members[chatId].includes(req.userId)) continue;
    const c = db.chats[chatId];
    const msgs = db.messages[chatId] || [];
    const last = msgs.length > 0 ? msgs[msgs.length - 1] : null;

    let memberInfo = null; let name = c.name;
    if (c.type === 'dm') {
      const otherId = db.chat_members[chatId].find(id => id !== req.userId);
      if (otherId && db.users[otherId]) { memberInfo = publicUser(db.users[otherId]); name = memberInfo.name; }
    }
    list.push({ id: chatId, type: c.type, name, memberInfo, last, isPublic: c.isPublic, ownerId: c.ownerId });
  }
  list.sort((a, b) => (b.last?.ts || 0) - (a.last?.ts || 0));
  res.json({ chats: list });
});

app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  if (!db.chat_members[req.params.id]?.includes(req.userId)) return res.status(403).json({ error: 'forbidden' });
  const msgs = (db.messages[req.params.id] || []).map(m => {
    const u = m.userId !== 'system' ? db.users[m.userId] : null;
    return { ...m, user: u ? publicUser(u) : { name: 'Система' } };
  });
  res.json({ messages: msgs });
});

app.get('/api/search', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().trim();
  const foundUsers = []; const foundChats = [];

  for (const id in db.users) {
    const u = db.users[id];
    if (u.id === req.userId || !u.username) continue;
    if (q && !u.username.toLowerCase().includes(q) && !(u.name||'').toLowerCase().includes(q)) continue;
    foundUsers.push(publicUser(u)); if (foundUsers.length >= 15) break;
  }
  for (const id in db.chats) {
    const c = db.chats[id];
    if (c.type === 'dm' || !c.isPublic || (q && !c.name.toLowerCase().includes(q))) continue;
    foundChats.push({ id: c.id, type: c.type, name: c.name, membersCount: (db.chat_members[c.id] || []).length }); 
    if (foundChats.length >= 15) break;
  }
  res.json({ users: foundUsers, chats: foundChats });
});

app.post('/api/dialog', authMiddleware, (req, res) => {
  const { userId } = req.body || {};
  if (!userId || !db.users[userId]) return res.status(400).json({ error: 'bad' });
  const ids = [req.userId, userId].sort();
  const chatId = 'dm_' + ids[0] + '_' + ids[1];
  
  if (!db.chats[chatId]) {
    db.chats[chatId] = { id: chatId, type: 'dm', ownerId: req.userId, isPublic: false };
    db.chat_members[chatId] = [req.userId, userId];
    db.messages[chatId] = [];
    saveDB();
  }
  res.json({ chat: { id: chatId, type: 'dm', memberInfo: publicUser(db.users[userId]) } });
});

// ---------- WS ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 15 * 1024 * 1024 });
const clients = new Map();

function send(ws, p) { if (ws.readyState === 1) ws.send(JSON.stringify(p)); }
function sendToUser(userId, p) {
  for (const [ws, ctx] of clients) if (ctx.userId === userId && ws.readyState === 1) ws.send(JSON.stringify(p));
}
function broadcastToChat(chatId, p) {
  const data = JSON.stringify(p);
  for (const [ws, ctx] of clients) if (ctx.chatId === chatId && ws.readyState === 1) ws.send(data);
}

wss.on('connection', (ws) => {
  ws.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (msg.type === 'auth') {
      const userId = db.sessions[msg.token];
      if (!userId) { ws.close(4001); return; }
      clients.set(ws, { userId, chatId: msg.chatId || null });
      send(ws, { type: 'authed', userId });
      return;
    }

    const ctx = clients.get(ws); if (!ctx) return;

    if (msg.type === 'switch_chat') {
      if (db.chat_members[msg.chatId]?.includes(ctx.userId)) { ctx.chatId = msg.chatId; send(ws, { type: 'chat_switched', chatId: msg.chatId }); }
      return;
    }

    if (msg.type === 'message') {
      const c = db.chats[ctx.chatId];
      if (!c || !db.chat_members[c.id].includes(ctx.userId)) return;
      if (c.type === 'channel' && c.ownerId !== ctx.userId) return;

      const text = String(msg.text || '').slice(0, 4000).trim();
      if (!text && !msg.media && !msg.poll) return;

      const entry = { id: crypto.randomBytes(8).toString('hex'), userId: ctx.userId, text, ts: Date.now(), media: msg.media || null, poll: msg.poll || null, reactions: {} };
      db.messages[c.id].push(entry);
      if (db.messages[c.id].length > 100) db.messages[c.id].shift(); // Лимит памяти

      const u = db.users[ctx.userId];
      broadcastToChat(c.id, { type: 'message', chatId: c.id, message: entry, user: publicUser(u) });
      saveDB();
      return;
    }

    if (msg.type === 'react') {
      const msgs = db.messages[ctx.chatId] || [];
      const m = msgs.find(x => x.id === msg.msgId); if (!m) return;
      
      m.reactions = m.reactions || {};
      const emoji = msg.emoji;
      if (!m.reactions[emoji]) m.reactions[emoji] = [];
      
      const idx = m.reactions[emoji].indexOf(ctx.userId);
      if (idx >= 0) m.reactions[emoji].splice(idx, 1); else m.reactions[emoji].push(ctx.userId);
      if (m.reactions[emoji].length === 0) delete m.reactions[emoji];

      broadcastToChat(ctx.chatId, { type: 'update_msg', chatId: ctx.chatId, message: m });
      saveDB();
      return;
    }

    if (msg.type === 'vote') {
      const msgs = db.messages[ctx.chatId] || [];
      const m = msgs.find(x => x.id === msg.msgId); if (!m || !m.poll) return;
      
      m.poll.votes = m.poll.votes || {};
      m.poll.votes[ctx.userId] = msg.optionIndex;
      broadcastToChat(ctx.chatId, { type: 'update_msg', chatId: ctx.chatId, message: m });
      saveDB();
      return;
    }
  });
  ws.on('close', () => clients.delete(ws));
});

server.listen(PORT, () => console.log(`Server on :${PORT}`));
