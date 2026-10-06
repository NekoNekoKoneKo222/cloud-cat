'use strict';
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Server } = require('socket.io');

const app = express(); const server = http.createServer(app); const io = new Server(server, { maxHttpBufferSize: 1024 * 1024 });
const prod = process.env.NODE_ENV === 'production';
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: prod ? { rejectUnauthorized: false } : false });
const adminNames = new Set(String(process.env.ADMIN_USERS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean));
const uploads = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 }, fileFilter: (_req, file, cb) => cb(null, ['image/png','image/jpeg','image/webp','image/gif'].includes(file.mimetype)) });

if (prod) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'", 'wss:'],
  objectSrc: ["'none'"], baseUri: ["'self'"],
} } }));
app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
const sm = session({ store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'development-only-change-me', name: 'cloudcat.sid',
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 7 * 24 * 60 * 60 * 1000 } });
app.use(sm); io.engine.use(sm);
app.use((req, res, next) => {
  if (['POST','PATCH','PUT','DELETE'].includes(req.method)) {
    const origin = req.get('origin');
    if ((prod && !origin) || (origin && origin !== `${req.protocol}://${req.get('host')}`) || req.get('sec-fetch-site') === 'cross-site') return res.status(403).json({ error: 'Originが一致しません' });
  }
  res.set('Cache-Control', 'no-store'); next();
});
app.use(express.static(path.join(__dirname, 'public')));

const q = (sql, params = []) => pool.query(sql, params);
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const validId = value => /^\d+$/.test(String(value)) && Number(value) > 0 ? Number(value) : null;
const text = (value, max) => typeof value === 'string' ? value.trim().slice(0, max) : '';
const userView = row => ({ id: row.id, username: row.username, displayName: row.display_name, bio: row.bio, avatarUrl: row.avatar_url, isAdmin: adminNames.has(row.username) });
const attempts=new Map();
function authLimit(req,res,next){const now=Date.now(),key=req.ip,entry=attempts.get(key)||{count:0,until:now+15*60*1000};if(now>entry.until){entry.count=0;entry.until=now+15*60*1000;}entry.count++;attempts.set(key,entry);if(entry.count>20)return res.status(429).json({error:'試行回数が多すぎます'});next();}
const auth = wrap(async (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: 'ログインが必要です' });
  const result = await q('SELECT id,username,display_name,bio,avatar_url,banned_at FROM users WHERE id=$1', [req.session.userId]);
  if (!result.rowCount || result.rows[0].banned_at) return res.status(403).json({ error: 'アカウントを利用できません' });
  req.user = result.rows[0]; next();
});
const adminOnly = (req, res, next) => adminNames.has(req.user.username) ? next() : res.status(403).json({ error: '管理者権限が必要です' });
const adminLog = (user, action, targetUser, targetRoom, details = {}) => q('INSERT INTO admin_logs(admin_user,action,target_user,target_room,details) VALUES($1,$2,$3,$4,$5)', [user, action, targetUser, targetRoom, JSON.stringify(details)]);
const notify = async (userId, title, content = '') => { await q('INSERT INTO notifications(user_id,title,content) VALUES($1,$2,$3)', [userId,title,content]); io.to('user:' + userId).emit('notification'); };
const imageMime = (buffer, mime) => {
  const h = buffer.subarray(0, 12).toString('hex');
  return (mime === 'image/png' && h.startsWith('89504e470d0a1a0a')) ||
    (mime === 'image/jpeg' && h.startsWith('ffd8ff')) ||
    (mime === 'image/gif' && (buffer.toString('ascii',0,6) === 'GIF87a' || buffer.toString('ascii',0,6) === 'GIF89a')) ||
    (mime === 'image/webp' && buffer.toString('ascii',0,4) === 'RIFF' && buffer.toString('ascii',8,12) === 'WEBP');
};
async function canDm(userId, roomId) { return (await q('SELECT 1 FROM dm_members WHERE room_id=$1 AND user_id=$2',[roomId,userId])).rowCount > 0; }
async function ownsUpload(userId,url){const id=validId(String(url).split('/').pop());return id && (await q('SELECT 1 FROM uploads WHERE id=$1 AND owner_id=$2',[id,userId])).rowCount>0;}
async function roomRole(user, roomId) {
  if (adminNames.has(user.username)) return 'admin';
  const result = await q('SELECT role FROM room_members WHERE room_id=$1 AND user_id=$2',[roomId,user.id]);
  return result.rows[0]?.role || null;
}
async function requireRoom(req,res,next) { const id=validId(req.params.id); if (!id || !(await roomRole(req.user,id))) return res.status(403).json({error:'ルームに参加していません'}); req.roomId=id; next(); }
async function requireManager(req,res,next) { const id=validId(req.params.id); const role=id && await roomRole(req.user,id); if (!['admin','owner','manager'].includes(role)) return res.status(403).json({error:'管理権限が必要です'}); req.roomId=id; next(); }

app.get('/healthz', wrap(async (_req,res) => { await q('SELECT 1'); res.json({ok:true,service:'cloud-cat'}); }));
app.post('/api/auth/signup',authLimit, wrap(async (req,res) => {
  const username=text(req.body.username,32).toLowerCase(), display=text(req.body.displayName,64)||username, password=String(req.body.password||'');
  if (!/^[a-z0-9_]{3,32}$/.test(username) || adminNames.has(username) || password.length < 8 || password.length > 128 || req.body.acceptTerms !== true) return res.status(400).json({error:'入力内容または利用規約への同意を確認してください'});
  const hash=await bcrypt.hash(password,12);
  try { const result=await q('INSERT INTO users(username,display_name,password_hash,terms_accepted_at) VALUES($1,$2,$3,NOW()) RETURNING *',[username,display,hash]);
    req.session.regenerate(err => { if(err) return res.status(500).json({error:'セッションを作成できません'}); req.session.userId=result.rows[0].id; res.status(201).json({user:userView(result.rows[0])}); });
  } catch(err) { if(err.code==='23505') return res.status(409).json({error:'ユーザー名は使用済みです'}); throw err; }
}));
app.post('/api/auth/login',authLimit, wrap(async (req,res) => {
  const username=text(req.body.username,32).toLowerCase(); const result=await q('SELECT * FROM users WHERE username=$1',[username]);
  if(!result.rowCount || !(await bcrypt.compare(String(req.body.password||''),result.rows[0].password_hash))) return res.status(401).json({error:'ログイン情報が違います'});
  if(result.rows[0].banned_at) return res.status(403).json({error:'アカウントを利用できません'});
  req.session.regenerate(err => { if(err) return res.status(500).json({error:'セッションを作成できません'}); req.session.userId=result.rows[0].id; res.json({user:userView(result.rows[0])}); });
}));
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>{res.clearCookie('cloudcat.sid');res.json({ok:true});}));
app.get('/api/me',auth,(req,res)=>res.json(userView(req.user)));
app.patch('/api/me',auth,wrap(async(req,res)=>{ const display=text(req.body.displayName,64), bio=text(req.body.bio,500);
  if(!display) return res.status(400).json({error:'表示名が必要です'});
  const result=await q('UPDATE users SET display_name=$1,bio=$2 WHERE id=$3 RETURNING *',[display,bio,req.user.id]); res.json(userView(result.rows[0])); }));
app.patch('/api/me/username',auth,wrap(async(req,res)=>{ const name=text(req.body.username,32).toLowerCase();
  if(!/^[a-z0-9_]{3,32}$/.test(name) || adminNames.has(name)) return res.status(400).json({error:'ユーザー名が不正です'});
  try { const result=await q('UPDATE users SET username=$1 WHERE id=$2 RETURNING *',[name,req.user.id]); res.json(userView(result.rows[0])); }
  catch(err) { if(err.code==='23505') return res.status(409).json({error:'ユーザー名は使用済みです'}); throw err; } }));
app.patch('/api/me/password',auth,wrap(async(req,res)=>{ const current=String(req.body.currentPassword||''), next=String(req.body.newPassword||'');
  if(next.length<8||next.length>128) return res.status(400).json({error:'パスワードは8〜128文字です'});
  const result=await q('SELECT password_hash FROM users WHERE id=$1',[req.user.id]);
  if(!(await bcrypt.compare(current,result.rows[0].password_hash))) return res.status(403).json({error:'現在のパスワードが違います'});
  await q('UPDATE users SET password_hash=$1 WHERE id=$2',[await bcrypt.hash(next,12),req.user.id]); res.json({ok:true}); }));
app.post('/api/uploads',auth,uploads.single('image'),wrap(async(req,res)=>{ if(!req.file||!imageMime(req.file.buffer,req.file.mimetype)) return res.status(400).json({error:'画像形式が不正です'});
  const result=await q('INSERT INTO uploads(owner_id,mime,bytes) VALUES($1,$2,$3) RETURNING id',[req.user.id,req.file.mimetype,req.file.buffer]); res.status(201).json({url:'/api/uploads/'+result.rows[0].id}); }));
app.get('/api/uploads/:id',auth,wrap(async(req,res)=>{const id=validId(req.params.id); if(!id)return res.status(404).end();const url='/api/uploads/'+id;
  const allowed=await q(`SELECT 1 FROM uploads u WHERE u.id=$1 AND (u.owner_id=$2 OR EXISTS(SELECT 1 FROM users WHERE avatar_url=$3) OR EXISTS(SELECT 1 FROM messages m JOIN dm_members d ON d.room_id=m.room_id WHERE m.image_url=$3 AND d.user_id=$2) OR EXISTS(SELECT 1 FROM room_messages m JOIN room_members r ON r.room_id=m.room_id WHERE m.image_url=$3 AND r.user_id=$2))`,[id,req.user.id,url]);
  if(!allowed.rowCount)return res.status(404).end();const result=await q('SELECT mime,bytes FROM uploads WHERE id=$1',[id]);res.set({'X-Content-Type-Options':'nosniff','Cache-Control':'private,max-age=3600'}).type(result.rows[0].mime).send(result.rows[0].bytes);}));
app.patch('/api/me/avatar',auth,wrap(async(req,res)=>{const url=text(req.body.url,100);if(url&&!/^\/api\/uploads\/\d+$/.test(url))return res.status(400).json({error:'画像URLが不正です'});await q('UPDATE users SET avatar_url=$1 WHERE id=$2',[url||null,req.user.id]);res.json({ok:true});}));

app.get('/api/users',auth,wrap(async(req,res)=>{const pattern='%'+text(req.query.q,60)+'%';const result=await q('SELECT id,username,display_name,bio,avatar_url FROM users WHERE id<>$1 AND banned_at IS NULL AND (username ILIKE $2 OR display_name ILIKE $2) ORDER BY username LIMIT 30',[req.user.id,pattern]);res.json(result.rows.map(userView));}));
app.get('/api/friends',auth,wrap(async(req,res)=>{const result=await q(`SELECT f.id,f.status,f.requester_id,f.addressee_id,u.id AS user_id,u.username,u.display_name,u.avatar_url FROM friendships f JOIN users u ON u.id=CASE WHEN f.requester_id=$1 THEN f.addressee_id ELSE f.requester_id END WHERE f.requester_id=$1 OR f.addressee_id=$1 ORDER BY f.id DESC`,[req.user.id]);res.json(result.rows);}));
app.post('/api/friends',auth,wrap(async(req,res)=>{const other=validId(req.body.userId);if(!other||other===Number(req.user.id))return res.status(400).json({error:'相手が不正です'});
  const existing=await q('SELECT id FROM friendships WHERE (requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1)',[req.user.id,other]);
  if(existing.rowCount)return res.status(409).json({error:'申請は既にあります'});
  const found=await q('SELECT 1 FROM users WHERE id=$1 AND banned_at IS NULL',[other]);if(!found.rowCount)return res.status(404).json({error:'ユーザーがいません'});
  const result=await q('INSERT INTO friendships(requester_id,addressee_id) VALUES($1,$2) RETURNING id',[req.user.id,other]);await notify(other,'フレンド申請',req.user.username+'から申請が届きました');res.status(201).json(result.rows[0]);}));
app.post('/api/friends/:id/accept',auth,wrap(async(req,res)=>{const result=await q("UPDATE friendships SET status='accepted' WHERE id=$1 AND addressee_id=$2 AND status='pending' RETURNING requester_id",[validId(req.params.id),req.user.id]);if(!result.rowCount)return res.status(404).json({error:'申請がありません'});await notify(result.rows[0].requester_id,'フレンド承認',req.user.username+'が承認しました');res.json({ok:true});}));
app.post('/api/friends/:id/reject',auth,wrap(async(req,res)=>{const result=await q("DELETE FROM friendships WHERE id=$1 AND addressee_id=$2 AND status='pending' RETURNING id",[validId(req.params.id),req.user.id]);res.status(result.rowCount?200:404).json(result.rowCount?{ok:true}:{error:'申請がありません'});}));
app.delete('/api/friends/:id',auth,wrap(async(req,res)=>{const result=await q('DELETE FROM friendships WHERE id=$1 AND (requester_id=$2 OR addressee_id=$2) RETURNING id',[validId(req.params.id),req.user.id]);res.status(result.rowCount?200:404).json(result.rowCount?{ok:true}:{error:'フレンドがいません'});}));

app.get('/api/notifications',auth,wrap(async(req,res)=>{const result=await q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[req.user.id]);res.json(result.rows);}));
app.post('/api/notifications/read',auth,wrap(async(req,res)=>{await q('UPDATE notifications SET is_read=TRUE WHERE user_id=$1',[req.user.id]);res.json({ok:true});}));

app.get('/api/dm',auth,wrap(async(req,res)=>{const result=await q(`SELECT r.id,u.id AS user_id,u.username,u.display_name,u.avatar_url FROM dm_rooms r JOIN dm_members a ON a.room_id=r.id AND a.user_id=$1 JOIN dm_members b ON b.room_id=r.id AND b.user_id<>$1 JOIN users u ON u.id=b.user_id ORDER BY r.id DESC`,[req.user.id]);res.json(result.rows);}));
app.post('/api/dm',auth,wrap(async(req,res)=>{const other=validId(req.body.userId);if(!other||other===Number(req.user.id))return res.status(400).json({error:'相手が不正です'});
  const friends=await q("SELECT 1 FROM friendships WHERE status='accepted' AND ((requester_id=$1 AND addressee_id=$2) OR (requester_id=$2 AND addressee_id=$1))",[req.user.id,other]);if(!friends.rowCount)return res.status(403).json({error:'フレンドのみDMを利用できます'});
  const existing=await q('SELECT r.id FROM dm_rooms r JOIN dm_members a ON a.room_id=r.id AND a.user_id=$1 JOIN dm_members b ON b.room_id=r.id AND b.user_id=$2 WHERE (SELECT COUNT(*) FROM dm_members WHERE room_id=r.id)=2 LIMIT 1',[req.user.id,other]);if(existing.rowCount)return res.json({roomId:existing.rows[0].id});
  const client=await pool.connect();try{await client.query('BEGIN');const room=await client.query('INSERT INTO dm_rooms DEFAULT VALUES RETURNING id');await client.query('INSERT INTO dm_members(room_id,user_id) VALUES($1,$2),($1,$3)',[room.rows[0].id,req.user.id,other]);await client.query('COMMIT');res.status(201).json({roomId:room.rows[0].id});}catch(err){await client.query('ROLLBACK');throw err;}finally{client.release();}
}));
app.get('/api/dm/:id/messages',auth,wrap(async(req,res)=>{const id=validId(req.params.id);if(!id||!(await canDm(req.user.id,id)))return res.status(403).json({error:'アクセスできません'});const result=await q('SELECT m.*,u.username FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE room_id=$1 ORDER BY created_at DESC LIMIT 100',[id]);res.json(result.rows.reverse());}));
app.post('/api/dm/:id/messages',auth,wrap(async(req,res)=>{const id=validId(req.params.id),content=text(req.body.content,4000),image=text(req.body.imageUrl,100),reply=validId(req.body.replyTo);if(!id||!(await canDm(req.user.id,id)))return res.status(403).json({error:'アクセスできません'});
  if(!content&&!image)return res.status(400).json({error:'空のメッセージです'});if(image&&(!/^\/api\/uploads\/\d+$/.test(image)||!(await ownsUpload(req.user.id,image))))return res.status(400).json({error:'画像URLが不正です'});
  if(reply && !(await q('SELECT 1 FROM messages WHERE id=$1 AND room_id=$2',[reply,id])).rowCount)return res.status(400).json({error:'返信先が不正です'});
  const result=await q('INSERT INTO messages(room_id,sender_id,content,image_url,reply_to) VALUES($1,$2,$3,$4,$5) RETURNING *',[id,req.user.id,content,image||null,reply]);
  const members=await q('SELECT user_id FROM dm_members WHERE room_id=$1',[id]);for(const m of members.rows){io.to('user:'+m.user_id).emit('dm:message',result.rows[0]);if(Number(m.user_id)!==Number(req.user.id))await notify(m.user_id,'DM',req.user.username+'からメッセージ');}
  res.status(201).json(result.rows[0]);}));
app.delete('/api/dm/:id/messages/:messageId',auth,wrap(async(req,res)=>{const id=validId(req.params.id);if(!id||!(await canDm(req.user.id,id)))return res.status(403).json({error:'アクセスできません'});const result=await q("UPDATE messages SET content='',image_url=NULL,deleted_at=NOW() WHERE id=$1 AND room_id=$2 AND sender_id=$3 AND deleted_at IS NULL RETURNING id",[validId(req.params.messageId),id,req.user.id]);res.status(result.rowCount?200:404).json(result.rowCount?{ok:true}:{error:'メッセージがありません'});}));
app.post('/api/dm/:id/messages/:messageId/reactions',auth,wrap(async(req,res)=>{const id=validId(req.params.id),message=validId(req.params.messageId),symbol=text(req.body.symbol,16);if(!id||!(await canDm(req.user.id,id)))return res.status(403).json({error:'アクセスできません'});if(!message||!symbol||symbol.length>8)return res.status(400).json({error:'リアクションが不正です'});const exists=await q('SELECT 1 FROM messages WHERE id=$1 AND room_id=$2',[message,id]);if(!exists.rowCount)return res.status(404).json({error:'メッセージがありません'});await q('INSERT INTO reactions(message_id,user_id,symbol) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[message,req.user.id,symbol]);res.json({ok:true});}));

app.get('/api/rooms',auth,wrap(async(req,res)=>{const result=await q(`SELECT r.id,r.name,r.is_private,r.owner_id,EXISTS(SELECT 1 FROM room_members m WHERE m.room_id=r.id AND m.user_id=$1) AS joined FROM rooms r WHERE NOT r.is_private OR EXISTS(SELECT 1 FROM room_members m WHERE m.room_id=r.id AND m.user_id=$1) OR $2 ORDER BY r.created_at DESC LIMIT 100`,[req.user.id,adminNames.has(req.user.username)]);res.json(result.rows);}));
app.post('/api/rooms',auth,wrap(async(req,res)=>{const name=text(req.body.name,100),privateRoom=req.body.isPrivate===true,code=text(req.body.code,80);
  if(!name||privateRoom&&code&&code.length<6)return res.status(400).json({error:'ルーム名または参加コードが不正です'});
  const hash=code?await bcrypt.hash(code,12):null;const client=await pool.connect();try{await client.query('BEGIN');const room=await client.query('INSERT INTO rooms(name,owner_id,is_private,code_hash) VALUES($1,$2,$3,$4) RETURNING id,name,is_private',[name,req.user.id,privateRoom,hash]);await client.query("INSERT INTO room_members(room_id,user_id,role) VALUES($1,$2,'owner')",[room.rows[0].id,req.user.id]);await client.query('COMMIT');res.status(201).json(room.rows[0]);}catch(err){await client.query('ROLLBACK');throw err;}finally{client.release();}
}));
app.post('/api/rooms/:id/join',auth,wrap(async(req,res)=>{const id=validId(req.params.id);if(!id)return res.status(400).json({error:'ルームIDが不正です'});const result=await q('SELECT is_private,code_hash FROM rooms WHERE id=$1',[id]);if(!result.rowCount)return res.status(404).json({error:'ルームがありません'});
  if((await q('SELECT 1 FROM room_bans WHERE room_id=$1 AND user_id=$2',[id,req.user.id])).rowCount && !adminNames.has(req.user.username))return res.status(403).json({error:'参加できません'});
  if(result.rows[0].is_private && result.rows[0].code_hash && !(await bcrypt.compare(String(req.body.code||''),result.rows[0].code_hash)) && !adminNames.has(req.user.username))return res.status(403).json({error:'参加コードが違います'});
  if(result.rows[0].is_private && !result.rows[0].code_hash && !adminNames.has(req.user.username))return res.status(403).json({error:'招待されたユーザーのみ参加できます'});
  await q("INSERT INTO room_members(room_id,user_id,role) VALUES($1,$2,'member') ON CONFLICT DO NOTHING",[id,req.user.id]);res.json({ok:true});}));
app.get('/api/rooms/:id/messages',auth,wrap(requireRoom),wrap(async(req,res)=>{const result=await q('SELECT m.*,u.username FROM room_messages m LEFT JOIN users u ON u.id=m.sender_id WHERE room_id=$1 ORDER BY created_at DESC LIMIT 100',[req.roomId]);res.json(result.rows.reverse());}));
app.post('/api/rooms/:id/messages',auth,wrap(requireRoom),wrap(async(req,res)=>{const content=text(req.body.content,4000),image=text(req.body.imageUrl,100),reply=validId(req.body.replyTo);if(!content&&!image)return res.status(400).json({error:'空のメッセージです'});if(image&&(!/^\/api\/uploads\/\d+$/.test(image)||!(await ownsUpload(req.user.id,image))))return res.status(400).json({error:'画像URLが不正です'});if(reply && !(await q('SELECT 1 FROM room_messages WHERE id=$1 AND room_id=$2',[reply,req.roomId])).rowCount)return res.status(400).json({error:'返信先が不正です'});
  const result=await q('INSERT INTO room_messages(room_id,sender_id,content,image_url,reply_to) VALUES($1,$2,$3,$4,$5) RETURNING *',[req.roomId,req.user.id,content,image||null,reply]);await q('INSERT INTO chat_logs(room_id,user_id,username,message,action) VALUES($1,$2,$3,$4,$5)',[req.roomId,req.user.id,req.user.username,content,'message']);io.to('room:'+req.roomId).emit('room:message',result.rows[0]);res.status(201).json(result.rows[0]);}));
app.delete('/api/rooms/:id/messages/:messageId',auth,wrap(requireRoom),wrap(async(req,res)=>{const mid=validId(req.params.messageId),role=await roomRole(req.user,req.roomId);const result=await q("UPDATE room_messages SET content='',image_url=NULL,deleted_at=NOW() WHERE id=$1 AND room_id=$2 AND deleted_at IS NULL AND (sender_id=$3 OR $4) RETURNING sender_id",[mid,req.roomId,req.user.id,['admin','owner','manager'].includes(role)]);if(!result.rowCount)return res.status(404).json({error:'メッセージがありません'});await q('INSERT INTO chat_logs(room_id,user_id,username,action) VALUES($1,$2,$3,$4)',[req.roomId,req.user.id,req.user.username,'delete_message']);res.json({ok:true});}));
app.post('/api/rooms/:id/kick',auth,wrap(requireManager),wrap(async(req,res)=>{const target=validId(req.body.userId);if(!target)return res.status(400).json({error:'ユーザーIDが不正です'});const row=await q('SELECT username FROM users WHERE id=$1',[target]);if(!row.rowCount||adminNames.has(row.rows[0].username))return res.status(403).json({error:'管理者をKickできません'});const result=await q("DELETE FROM room_members WHERE room_id=$1 AND user_id=$2 AND role='member' RETURNING user_id",[req.roomId,target]);if(!result.rowCount)return res.status(404).json({error:'メンバーがいません'});io.to('user:'+target).emit('room:kicked',{roomId:req.roomId});io.in('user:'+target).socketsLeave('room:'+req.roomId);await adminLog(req.user.username,'room_kick',target,req.roomId);res.json({ok:true});}));
app.post('/api/rooms/:id/ban',auth,wrap(requireManager),wrap(async(req,res)=>{const target=validId(req.body.userId);if(!target)return res.status(400).json({error:'ユーザーIDが不正です'});const row=await q('SELECT u.username,m.role FROM users u LEFT JOIN room_members m ON m.user_id=u.id AND m.room_id=$2 WHERE u.id=$1',[target,req.roomId]);if(!row.rowCount||adminNames.has(row.rows[0].username)||row.rows[0].role==='owner'||row.rows[0].role==='manager')return res.status(403).json({error:'このユーザーをBANできません'});await q('INSERT INTO room_bans(room_id,user_id,banned_by) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[req.roomId,target,req.user.id]);await q("DELETE FROM room_members WHERE room_id=$1 AND user_id=$2 AND role='member'",[req.roomId,target]);io.to('user:'+target).emit('room:banned',{roomId:req.roomId});io.in('user:'+target).socketsLeave('room:'+req.roomId);await adminLog(req.user.username,'room_ban',target,req.roomId);res.json({ok:true});}));
app.delete('/api/rooms/:id/ban/:userId',auth,wrap(requireManager),wrap(async(req,res)=>{const target=validId(req.params.userId);await q('DELETE FROM room_bans WHERE room_id=$1 AND user_id=$2',[req.roomId,target]);await adminLog(req.user.username,'room_unban',target,req.roomId);res.json({ok:true});}));
app.delete('/api/rooms/:id',auth,wrap(requireManager),wrap(async(req,res)=>{await q('DELETE FROM rooms WHERE id=$1',[req.roomId]);await adminLog(req.user.username,'room_delete',null,req.roomId);res.json({ok:true});}));

app.get('/api/admin/users',auth,adminOnly,wrap(async(req,res)=>{const result=await q('SELECT id,username,display_name,banned_at,created_at FROM users ORDER BY id DESC LIMIT 200');res.json(result.rows);}));
app.post('/api/admin/users/:id/ban',auth,adminOnly,wrap(async(req,res)=>{const target=validId(req.params.id);const row=await q('SELECT username FROM users WHERE id=$1',[target]);if(!row.rowCount||adminNames.has(row.rows[0].username))return res.status(403).json({error:'管理者をBANできません'});await q('UPDATE users SET banned_at=NOW() WHERE id=$1',[target]);io.in('user:'+target).disconnectSockets(true);await adminLog(req.user.username,'user_ban',target,null);res.json({ok:true});}));
app.delete('/api/admin/users/:id/ban',auth,adminOnly,wrap(async(req,res)=>{const target=validId(req.params.id);await q('UPDATE users SET banned_at=NULL WHERE id=$1',[target]);await adminLog(req.user.username,'user_unban',target,null);res.json({ok:true});}));
app.get('/api/admin/rooms',auth,adminOnly,wrap(async(req,res)=>{const result=await q('SELECT id,name,is_private,owner_id,created_at FROM rooms ORDER BY id DESC LIMIT 200');res.json(result.rows);}));
app.get('/api/admin/logs',auth,adminOnly,wrap(async(req,res)=>{const result=await q('SELECT * FROM admin_logs ORDER BY timestamp DESC LIMIT 200');res.json(result.rows);}));
app.use('/api',(_req,res)=>res.status(404).json({error:'APIがありません'}));
app.get('*',(_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,_req,res,_next)=>{console.error('[cloud-cat]',err);if(res.headersSent)return;res.status(err instanceof multer.MulterError?400:500).json({error:err instanceof multer.MulterError?'アップロードが不正です':'サーバーエラー'});});
io.on('connection',async socket=>{const userId=socket.request.session?.userId;if(!userId)return socket.disconnect(true);try{const user=await q('SELECT banned_at FROM users WHERE id=$1',[userId]);if(!user.rowCount||user.rows[0].banned_at)return socket.disconnect(true);}catch{return socket.disconnect(true);}socket.join('user:'+userId);
  socket.on('room:join',async(id,ack)=>{try{const room=validId(id);const row=await q('SELECT 1 FROM room_members WHERE room_id=$1 AND user_id=$2',[room,userId]);if(!row.rowCount)return ack?.({ok:false});socket.join('room:'+room);ack?.({ok:true});}catch{ack?.({ok:false});}});
});
async function start(){if(!process.env.DATABASE_URL||!process.env.SESSION_SECRET)throw new Error('DATABASE_URL と SESSION_SECRET が必要です');await q(fs.readFileSync(path.join(__dirname,'schema.sql'),'utf8'));return server.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Cloud Cat ready'));}
if(require.main===module)start().catch(err=>{console.error(err.message);process.exit(1);});
module.exports={app,start,validId,text,imageMime};
