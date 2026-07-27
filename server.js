require('dotenv').config();
const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const db = new Database(path.join(__dirname, 'linknest.db'));
const secret = process.env.JWT_SECRET || 'change-this-secret-before-production';
db.pragma('foreign_keys = ON');
db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL COLLATE NOCASE, password_hash TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, color TEXT DEFAULT '#c8f04b', UNIQUE(user_id,name));
CREATE TABLE IF NOT EXISTS links (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, url TEXT NOT NULL, icon TEXT DEFAULT '↗', group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL, starred INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS link_shares (link_id INTEGER REFERENCES links(id) ON DELETE CASCADE, user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(link_id,user_id));`);
app.use(express.json()); app.use(express.static(__dirname));
const tokenFor = u => jwt.sign({id:u.id, username:u.username}, secret, {expiresIn:'14d'});
function auth(req,res,next){const t=req.headers.authorization?.replace('Bearer ','');try{req.user=jwt.verify(t,secret);next()}catch{res.status(401).json({error:'Требуется авторизация'})}}
const getUser = id => db.prepare('SELECT id, username FROM users WHERE id=?').get(id);
app.post('/api/auth/register', (req,res)=>{const {username,password}=req.body;if(!/^[\w.-]{3,30}$/u.test(username||''))return res.status(400).json({error:'Имя: от 3 символов, буквы, цифры, . или -'});if(!password||password.length<4)return res.status(400).json({error:'Пароль должен быть не короче 4 символов'});try{const r=db.prepare('INSERT INTO users(username,password_hash) VALUES (?,?)').run(username.trim(),bcrypt.hashSync(password,12));const u=getUser(r.lastInsertRowid);res.json({token:tokenFor(u),user:u})}catch(e){res.status(409).json({error:'Это имя уже занято'})}});
app.post('/api/auth/login',(req,res)=>{const u=db.prepare('SELECT * FROM users WHERE username=?').get((req.body.username||'').trim());if(!u||!bcrypt.compareSync(req.body.password||'',u.password_hash))return res.status(401).json({error:'Неверное имя или пароль'});res.json({token:tokenFor(u),user:{id:u.id,username:u.username}})});
app.get('/api/me',auth,(req,res)=>res.json({user:getUser(req.user.id)}));
app.get('/api/groups',auth,(req,res)=>res.json(db.prepare('SELECT g.*,COUNT(l.id) as count FROM groups g LEFT JOIN links l ON l.group_id=g.id WHERE g.user_id=? GROUP BY g.id ORDER BY g.id DESC').all(req.user.id)));
app.post('/api/groups',auth,(req,res)=>{const name=(req.body.name||'').trim();if(!name)return res.status(400).json({error:'Введите название'});try{const r=db.prepare('INSERT INTO groups(user_id,name,color) VALUES(?,?,?)').run(req.user.id,name,req.body.color||'#c8f04b');res.json(db.prepare('SELECT * FROM groups WHERE id=?').get(r.lastInsertRowid))}catch{res.status(409).json({error:'Такая коллекция уже есть'})}});
function linksFor(userId){return db.prepare(`SELECT l.id,l.title,l.url,l.icon,l.starred,l.created_at,g.name group_name,g.id group_id,COUNT(s.user_id) share_count FROM links l LEFT JOIN groups g ON g.id=l.group_id LEFT JOIN link_shares s ON s.link_id=l.id WHERE l.user_id=? GROUP BY l.id ORDER BY l.created_at DESC`).all(userId)}
app.get('/api/links',auth,(req,res)=>res.json(linksFor(req.user.id)));
app.post('/api/links',auth,(req,res)=>{const {title,url,icon,group_id}=req.body;if(!title?.trim()||!url?.trim())return res.status(400).json({error:'Заполните название и ссылку'});let parsed;try{parsed=new URL(url)}catch{return res.status(400).json({error:'Некорректная ссылка'})}if(!['http:','https:'].includes(parsed.protocol))return res.status(400).json({error:'Разрешены только http и https ссылки'});const r=db.prepare('INSERT INTO links(user_id,title,url,icon,group_id) VALUES(?,?,?,?,?)').run(req.user.id,title.trim(),url.trim(),icon||'↗',group_id||null);res.json(linksFor(req.user.id).find(x=>x.id===r.lastInsertRowid))});
app.patch('/api/links/:id',auth,(req,res)=>{const link=db.prepare('SELECT * FROM links WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!link)return res.status(404).json({error:'Ссылка не найдена'});if('starred' in req.body)db.prepare('UPDATE links SET starred=? WHERE id=?').run(req.body.starred?1:0,link.id);res.json({ok:true})});
app.get('/api/links/:id/shares',auth,(req,res)=>{const l=db.prepare('SELECT id FROM links WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!l)return res.status(404).json({error:'Ссылка не найдена'});res.json(db.prepare('SELECT u.username FROM link_shares s JOIN users u ON u.id=s.user_id WHERE s.link_id=?').all(l.id))});
app.post('/api/links/:id/shares',auth,(req,res)=>{const l=db.prepare('SELECT id FROM links WHERE id=? AND user_id=?').get(req.params.id,req.user.id), username=(req.body.username||'').trim();if(!l)return res.status(404).json({error:'Ссылка не найдена'});const target=db.prepare('SELECT id FROM users WHERE username=?').get(username);if(!target)return res.status(404).json({error:'Пользователь не найден'});if(target.id===req.user.id)return res.status(400).json({error:'Это ваша ссылка'});db.prepare('INSERT OR IGNORE INTO link_shares(link_id,user_id) VALUES (?,?)').run(l.id,target.id);res.json({ok:true})});
app.delete('/api/links/:id/shares/:username',auth,(req,res)=>{const l=db.prepare('SELECT id FROM links WHERE id=? AND user_id=?').get(req.params.id,req.user.id);if(!l)return res.status(404).json({error:'Ссылка не найдена'});db.prepare('DELETE FROM link_shares WHERE link_id=? AND user_id=(SELECT id FROM users WHERE username=?)').run(l.id,req.params.username);res.json({ok:true})});
app.get('/api/shared',auth,(req,res)=>res.json(db.prepare(`SELECT l.id,l.title,l.url,l.icon,l.starred,g.name group_name,u.username owner FROM link_shares s JOIN links l ON l.id=s.link_id JOIN users u ON u.id=l.user_id LEFT JOIN groups g ON g.id=l.group_id WHERE s.user_id=? ORDER BY l.created_at DESC`).all(req.user.id)));
app.listen(process.env.PORT||3000,()=>console.log('Linknest running on http://localhost:'+(process.env.PORT||3000)));
