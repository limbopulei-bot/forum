const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const OWNER_IPS = (process.env.OWNER_IPS || "127.0.0.1").split(",").map(x => x.trim());
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "lll3";

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
const dbFile = path.join(dataDir, "db.json");

if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, {recursive:true});
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, {recursive:true});

let db = fs.existsSync(dbFile)
  ? JSON.parse(fs.readFileSync(dbFile, "utf8"))
  : { users: [], messages: [], settings: {notice:""} };

function save(){ fs.writeFileSync(dbFile, JSON.stringify(db, null, 2)); }

app.use(express.json({limit:"2mb"}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const upload = multer({
  dest: uploadDir,
  limits: {fileSize: 25 * 1024 * 1024}
});

const sessions = new Map();

function ip(req){
  return (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "")
    .split(",")[0].trim().replace(/^::ffff:/,"");
}

function broadcast(obj){
  const s = JSON.stringify(obj);
  for(const c of wss.clients) if(c.readyState === WebSocket.OPEN) c.send(s);
}

function auth(req){
  return sessions.get(req.cookies.sid);
}

function ownerIP(req){ return OWNER_IPS.includes(ip(req)); }

function safeUser(u){
  return {id:u.id, username:u.username, role:u.role, banned:u.banned};
}

app.post("/api/register", async (req,res)=>{
  const username=String(req.body.username||"").trim();
  const password=String(req.body.password||"");
  if(!/^[\wÀ-ÿ .-]{2,24}$/u.test(username))
    return res.status(400).json({error:"Nome de usuário inválido."});
  if(password.length<4) return res.status(400).json({error:"Senha muito curta."});
  if(db.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))
    return res.status(409).json({error:"Esse nome já está em uso."});

  const u={
    id:crypto.randomUUID(),
    username,
    password:await bcrypt.hash(password,10),
    role:"user",
    banned:false
  };
  db.users.push(u); save();
  const sid=crypto.randomUUID(); sessions.set(sid,u.id);
  res.cookie("sid",sid,{httpOnly:true,sameSite:"lax"});
  res.json({user:safeUser(u)});
});

app.post("/api/login", async (req,res)=>{
  const username=String(req.body.username||"").trim();
  const password=String(req.body.password||"");
  const u=db.users.find(x=>x.username.toLowerCase()===username.toLowerCase());
  if(!u || !(await bcrypt.compare(password,u.password)))
    return res.status(401).json({error:"Usuário ou senha incorretos."});
  if(u.banned) return res.status(403).json({error:"Você foi banido."});
  const sid=crypto.randomUUID(); sessions.set(sid,u.id);
  res.cookie("sid",sid,{httpOnly:true,sameSite:"lax"});
  res.json({user:safeUser(u)});
});

app.post("/api/logout",(req,res)=>{
  sessions.delete(req.cookies.sid); res.clearCookie("sid"); res.json({ok:true});
});

app.get("/api/me",(req,res)=>{
  const u=auth(req);
  res.json({user:u ? safeUser(db.users.find(x=>x.id===u)) : null});
});

app.get("/api/messages",(req,res)=>{
  const u=auth(req);
  if(!u) return res.status(401).json({error:"login"});
  res.json({
    messages:db.messages.slice(-200),
    notice:db.settings.notice || ""
  });
});

app.post("/api/message",(req,res)=>{
  const uid=auth(req); const u=db.users.find(x=>x.id===uid);
  if(!u) return res.status(401).json({error:"login"});
  if(u.banned) return res.status(403).json({error:"ban"});
  const body=String(req.body.text||"").trim();
  if(!body || body.length>5000) return res.status(400).json({error:"Mensagem inválida."});
  const m={id:crypto.randomUUID(),userId:u.id,username:u.username,text:body,ts:Date.now()};
  db.messages.push(m); db.messages=db.messages.slice(-5000); save();
  broadcast({type:"message",message:m});
  res.json({ok:true});
});

app.post("/api/upload", upload.single("file"), (req,res)=>{
  const uid=auth(req); const u=db.users.find(x=>x.id===uid);
  if(!u) return res.status(401).json({error:"login"});
  if(u.banned) return res.status(403).json({error:"ban"});
  if(!req.file) return res.status(400).json({error:"arquivo"});
  const ext=path.extname(req.file.originalname).toLowerCase();
  const allowed=[".jpg",".jpeg",".png",".gif",".webp",".pdf",".mp3",".wav",".ogg",".m4a"];
  if(!allowed.includes(ext)){ fs.unlinkSync(req.file.path); return res.status(400).json({error:"tipo não permitido"}); }
  const finalName=req.file.filename+ext;
  fs.renameSync(req.file.path,path.join(uploadDir,finalName));
  const m={
    id:crypto.randomUUID(),userId:u.id,username:u.username,
    file:{name:req.file.originalname,url:"/uploads/"+finalName,type:req.file.mimetype},
    ts:Date.now()
  };
  db.messages.push(m); db.messages=db.messages.slice(-5000); save();
  broadcast({type:"message",message:m});
  res.json({ok:true});
});

app.use("/uploads", express.static(uploadDir));

function moderator(u){ return u && ["moderator","admin","owner"].includes(u.role); }

app.post("/api/admin/login",(req,res)=>{
  if(!ownerIP(req)) return res.status(403).json({error:"Acesso negado."});
  if(String(req.body.password||"")!==ADMIN_PASSWORD)
    return res.status(401).json({error:"Senha incorreta."});
  const sid=crypto.randomUUID();
  sessions.set("admin:"+sid,{owner:true,ip:ip(req)});
  res.cookie("admin_sid",sid,{httpOnly:true,sameSite:"strict"});
  res.json({ok:true});
});

function adminAuth(req){
  const x=sessions.get("admin:"+req.cookies.admin_sid);
  return x && x.owner && ownerIP(req);
}

app.get("/api/admin/status",(req,res)=>res.json({ok:!!adminAuth(req)}));

app.get("/api/admin/users",(req,res)=>{
  if(!adminAuth(req)) return res.status(403).json({error:"negado"});
  res.json({users:db.users.map(safeUser)});
});

app.post("/api/admin/action",(req,res)=>{
  if(!adminAuth(req)) return res.status(403).json({error:"negado"});
  const {action,userId,role}=req.body;
  const u=db.users.find(x=>x.id===userId);
  if(["ban","unban","kick","role"].includes(action) && !u)
    return res.status(404).json({error:"usuário"});
  if(action==="ban") u.banned=true;
  if(action==="unban") u.banned=false;
  if(action==="role"){
    if(!["user","moderator","admin"].includes(role)) return res.status(400).json({error:"cargo"});
    u.role=role;
  }
  if(action==="kick"){
    for(const [sid,id] of sessions) if(id===u.id) sessions.delete(sid);
  }
  save(); broadcast({type:"adminUpdate"});
  res.json({ok:true});
});

app.post("/api/admin/notice",(req,res)=>{
  if(!adminAuth(req)) return res.status(403).json({error:"negado"});
  db.settings.notice=String(req.body.text||"").slice(0,500);
  save(); broadcast({type:"notice",text:db.settings.notice});
  res.json({ok:true});
});

app.post("/api/admin/redirect",(req,res)=>{
  if(!adminAuth(req)) return res.status(403).json({error:"negado"});
  const url=String(req.body.url||"").trim();
  if(!/^https?:\/\//i.test(url)) return res.status(400).json({error:"URL deve começar com http:// ou https://"});
  broadcast({type:"redirect",url});
  res.json({ok:true});
});

wss.on("connection", ws=>{ ws.send(JSON.stringify({type:"connected"})); });

server.listen(PORT,()=>console.log(`Servidor: http://localhost:${PORT}`));
