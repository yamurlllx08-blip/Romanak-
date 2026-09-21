import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import nodemailer from "nodemailer";
import {Pool} from "pg";
import dotenv from "dotenv";
import {z} from "zod";
import path from "node:path";
import {fileURLToPath} from "node:url";

dotenv.config();
const app=express();
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const PORT=Number(process.env.PORT||8080);
const JWT_SECRET=process.env.JWT_SECRET;
if(!JWT_SECRET) throw new Error("JWT_SECRET is required");

app.use(helmet({contentSecurityPolicy:false}));
app.use(cors({origin:true,credentials:false}));
app.use(express.json({limit:"1mb"}));
app.use(rateLimit({windowMs:15*60*1000,max:300,standardHeaders:true,legacyHeaders:false}));

const __dirname=path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.join(__dirname,"../../web")));

function token(user){return jwt.sign({sub:user.id,role:user.role,email:user.email},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){try{const h=req.headers.authorization||"";if(!h.startsWith("Bearer ")) throw 0;req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{res.status(401).json({error:"AUTH_REQUIRED"})}}
function admin(req,res,next){if(req.user?.role!=="admin") return res.status(403).json({error:"ADMIN_ONLY"});next()}
function rawToken(){return crypto.randomBytes(32).toString("hex")}
function hash(v){return crypto.createHash("sha256").update(v).digest("hex")}

const transporter=process.env.SMTP_HOST?nodemailer.createTransport({
 host:process.env.SMTP_HOST,port:Number(process.env.SMTP_PORT||587),
 secure:String(process.env.SMTP_SECURE)==="true",
 auth:{user:process.env.SMTP_USER,pass:process.env.SMTP_PASS}
}):null;

async function mail(to,subject,html){
 if(!transporter) { console.warn("SMTP not configured; email:",to,subject); return; }
 await transporter.sendMail({from:process.env.MAIL_FROM,to,subject,html});
}

async function db(q,p=[]){return pool.query(q,p)}

app.get("/api/health",async(_,res)=>{try{await db("select 1");res.json({ok:true})}catch{res.status(500).json({ok:false})}});

const registerSchema=z.object({name:z.string().min(2).max(80),email:z.string().email(),password:z.string().min(8).max(100)});
app.post("/api/auth/register",async(req,res)=>{
 try{
  const x=registerSchema.parse(req.body), email=x.email.toLowerCase();
  const exists=await db("select id from users where email=$1",[email]);
  if(exists.rowCount) return res.status(409).json({error:"EMAIL_EXISTS"});
  const ph=await bcrypt.hash(x.password,12);
  const u=(await db("insert into users(name,email,password_hash) values($1,$2,$3) returning id,name,email,role",[x.name,email,ph])).rows[0];
  const raw=rawToken(); await db("insert into email_verifications(user_id,token_hash,expires_at) values($1,$2,now()+interval '30 minutes')",[u.id,hash(raw)]);
  const url=`${process.env.PUBLIC_WEB_URL||"http://localhost:8080"}/?verify=${raw}`;
  await mail(email,"تأیید ایمیل رمانک",`<h2>به رمانک خوش آمدی</h2><p>برای تأیید ایمیل روی این لینک بزن:</p><p><a href="${url}">${url}</a></p>`);
  res.json({message:"REGISTERED",user:u,token:token(u),emailVerificationRequired:true});
 }catch(e){res.status(400).json({error:"INVALID_DATA",detail:e.message})}
});

app.get("/api/auth/verify-email",async(req,res)=>{
 try{
  const raw=String(req.query.token||""); const r=await db("select user_id from email_verifications where token_hash=$1 and expires_at>now()",[hash(raw)]);
  if(!r.rowCount) return res.status(400).json({error:"INVALID_OR_EXPIRED_TOKEN"});
  const u=(await db("update users set email_verified=true where id=$1 returning id,name,email,role",[r.rows[0].user_id])).rows[0];
  await db("delete from email_verifications where token_hash=$1",[hash(raw)]);
  res.json({user:u,token:token(u)});
 }catch{res.status(400).json({error:"VERIFY_FAILED"})}
});

app.post("/api/auth/login",async(req,res)=>{
 try{
  const {email,password}=z.object({email:z.string().email(),password:z.string()}).parse(req.body);
  const r=await db("select * from users where email=$1",[email.toLowerCase()]);
  if(!r.rowCount || !r.rows[0].password_hash || !(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:"INVALID_LOGIN"});
  const u=r.rows[0];res.json({token:token(u),user:{id:u.id,name:u.name,email:u.email,role:u.role,email_verified:u.email_verified}});
 }catch{res.status(400).json({error:"INVALID_DATA"})}
});

app.post("/api/auth/google",async(req,res)=>{
 try{
  const credential=String(req.body.credential||"");
  const r=await fetch("https://oauth2.googleapis.com/tokeninfo?id_token="+encodeURIComponent(credential));
  if(!r.ok) return res.status(401).json({error:"GOOGLE_TOKEN_INVALID"});
  const g=await r.json();
  if(g.aud!==process.env.GOOGLE_CLIENT_ID || g.email_verified!=="true") return res.status(401).json({error:"GOOGLE_TOKEN_NOT_ALLOWED"});  const email=g.email.toLowerCase();
  let q=await db("select * from users where email=$1",[email]);
  let u;
  if(q.rowCount) u=q.rows[0];
  else u=(await db("insert into users(name,email,google_sub,email_verified) values($1,$2,$3,true) returning *",[g.name||g.email.split("@")[0],email,g.sub])).rows[0];
  res.json({token:token(u),user:{id:u.id,name:u.name,email:u.email,role:u.role,email_verified:true}});
 }catch(e){res.status(500).json({error:"GOOGLE_LOGIN_FAILED"})}
});

app.post("/api/auth/forgot-password",async(req,res)=>{
 const email=String(req.body.email||"").toLowerCase();
 const u=(await db("select id,email from users where email=$1",[email])).rows[0];
 if(u){
  const raw=rawToken(); await db("delete from password_resets where user_id=$1",[u.id]);
  await db("insert into password_resets(user_id,token_hash,expires_at) values($1,$2,now()+interval '30 minutes')",[u.id,hash(raw)]);
  const url=`${process.env.PUBLIC_WEB_URL||"http://localhost:8080"}/?reset=${raw}`;
  await mail(email,"بازیابی رمز رمانک",`<p>لینک بازیابی رمز:</p><p><a href="${url}">${url}</a></p>`);
 }
 res.json({message:"IF_ACCOUNT_EXISTS_EMAIL_SENT"});
});

app.post("/api/auth/reset-password",async(req,res)=>{
 const {token:newToken,password}=z.object({token:z.string(),password:z.string().min(8)}).parse(req.body);
 const r=await db("select user_id from password_resets where token_hash=$1 and expires_at>now()",[hash(newToken)]);
 if(!r.rowCount) return res.status(400).json({error:"INVALID_OR_EXPIRED_TOKEN"});
 const ph=await bcrypt.hash(password,12);
 await db("update users set password_hash=$1 where id=$2",[ph,r.rows[0].user_id]);
 await db("delete from password_resets where token_hash=$1",[hash(newToken)]);
 res.json({message:"PASSWORD_CHANGED"});
});
app.get("/api/novels",async(req,res)=>{
 const q=String(req.query.q||"").trim(),status=String(req.query.status||"published");
 const allowed=["published","draft","pending","revision"];
 const st=allowed.includes(status)?status:"published";
 const params=[];let where="n.status=$1";params.push(st);
 if(q){
  params.push("%"+q+"%");
  where+=" and (n.title ilike $"+params.length+" or n.genre ilike $"+params.length+" or u.name ilike $"+params.length+")"
 }
 const r=await db(`select n.id,n.title,n.description,n.genre,n.cover_url,n.status,n.review_note,n.created_at,n.updated_at,u.id author_id,u.name author,
 (select count(*) from chapters c where c.novel_id=n.id) chapter_count,
 (select count(*) from likes l where l.novel_id=n.id) like_count
 from novels n join users u on u.id=n.author_id where ${where} order by n.updated_at desc limit 100`,params);
 res.json(r.rows);
});

app.get("/api/novels/:id",async(req,res)=>{
 const n=(await db(`select n.*,u.name author from novels n join users u on u.id=n.author_id where n.id=$1`,[req.params.id])).rows[0];
 if(!n)return res.status(404).json({error:"NOT_FOUND"});
 const chapters=(await db("select id,chapter_no,title,body,created_at,updated_at from chapters where novel_id=$1 order by chapter_no",[n.id])).rows;
 const comments=(await db(`select c.id,c.body,c.created_at,u.id user_id,u.name from comments c join users u on u.id=c.user_id where c.novel_id=$1 order by c.created_at desc`,[n.id])).rows;
 res.json({novel:n,chapters,comments});
});

app.post("/api/novels",auth,async(req,res)=>{
 const x=z.object({
  title:z.string().min(1).max(160),
  description:z.string().max(5000).optional(),
  genre:z.string().min(1).max(80),
  cover_url:z.string().max(1000).optional()
 }).parse(req.body);
 const n=(await db("insert into novels(author_id,title,description,genre,cover_url) values($1,$2,$3,$4,$5) returning *",[req.user.sub,x.title,x.description||"",x.genre,x.cover_url||""])).rows[0];
 res.status(201).json(n);
});
app.get("/api/mine",auth,async(req,res)=>{
 const r=await db("select * from novels where author_id=$1 order by updated_at desc",[req.user.sub]);
 res.json(r.rows);
});

app.post("/api/novels/:id/chapters",auth,async(req,res)=>{
 const x=z.object({
  chapter_no:z.number().int().positive(),
  title:z.string().min(1).max(200),
  body:z.string().min(1)
 }).parse(req.body);

 const own=await db("select id from novels where id=$1 and author_id=$2",[req.params.id,req.user.sub]);
 if(!own.rowCount)return res.status(403).json({error:"NOT_OWNER"});

 const r=await db(
  `insert into chapters(novel_id,chapter_no,title,body)
   values($1,$2,$3,$4)
   on conflict(novel_id,chapter_no)
   do update set title=excluded.title,body=excluded.body,updated_at=now()
   returning *`,
  [req.params.id,x.chapter_no,x.title,x.body]
 );
 res.status(201).json(r.rows[0]);
});

app.post("/api/novels/:id/submit",auth,async(req,res)=>{
 const own=await db("select id from novels where id=$1 and author_id=$2",[req.params.id,req.user.sub]);
 if(!own.rowCount)return res.status(403).json({error:"NOT_OWNER"});

 const r=await db(
  "update novels set status='pending',updated_at=now() where id=$1 returning *",
  [req.params.id]
 );
 res.json(r.rows[0]);
});

app.get("/api/admin/pending",auth,admin,async(req,res)=>{
 const r=await db(
  `select n.*,u.name author
   from novels n join users u on u.id=n.author_id
   where n.status='pending'
   order by n.updated_at asc`
 );
 res.json(r.rows);
});

app.post("/api/admin/novels/:id/review",auth,admin,async(req,res)=>{
 const x=z.object({
  status:z.enum(["published","revision"]),
  review_note:z.string().max(2000).optional()
 }).parse(req.body);

 const r=await db(
  `update novels
   set status=$1,review_note=$2,updated_at=now(),
       published_at=case when $1='published' then now() else published_at end
   where id=$3
   returning *`,
  [x.status,x.review_note||"",req.params.id]
 );

 if(!r.rowCount)return res.status(404).json({error:"NOT_FOUND"});
 res.json(r.rows[0]);
});
app.post("/api/novels/:id/comments",auth,async(req,res)=>{
 const body=z.string().min(1).max(3000).parse(req.body.body);
 const r=await db("insert into comments(novel_id,user_id,body) values($1,$2,$3) returning *",[req.params.id,req.user.sub,body]);
 res.status(201).json(r.rows[0]);
});

app.post("/api/novels/:id/like",auth,async(req,res)=>{
 const has=await db("select 1 from likes where user_id=$1 and novel_id=$2",[req.user.sub,req.params.id]);
 if(has.rowCount) await db("delete from likes where user_id=$1 and novel_id=$2",[req.user.sub,req.params.id]);
 else await db("insert into likes(user_id,novel_id) values($1,$2)",[req.user.sub,req.params.id]);
 res.json({liked:!has.rowCount});
});

app.post("/api/novels/:id/bookmark",auth,async(req,res)=>{
 const has=await db("select 1 from bookmarks where user_id=$1 and novel_id=$2",[req.user.sub,req.params.id]);
 if(has.rowCount) await db("delete from bookmarks where user_id=$1 and novel_id=$2",[req.user.sub,req.params.id]);
 else await db("insert into bookmarks(user_id,novel_id) values($1,$2)",[req.user.sub,req.params.id]);
 res.json({bookmarked:!has.rowCount});
});

app.get("/api/me",auth,async(req,res)=>{
 const u=(await db("select id,name,email,role,email_verified,avatar_url,bio,created_at from users where id=$1",[req.user.sub])).rows[0];
 res.json(u);
});

app.put("/api/me",auth,async(req,res)=>{
 const x=z.object({
  name:z.string().min(2).max(80),
  bio:z.string().max(2000),
  avatar_url:z.string().max(1000).optional()
 }).parse(req.body);

 const u=(await db(
  "update users set name=$1,bio=$2,avatar_url=$3 where id=$4 returning id,name,email,role,email_verified,avatar_url,bio",
  [x.name,x.bio,x.avatar_url||"",req.user.sub]
 )).rows[0];

 res.json(u);
});

app.use((req,res)=>res.sendFile(path.join(__dirname,"../../web/index.html")));

app.listen(PORT,()=>console.log(`Romanak API listening on :${PORT}`));
