import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "node:crypto";
import { Pool } from "pg";
import dotenv from "dotenv";
import { z } from "zod";
import path from "node:path";
import { fileURLToPath } from "node:url";

dotenv.config();

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const PORT = Number(process.env.PORT || 8080);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is required");
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true }));
app.use(express.json({ limit: "1mb" }));

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.use(express.static(path.join(__dirname, "../../")));

function makeToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      role: user.role,
      email: user.email
    },
    JWT_SECRET,
    { expiresIn
     app.get("/api/auth/verify-email", async (req, res) => {
  try {
    const token = String(req.query.token || "");

    const result = await db(
      `SELECT user_id
       FROM email_verifications
       WHERE token=$1
       AND expires_at>NOW()
       AND used_at IS NULL`,
      [token]
    );

    if (!result.rowCount) {
      return res.status(400).json({
        error: "INVALID_OR_EXPIRED_TOKEN"
      });
    }

    const user = (
      await db(
        `UPDATE users
         SET email_verified=true
         WHERE id=$1
         RETURNING id,name,email,role,email_verified`,
        [result.rows[0].user_id]
      )
    ).rows[0];

    await db(
      `UPDATE email_verifications
       SET used_at=NOW()
       WHERE token=$1`,
      [token]
    );

    res.json({
      message: "EMAIL_VERIFIED",
      user,
      token: makeToken(user)
    });

  } catch (error) {
    res.status(400).json({
      error: "VERIFY_FAILED"
    });
  }
});


app.post("/api/auth/login", async (req, res) => {
  try {
    const data = z.object({
      email: z.string().email(),
      password: z.string()
    }).parse(req.body);

    const result = await db(
      "SELECT * FROM users WHERE email=$1",
      [data.email.toLowerCase()]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "INVALID_LOGIN"
      });
    }

    const user = result.rows[0];

    if (!user.password_hash) {
      return res.status(401).json({
        error: "USE_GOOGLE_LOGIN"
      });
    }

    const valid = await bcrypt.compare(
      data.password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "INVALID_LOGIN"
      });
    }

    res.json({
      message: "LOGIN_SUCCESS",
      token: makeToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        email_verified: user.email_verified
      }
    });

  } catch (error) {
    res.status(400).json({
      error: "INVALID_DATA"
    });
  }
});


app.post("/api/auth/google", async (req, res) => {
  try {
    const credential = String(
      req.body.credential || ""
    );

    if (!credential) {
      return res.status(400).json({
        error: "GOOGLE_CREDENTIAL_REQUIRED"
      });
    }

    const response = await fetch(
      "https://oauth2.googleapis.com/tokeninfo?id_token=" +
      encodeURIComponent(credential)
    );

    if (!response.ok) {
      return res.status(401).json({
        error: "GOOGLE_TOKEN_INVALID"
      });
    }

    const google = await response.json();

    if (
      google.aud !== process.env.GOOGLE_CLIENT_ID ||
      google.email_verified !== "true"
    ) {
      return res.status(401).json({
        error: "GOOGLE_TOKEN_NOT_ALLOWED"
      });
    }

    const email = google.email.toLowerCase();

    let result = await db(
      "SELECT * FROM users WHERE email=$1",
      [email]
    );

    let user;

    if (result.rowCount) {
      user = result.rows[0];

      await db(
        `UPDATE users
         SET google_id=$1,email_verified=true
         WHERE id=$2`,
        [google.sub, user.id]
      );

      user.google_id = google.sub;
      user.email_verified = true;

    } else {
      user = (
        await db(
          `INSERT INTO users
          (id,name,email,role,email_verified,google_id)
          VALUES
          (gen_random_uuid(),$1,$2,'user',true,$3)
          RETURNING *`,
          [
            google.name ||
            google.email.split("@")[0],
            email,
            google.sub
          ]
        )
      ).rows[0];
    }

    res.json({
      message: "GOOGLE_LOGIN_SUCCESS",
      token: makeToken(user),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        email_verified: true
      }
    });

  } catch (error) {
    res.status(500).json({
      error: "GOOGLE_LOGIN_FAILED"
    });
  }
});
 app.get("/api/novels",async(req,res)=>{
try{
const q=String(req.query.q||"").trim(),s=String(req.query.status||"published");
const p=[s];let w="n.status=$1";
if(q){p.push("%"+q+"%");w+=" AND (n.title ILIKE $2 OR n.genre ILIKE $2 OR u.name ILIKE $2)"}
const r=await db(`SELECT n.id,n.title,n.description,n.cover_url,n.genre,n.status,n.created_at,u.id author_id,u.name author
FROM novels n JOIN users u ON u.id=n.author_id WHERE ${w} ORDER BY n.created_at DESC LIMIT 100`,p);
res.json(r.rows)
}catch(e){res.status(500).json({error:"NOVELS_FAILED"})}
});

app.get("/api/novels/:id",async(req,res)=>{
try{
const n=(await db("SELECT n.*,u.name author FROM novels n JOIN users u ON u.id=n.author_id WHERE n.id=$1",[req.params.id])).rows[0];
if(!n)return res.status(404).json({error:"NOT_FOUND"});
const chapters=(await db("SELECT id,part_number,title,content,status,created_at FROM chapters WHERE novel_id=$1 ORDER BY part_number",[n.id])).rows;
const comments=(await db("SELECT c.id,c.content,c.created_at,u.id user_id,u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.novel_id=$1 ORDER BY c.created_at DESC",[n.id])).rows;
res.json({novel:n,chapters,comments})
}catch(e){res.status(500).json({error:"NOVEL_FAILED"})}
});

app.post("/api/novels",auth,async(req,res)=>{
try{
const x=z.object({title:z.string().min(1).max(160),description:z.string().max(5000).optional(),genre:z.string().min(1).max(80),cover_url:z.string().max(1000).optional()}).parse(req.body);
const n=(await db("INSERT INTO novels(author_id,title,description,genre,cover_url) VALUES($1,$2,$3,$4,$5) RETURNING *",[req.user.sub,x.title,x.description||"",x.genre,x.cover_url||""])).rows[0];
res.status(201).json(n)
}catch(e){res.status(400).json({error:"INVALID_DATA"})}
});
 app.get("/api/mine",auth,async(req,res)=>{
const r=await db("SELECT * FROM novels WHERE author_id=$1 ORDER BY created_at DESC",[req.user.sub]);
res.json(r.rows);
});

app.post("/api/novels/:id/chapters",auth,async(req,res)=>{
try{
const x=z.object({
part_number:z.number().int().positive(),
title:z.string().min(1).max(200),
content:z.string().min(1)
}).parse(req.body);

const own=await db(
"SELECT id FROM novels WHERE id=$1 AND author_id=$2",
[req.params.id,req.user.sub]
);

if(!own.rowCount)return res.status(403).json({error:"NOT_OWNER"});

const r=await db(
`INSERT INTO chapters(novel_id,part_number,title,content)
VALUES($1,$2,$3,$4)
ON CONFLICT(novel_id,part_number)
DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content
RETURNING *`,
[req.params.id,x.part_number,x.title,x.content]
);

res.status(201).json(r.rows[0]);
}catch(e){
res.status(400).json({error:"INVALID_DATA"});
}
});

app.post("/api/novels/:id/submit",auth,async(req,res)=>{
const r=await db(
"UPDATE novels SET status='pending' WHERE id=$1 AND author_id=$2 RETURNING *",
[req.params.id,req.user.sub]
);
if(!r.rowCount)return res.status(403).json({error:"NOT_OWNER"});
res.json(r.rows[0]);
});
 app.get("/api/admin/pending",auth,admin,async(req,res)=>{
const r=await db(`SELECT n.*,u.name author FROM novels n JOIN users u ON u.id=n.author_id WHERE n.status='pending' ORDER BY n.created_at`);
res.json(r.rows);
});

app.post("/api/admin/novels/:id/review",auth,admin,async(req,res)=>{
try{
const x=z.object({
status:z.enum(["published","revision"]),
rejection_reason:z.string().max(2000).optional()
}).parse(req.body);

const r=await db(
`UPDATE novels SET status=$1,rejection_reason=$2,reviewed_at=NOW(),reviewed_by=$3
WHERE id=$4 RETURNING *`,
[x.status,x.rejection_reason||"",req.user.sub,req.params.id]
);

if(!r.rowCount)return res.status(404).json({error:"NOT_FOUND"});
res.json(r.rows[0]);
}catch(e){
res.status(400).json({error:"INVALID_DATA"});
}
});
 app.post("/api/novels/:id/comments",auth,async(req,res)=>{
const content=z.string().min(1).max(3000).parse(req.body.content);
const r=await db(
"INSERT INTO comments(novel_id,user_id,content) VALUES($1,$2,$3) RETURNING *",
[req.params.id,req.user.sub,content]
);
res.status(201).json(r.rows[0]);
});

app.post("/api/novels/:id/like",auth,async(req,res)=>{
const x=await db("SELECT 1 FROM likes WHERE user_id=$1 AND novel_id=$2",[req.user.sub,req.params.id]);
if(x.rowCount)await db("DELETE FROM likes WHERE user_id=$1 AND novel_id=$2",[req.user.sub,req.params.id]);
else await db("INSERT INTO likes(novel_id,user_id) VALUES($1,$2)",[req.params.id,req.user.sub]);
res.json({liked:!x.rowCount});
});

app.post("/api/novels/:id/bookmark",auth,async(req,res)=>{
const x=await db("SELECT 1 FROM bookmarks WHERE user_id=$1 AND novel_id=$2",[req.user.sub,req.params.id]);
if(x.rowCount)await db("DELETE FROM bookmarks WHERE user_id=$1 AND novel_id=$2",[req.user.sub,req.params.id]);
else await db("INSERT INTO bookmarks(novel_id,user_id) VALUES($1,$2)",[req.params.id,req.user.sub]);
res.json({bookmarked:!x.rowCount});
});

app.get("/api/me",auth,async(req,res)=>{
const u=(await db("SELECT id,name,email,role,email_verified,avatar_url,bio FROM users WHERE id=$1",[req.user.sub])).rows[0];
res.json(u);
});

app.put("/api/me",auth,async(req,res)=>{
const x=z.object({
name:z.string().min(2).max(80),
bio:z.string().max(2000),
avatar_url:z.string().max(1000).optional()
}).parse(req.body);
const u=(await db(
"UPDATE users SET name=$1,bio=$2,avatar_url=$3 WHERE id=$4 RETURNING id,name,email,role,email_verified,avatar_url,bio",
[x.name,x.bio,x.avatar_url||"",req.user.sub]
)).rows[0];
res.json(u);
});

app.use((req,res)=>res.sendFile(path.join(__dirname,"../../index.html")));

app.listen(PORT,()=>console.log("Romanak API running on "+PORT));
