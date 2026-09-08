import express from "express";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import pg from "pg";
import argon2 from "argon2";
import { rateLimit } from "express-rate-limit";

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
const FRONTEND_URL = process.env.FRONTEND_URL || "";
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: isProduction ? { rejectUnauthorized: false } : undefined });

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      email_verified BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS sessions(
      id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS password_resets(
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS email_verifications(
      token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at BIGINT NOT NULL
    );
  `);
}

app.disable("x-powered-by");
app.use((req,res,next)=>{ res.setHeader("X-Content-Type-Options","nosniff"); res.setHeader("X-Frame-Options","DENY"); res.setHeader("Referrer-Policy","strict-origin-when-cross-origin"); next(); });
app.use(express.json({limit:"20kb"}));
app.use(express.urlencoded({extended:false,limit:"20kb"}));
const authLimiter = rateLimit({windowMs:15*60*1000,limit:10,standardHeaders:"draft-8",legacyHeaders:false,message:{error:"Too many attempts. Try again later."}});
const registerLimiter = rateLimit({windowMs:60*60*1000,limit:5,standardHeaders:"draft-8",legacyHeaders:false,message:{error:"Too many registrations. Try again later."}});
const normalizeEmail=e=>String(e||"").trim().toLowerCase();
const validEmail=e=>/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validUsername=u=>/^[a-zA-Z0-9_]{3,30}$/.test(u);
function cookie(res,token,maxAge){let s=`session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;if(isProduction)s+="; Secure";res.setHeader("Set-Cookie",s)}
function clearCookie(res){res.setHeader("Set-Cookie","session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")}
function getCookie(req,name){for(const part of (req.headers.cookie||"").split(";")){const [k,...v]=part.trim().split("=");if(k===name)return decodeURIComponent(v.join("="))}return null}
function token(){return crypto.randomBytes(32).toString("base64url")}
function hashToken(t){return crypto.createHash("sha256").update(t).digest("hex")}
async function createSession(userId){const t=token(),expires=Date.now()+7*86400000;await pool.query("INSERT INTO sessions(id,user_id,expires_at) VALUES($1,$2,$3)",[t,userId,expires]);return {t,expires}}
async function auth(req,res,next){try{const t=getCookie(req,"session");if(!t)return res.status(401).json({error:"Not logged in."});const {rows}=await pool.query(`SELECT s.id,s.expires_at,u.id AS user_id,u.username,u.email,u.is_admin,u.email_verified FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>$2`,[t,Date.now()]);const u=rows[0];if(!u){clearCookie(res);return res.status(401).json({error:"Session expired."})}req.user=u;req.sessionToken=t;next()}catch(e){next(e)}}
function admin(req,res,next){if(!req.user?.is_admin)return res.status(403).json({error:"Admin only."});next()}

app.post("/api/register",registerLimiter,async(req,res)=>{try{const username=String(req.body.username||"").trim(),email=normalizeEmail(req.body.email),password=String(req.body.password||"");if(!validUsername(username))return res.status(400).json({error:"Username: 3-30 letters, numbers or _."});if(!validEmail(email))return res.status(400).json({error:"Enter a valid email."});if(password.length<12)return res.status(400).json({error:"Password must be at least 12 characters."});const existing=await pool.query("SELECT id FROM users WHERE username=$1 OR email=$2 LIMIT 1",[username,email]);if(existing.rowCount)return res.status(409).json({error:"Username or email already exists."});const hash=await argon2.hash(password,{type:argon2.argon2id});const {rows}=await pool.query("INSERT INTO users(username,email,password_hash) VALUES($1,$2,$3) RETURNING id",[username,email,hash]);const {t}=await createSession(rows[0].id);cookie(res,t,7*86400);res.status(201).json({ok:true,message:"Account created.",user:{username,email}})}catch(e){console.error("register:",e.message);res.status(500).json({error:"Server error."})}});
app.post("/api/login",authLimiter,async(req,res)=>{try{const email=normalizeEmail(req.body.email),password=String(req.body.password||"");const {rows}=await pool.query("SELECT * FROM users WHERE email=$1",[email]);const u=rows[0];if(!u||!(await argon2.verify(u.password_hash,password)))return res.status(401).json({error:"Invalid email or password."});const {t}=await createSession(u.id);cookie(res,t,7*86400);res.json({ok:true,user:{username:u.username,email:u.email,isAdmin:!!u.is_admin,emailVerified:!!u.email_verified}})}catch(e){console.error("login:",e.message);res.status(500).json({error:"Server error."})}});
app.get("/api/me",auth,(req,res)=>res.json({loggedIn:true,user:{id:req.user.user_id,username:req.user.username,email:req.user.email,isAdmin:!!req.user.is_admin,emailVerified:!!req.user.email_verified}}));
app.post("/api/logout",async(req,res)=>{const t=getCookie(req,"session");if(t)await pool.query("DELETE FROM sessions WHERE id=$1",[t]);clearCookie(res);res.json({ok:true})});
app.patch("/api/profile",auth,async(req,res)=>{const username=String(req.body.username||"").trim();if(!validUsername(username))return res.status(400).json({error:"Invalid username."});const e=await pool.query("SELECT id FROM users WHERE username=$1 AND id<>$2",[username,req.user.user_id]);if(e.rowCount)return res.status(409).json({error:"Username already exists."});await pool.query("UPDATE users SET username=$1 WHERE id=$2",[username,req.user.user_id]);res.json({ok:true,username})});
app.post("/api/change-password",auth,async(req,res)=>{const oldP=String(req.body.oldPassword||""),newP=String(req.body.newPassword||"");const {rows}=await pool.query("SELECT password_hash FROM users WHERE id=$1",[req.user.user_id]);if(!rows[0]||!(await argon2.verify(rows[0].password_hash,oldP)))return res.status(401).json({error:"Current password is incorrect."});if(newP.length<12)return res.status(400).json({error:"New password must be at least 12 characters."});const hash=await argon2.hash(newP,{type:argon2.argon2id});await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2",[hash,req.user.user_id]);await pool.query("DELETE FROM sessions WHERE user_id=$1 AND id<>$2",[req.user.user_id,req.sessionToken]);res.json({ok:true,message:"Password changed. Other sessions were logged out."})});
app.post("/api/send-verification",auth,async(req,res)=>{const raw=token(),h=hashToken(raw),expires=Date.now()+30*60*1000;await pool.query("DELETE FROM email_verifications WHERE user_id=$1",[req.user.user_id]);await pool.query("INSERT INTO email_verifications(token_hash,user_id,expires_at) VALUES($1,$2,$3)",[h,req.user.user_id,expires]);const link=`${FRONTEND_URL||`http://localhost:${PORT}`}/verify-email.html?token=${encodeURIComponent(raw)}`;console.log("DEV verification link:",link);res.json({ok:true,message:"Verification link generated. In production send it by email.",devLink:link})});
app.get("/api/verify-email",async(req,res)=>{const raw=String(req.query.token||"");const {rows}=await pool.query("SELECT user_id FROM email_verifications WHERE token_hash=$1 AND expires_at>$2",[hashToken(raw),Date.now()]);if(!rows[0])return res.status(400).json({error:"Invalid or expired verification link."});await pool.query("UPDATE users SET email_verified=TRUE WHERE id=$1",[rows[0].user_id]);await pool.query("DELETE FROM email_verifications WHERE token_hash=$1",[hashToken(raw)]);res.json({ok:true,message:"Email verified."})});
app.post("/api/forgot-password",authLimiter,async(req,res)=>{const email=normalizeEmail(req.body.email),{rows}=await pool.query("SELECT id FROM users WHERE email=$1",[email]);const response={ok:true,message:"If that email exists, a reset link has been created."};if(!rows[0])return res.json(response);const raw=token(),h=hashToken(raw),expires=Date.now()+15*60*1000;await pool.query("DELETE FROM password_resets WHERE user_id=$1",[rows[0].id]);await pool.query("INSERT INTO password_resets(token_hash,user_id,expires_at) VALUES($1,$2,$3)",[h,rows[0].id,expires]);const link=`${FRONTEND_URL||`http://localhost:${PORT}`}/reset-password.html?token=${encodeURIComponent(raw)}`;console.log("DEV password reset link:",link);res.json({...response,devLink:link})});
app.post("/api/reset-password",authLimiter,async(req,res)=>{const raw=String(req.body.token||""),p=String(req.body.password||"");if(p.length<12)return res.status(400).json({error:"Password must be at least 12 characters."});const {rows}=await pool.query("SELECT user_id FROM password_resets WHERE token_hash=$1 AND expires_at>$2",[hashToken(raw),Date.now()]);if(!rows[0])return res.status(400).json({error:"Invalid or expired reset token."});const hash=await argon2.hash(p,{type:argon2.argon2id});await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2",[hash,rows[0].user_id]);await pool.query("DELETE FROM password_resets WHERE user_id=$1",[rows[0].user_id]);await pool.query("DELETE FROM sessions WHERE user_id=$1",[rows[0].user_id]);res.json({ok:true,message:"Password reset. You can log in now."})});
app.get("/api/admin/users",auth,admin,async(req,res)=>{const {rows}=await pool.query("SELECT id,username,email,is_admin,email_verified,created_at FROM users ORDER BY id DESC");res.json({users:rows})});
app.patch("/api/admin/users/:id",auth,admin,async(req,res)=>{const id=Number(req.params.id);if(id===req.user.user_id)return res.status(400).json({error:"Do not remove your own admin access here."});await pool.query("UPDATE users SET is_admin=$1 WHERE id=$2",[!!req.body.isAdmin,id]);res.json({ok:true})});
app.delete("/api/admin/users/:id",auth,admin,async(req,res)=>{const id=Number(req.params.id);if(id===req.user.user_id)return res.status(400).json({error:"You cannot delete yourself."});await pool.query("DELETE FROM users WHERE id=$1",[id]);res.json({ok:true})});
app.use(express.static(path.join(__dirname,"public")));
app.get("*splat",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

initDb().then(()=>app.listen(PORT,()=>console.log(`Volt running on port ${PORT}`))).catch(e=>{console.error("Database initialization failed:",e);process.exit(1)});
