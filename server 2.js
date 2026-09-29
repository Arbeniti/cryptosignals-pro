const express=require("express");
const path=require("path");
const Database=require("better-sqlite3");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const crypto=require("crypto");
require("dotenv").config();

const app=express();
const db=new Database(process.env.DB_FILE||"cryptosignals.db");
const PORT=process.env.PORT||3000;
const JWT_SECRET=process.env.JWT_SECRET||"CHANGE_ME";
const ADMIN_EMAIL=(process.env.ADMIN_EMAIL||"").toLowerCase();
const PAYMENT_COIN=process.env.PAYMENT_COIN||"USDT";
const PAYMENT_NETWORK=process.env.PAYMENT_NETWORK||"TRC20";
const PAYMENT_ADDRESS=process.env.PAYMENT_ADDRESS||"";

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user',
 vip_until TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS signals(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 pair TEXT NOT NULL,
 direction TEXT NOT NULL,
 entry TEXT NOT NULL,
 stop_loss TEXT NOT NULL,
 take_profit TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Active',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 tx_hash TEXT UNIQUE NOT NULL,
 amount TEXT,
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);`);

app.use(express.json());
app.use(express.static(path.join(__dirname,"public")));

function sign(u){return jwt.sign({id:u.id,email:u.email,role:u.role},JWT_SECRET,{expiresIn:"7d"})}
function auth(req,res,next){
 const h=req.headers.authorization||"";
 if(!h.startsWith("Bearer "))return res.status(401).json({error:"Login required"});
 try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next()}catch{return res.status(401).json({error:"Session expired"})}
}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"Admin only"});next()}

app.get("/api/config",(req,res)=>res.json({
 coin:PAYMENT_COIN,network:PAYMENT_NETWORK,address:PAYMENT_ADDRESS,
 price:process.env.VIP_PRICE||"49",currency:"USD",
 verificationConfigured:Boolean(process.env.TRON_API_URL&&PAYMENT_ADDRESS)
}));

app.post("/api/register",async(req,res)=>{
 const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
 if(!email||password.length<8)return res.status(400).json({error:"Valid email and 8+ character password required"});
 try{
  const role=email===ADMIN_EMAIL&&ADMIN_EMAIL?"admin":"user";
  const hash=await bcrypt.hash(password,12);
  const x=db.prepare("INSERT INTO users(email,password_hash,role) VALUES(?,?,?)").run(email,hash,role);
  const u=db.prepare("SELECT id,email,role,vip_until FROM users WHERE id=?").get(x.lastInsertRowid);
  res.json({token:sign(u),user:u});
 }catch(e){res.status(409).json({error:"Email already registered"})}
});

app.post("/api/login",async(req,res)=>{
 const email=(req.body.email||"").trim().toLowerCase(), password=req.body.password||"";
 const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
 if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({error:"Invalid email or password"});
 res.json({token:sign(u),user:{id:u.id,email:u.email,role:u.role,vip_until:u.vip_until}});
});

app.get("/api/me",auth,(req,res)=>{
 const u=db.prepare("SELECT id,email,role,vip_until FROM users WHERE id=?").get(req.user.id);
 res.json(u);
});

app.get("/api/signals",auth,(req,res)=>{
 const u=db.prepare("SELECT vip_until FROM users WHERE id=?").get(req.user.id);
 if(u?.role!=="admin" && (!u?.vip_until || new Date(u.vip_until)<=new Date()))
   return res.status(402).json({error:"VIP subscription required"});
 res.json(db.prepare("SELECT * FROM signals ORDER BY id DESC").all());
});

app.post("/api/signals",auth,admin,(req,res)=>{
 const {pair,direction,entry,stop_loss,take_profit}=req.body||{};
 if(!pair||!direction||!entry||!stop_loss||!take_profit)return res.status(400).json({error:"All fields required"});
 const x=db.prepare("INSERT INTO signals(pair,direction,entry,stop_loss,take_profit) VALUES(?,?,?,?,?)")
 .run(pair,direction,entry,stop_loss,take_profit);
 res.json(db.prepare("SELECT * FROM signals WHERE id=?").get(x.lastInsertRowid));
});

app.delete("/api/signals/:id",auth,admin,(req,res)=>{
 db.prepare("DELETE FROM signals WHERE id=?").run(req.params.id);res.json({ok:true});
});

app.get("/api/admin/users",auth,admin,(req,res)=>{
 res.json(db.prepare("SELECT id,email,role,vip_until,created_at FROM users ORDER BY id DESC").all());
});

/*
 Payment flow:
 1) User submits a blockchain transaction hash.
 2) Server verifies it with the configured blockchain API.
 3) Only a VERIFIED transaction activates VIP.
 The verifier below supports TRON/TRC20 USDT when TRON_API_URL is configured.
*/
app.post("/api/payments/submit",auth,async(req,res)=>{
 const tx=(req.body.tx_hash||"").trim();
 if(!tx)return res.status(400).json({error:"Transaction hash required"});
 try{
  const used=db.prepare("SELECT user_id,status FROM payments WHERE tx_hash=?").get(tx);
  if(used && used.user_id!==req.user.id) return res.status(409).json({error:"This transaction has already been used"});
  if(!used) db.prepare("INSERT INTO payments(user_id,tx_hash) VALUES(?,?)").run(req.user.id,tx);
 }catch(e){return res.status(409).json({error:"This transaction was already submitted"})}
 const result=await verifyTronTx(tx);
 if(result.verified){
   const days=30;
   const until=new Date(Date.now()+days*86400000).toISOString();
   db.prepare("UPDATE payments SET status='verified',amount=? WHERE tx_hash=?").run(result.amount,tx);
   db.prepare("UPDATE users SET vip_until=? WHERE id=?").run(until,req.user.id);
   return res.json({verified:true,vip_until:until,amount:result.amount});
 }
 db.prepare("UPDATE payments SET status=? WHERE tx_hash=?").run(result.status||"pending",tx);
 res.json({verified:false,status:result.status||"pending",message:result.message});
});

async function verifyTronTx(tx){
 if(PAYMENT_NETWORK!=="TRC20") return {verified:false,status:"pending",message:"TRC20 verification is enabled for this site."};
 if(!PAYMENT_ADDRESS) return {verified:false,status:"pending",message:"Receiving address is not configured."};

 const priceUsd=Number(process.env.VIP_PRICE||49);
 const expectedSun=String(Math.round(priceUsd*1_000_000));
 const usdtContract=(process.env.USDT_TRC20_CONTRACT||"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6").trim();
 const base=(process.env.TRON_API_URL||"https://api.trongrid.io").replace(/\/$/,"");
 const headers={"Accept":"application/json"};
 if(process.env.TRON_API_KEY) headers["TRON-PRO-API-KEY"]=process.env.TRON_API_KEY;

 try{
   const url=`${base}/v1/accounts/${encodeURIComponent(PAYMENT_ADDRESS)}/transactions/trc20?only_confirmed=true&limit=200&contract_address=${encodeURIComponent(usdtContract)}`;
   const r=await fetch(url,{headers});
   if(!r.ok) return {verified:false,status:"pending",message:"Blockchain provider did not return the payment list."};
   const j=await r.json();
   const rows=Array.isArray(j.data)?j.data:[];
   const hit=rows.find(x=>String(x.transaction_id).toLowerCase()===tx.toLowerCase());
   if(!hit) return {verified:false,status:"pending",message:"Transaction not found as a confirmed USDT TRC20 payment to the configured address."};

   const recipient=String(hit.to||"");
   const sender=String(hit.from||"");
   const contract=String(hit.token_info?.address||usdtContract);
   const decimals=Number(hit.token_info?.decimals ?? 6);
   const amount=String(hit.value||"0");

   if(recipient!==PAYMENT_ADDRESS) return {verified:false,status:"pending",message:"The transaction recipient does not match the receiving wallet."};
   if(contract!==usdtContract) return {verified:false,status:"pending",message:"The token contract does not match USDT TRC20."};
   const required=BigInt(expectedSun);
   const paid=BigInt(amount);
   if(paid<required) return {verified:false,status:"pending",message:`Payment is below the required ${priceUsd} USDT.`};

   const existing=db.prepare("SELECT id,user_id FROM payments WHERE tx_hash=?").get(tx);
   if(existing && existing.user_id!==Number(this?.user_id||0))
     return {verified:false,status:"rejected",message:"This transaction has already been used."};

   return {verified:true,amount:(Number(amount)/(10**decimals)).toFixed(decimals),sender};
 }catch(e){
   console.error("TRON verification error:",e.message);
   return {verified:false,status:"pending",message:"Blockchain verification is temporarily unavailable."};
 }
}

app.listen(PORT,()=>console.log(`CryptoSignals running on http://localhost:${PORT}`));
