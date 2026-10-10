import { connect } from "cloudflare:sockets";

/* ---------------------------------- 常量 ---------------------------------- */
const SITE_TITLE = "次元星域登录授权中心";
const CFG_KEY = "mailgate:cfg";
const LOG_KEY = "mailgate:log";
const SESS_MAX_AGE = 7 * 86400; /* 服务台登录态 7 天 */
const te = new TextEncoder();
const td = new TextDecoder();
const B64C = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* -------------------------------- 基础工具 -------------------------------- */
function b64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64C[a >> 2] + B64C[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < bytes.length ? B64C[((b & 15) << 2) | (c >> 6)] : "=";
    out += i + 2 < bytes.length ? B64C[c & 63] : "=";
  }
  return out;
}
function b64s(s) { return b64(te.encode(s)); }
function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function unb64url(s) {
  let x = String(s).replace(/-/g, "+").replace(/_/g, "/");
  while (x.length % 4) x += "=";
  const bin = atob(x);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function randHex(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < a.length; i++) s += a[i].toString(16).padStart(2, "0");
  return s;
}
async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", te.encode(s));
  let h = "";
  for (const b of new Uint8Array(d)) h += b.toString(16).padStart(2, "0");
  return h;
}
async function sign(secret, data) {
  const key = await crypto.subtle.importKey("raw", te.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const d = await crypto.subtle.sign("HMAC", key, te.encode(data));
  return b64url(new Uint8Array(d));
}
function eqStr(a, b) {
  a = String(a); b = String(b);
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function jss(obj) { /* 安全内嵌 JSON（防止 </script> 逃逸） */
  return JSON.stringify(obj).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");
}
function fill(tpl, vars) {
  return String(tpl == null ? "" : tpl).replace(/\{\{(\w+)\}\}/g, (m, k) => (vars[k] != null ? String(vars[k]) : ""));
}
function isEmail(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(s); }
function genCode(len) {
  const a = new Uint8Array(len);
  crypto.getRandomValues(a);
  let s = "";
  for (let i = 0; i < len; i++) s += String(a[i] % 10);
  return s;
}
function json(o, status) {
  return new Response(JSON.stringify(o), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });
}
function page(html, status) {
  return new Response(html, {
    status: status || 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "frame-ancestors 'self' https://*.107211.xyz" }
  });
}
async function readJson(req) { try { return await req.json(); } catch (e) { return {}; } }
function cookieOf(req, name) {
  const c = req.headers.get("cookie") || "";
  for (const part of c.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return "";
}
function withTimeout(ms, msg) {
  return new Promise((_, rej) => setTimeout(() => rej(new Error(msg || "操作超时")), ms));
}

/* ------------------------------- KV / 内存 ------------------------------- */
function kvOf(env) { return (env && (env.STORE || env.KV || env.CONFIG || env.MAILGATE)) || null; }
function mem() { return (globalThis.__MG_MEM = globalThis.__MG_MEM || new Map()); }
async function kGet(env, key, type) {
  const kv = kvOf(env);
  if (kv) return await kv.get(key, type);
  const it = mem().get(key);
  if (!it) return null;
  if (it.x && it.x < Date.now()) { mem().delete(key); return null; }
  return type === "json" ? JSON.parse(it.v) : it.v;
}
async function kPut(env, key, val, ttlSec) {
  const kv = kvOf(env);
  if (kv) { await kv.put(key, val, ttlSec ? { expirationTtl: Math.max(60, ttlSec) } : undefined); return; }
  mem().set(key, { v: val, x: ttlSec ? Date.now() + ttlSec * 1000 : 0 });
}
async function kDel(env, key) {
  const kv = kvOf(env);
  if (kv) { await kv.delete(key); return; }
  mem().delete(key);
}

/* --------------------------------- 配置 --------------------------------- */
const DEF = {
  siteName: "邮箱验证服务",
  hmacSecret: "",
  sendMode: "smtp",                 /* smtp | resend */
  smtpHost: "", smtpPort: "465", smtpSecurity: "ssl",
  smtpUser: "", smtpPass: "", smtpFrom: "", smtpFromName: "",
  resendApiKey: "",
  codeLength: "6", codeTtlSec: "300", resendGapSec: "60", maxTry: "5", ticketTtlSec: "600",
  subject: "【{{site}}】邮箱验证码",
  bodyHtml: `<div style="margin:0;background:#f8fafc;padding:32px 16px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;color:#1f2937;-webkit-font-smoothing:antialiased;">
 <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:20px;overflow:hidden;box-shadow:0 16px 48px rgba(0,0,0,.10);">
  <div style="height:4px;background:linear-gradient(90deg,#ffb7c5,#ff8fa8,#ffb7c5);"></div>
  <div style="padding:30px 30px 26px;">
   <div style="font-size:13px;color:#6b7280;margin:0 0 14px;"><b style="color:#1f2937;font-weight:700;">MAILGATE</b></div>
   <h1 style="font-size:20px;font-weight:800;margin:0 0 16px;color:#e0567e;">{{site}} · 邮箱验证码</h1>
   <div style="border-top:1px solid #e5e7eb;padding-top:16px;font-size:14px;line-height:1.8;">
    验证码用于验证邮箱 <b>{{email}}</b>：
   </div>
   <div style="margin:16px 0;background:#f9fafb;border:1px solid #e5e7eb;border-radius:14px;padding:16px 0;text-align:center;font-family:'Fira Code',Consolas,Menlo,monospace;font-size:34px;letter-spacing:.32em;font-weight:700;color:#1f2937;">{{code}}</div>
   <div style="font-size:13px;color:#6b7280;line-height:1.8;">验证码 {{minutes}} 分钟内有效。若非本人操作，请忽略本邮件。</div>
  </div>
 </div>
</div>`,
  turnstileSiteKey: "", turnstileSecret: "",
  allowedOrigins: ""
};
const WRITE_ONLY = ["smtpPass", "resendApiKey", "turnstileSecret"];

async function loadCfg(env) {
  const saved = await kGet(env, CFG_KEY, "json");
  const cfg = Object.assign({}, DEF, saved || {});
  if (!cfg.hmacSecret) {
    cfg.hmacSecret = "mg-" + randHex(32);
    try { await kPut(env, CFG_KEY, JSON.stringify(cfg), 0); } catch (e) {}
  }
  return cfg;
}
async function saveCfg(env, cfg) { await kPut(env, CFG_KEY, JSON.stringify(cfg), 0); }
async function hashPw(pw) {
  const salt = randHex(8);
  return salt + "$" + (await sha256hex(salt + "|" + pw));
}
async function checkPw(cfg, pw) {
  const s = String(cfg.adminPw || "");
  const i = s.indexOf("$");
  if (i < 0) return false;
  return eqStr(await sha256hex(s.slice(0, i) + "|" + pw), s.slice(i + 1));
}

/* --------------------------------- 发信 --------------------------------- */
function mimeWord(s) { return "=?UTF-8?B?" + b64s(s) + "?="; }
function b64lines(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 57) out += b64(bytes.subarray(i, i + 57)) + "\r\n";
  return out;
}
function buildMime(from, fromName, to, subject, html) {
  const host = from.indexOf("@") >= 0 ? from.split("@")[1] : "localhost";
  const fromH = fromName
    ? mimeWord(fromName) + " <" + from + ">"
    : from + " <" + from + ">";
  const head = [
    "From: " + fromH,
    "To: <" + to + ">",
    "Subject: " + mimeWord(subject),
    "Date: " + new Date().toUTCString(),
    "Message-ID: <" + randHex(12) + "@" + host + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: base64"
  ];
  let body = b64lines(te.encode(html));
  /* body 保留末尾 CRLF：send(buildMime(...) + ".") 会拼出 "\r\n.\r\n" 作为 DATA 终止符 */
  return head.join("\r\n") + "\r\n\r\n" + body;
}

async function smtpSend(cfg, toAddr, subject, htmlBody) {
  const host = String(cfg.smtpHost || "").trim();
  const port = parseInt(cfg.smtpPort, 10) || 465;
  /** @type {"off" | "on" | "starttls"} 三值之外的配置一律按隐式 TLS 处理 */
  const sec = cfg.smtpSecurity === "starttls" ? "starttls" : (cfg.smtpSecurity === "plain" ? "off" : "on");
  if (!host) throw new Error("未配置 SMTP 服务器地址");
  if (port === 25) throw new Error("Cloudflare Workers 禁止 25 端口出站，请改用 465 或 587");
  const from = String(cfg.smtpFrom || "").trim() || String(cfg.smtpUser || "").trim();
  if (!isEmail(from)) throw new Error("请填写有效的发件地址（smtpFrom）");
  if (!isEmail(toAddr)) throw new Error("收件邮箱不合法");
  const EHLO = "EHLO mailgate.local";
  const S = { sock: null, r: null, w: null, buf: "" };

  async function attach(s) {
    if (S.r) { try { S.r.releaseLock(); } catch (e) {} }
    if (S.w) { try { S.w.releaseLock(); } catch (e) {} }
    S.sock = s; S.buf = "";
    S.r = s.readable.getReader();
    S.w = s.writable.getWriter();
  }
  async function pull() {
    let tt;
    const race = Promise.race([
      S.r.read(),
      new Promise((_, rej) => { tt = setTimeout(() => rej(new Error("SMTP 等待响应超时")), 15000); })
    ]);
    const r = await race;
    clearTimeout(tt);
    if (r.done) throw new Error("SMTP 连接被对方关闭");
    S.buf += td.decode(r.value, { stream: true });
  }
  async function rawLine() {
    for (;;) {
      let i = S.buf.indexOf("\r\n");
      if (i < 0) i = S.buf.indexOf("\n");
      if (i >= 0) {
        let l = S.buf.slice(0, i);
        if (l.endsWith("\r")) l = l.slice(0, -1);
        S.buf = S.buf.slice(i + 1);
        if (S.buf.startsWith("\n")) S.buf = S.buf.slice(1);
        return l;
      }
      await pull();
    }
  }
  async function reply() {
    for (;;) {
      const l = await rawLine();
      if (!l) continue;
      if (/^\d{3}-/.test(l)) continue;
      if (/^\d{3} /.test(l)) return { code: parseInt(l.slice(0, 3), 10), text: l };
      /* 非标准行，忽略 */
    }
  }
  async function send(s) { await S.w.write(te.encode(s + "\r\n")); }
  async function cmd(c) { await send(c); return await reply(); }
  function die(r, what) { throw new Error(what + "：" + (r ? r.text : "服务器无响应")); }

  let sock = connect({ hostname: host, port: port }, { secureTransport: sec, allowHalfOpen: false });
  try {
    await sock.opened;
    await attach(sock);
    let r = await reply();
    if (r.code !== 220) die(r, "SMTP 握手");
    r = await cmd(EHLO);
    if (r.code !== 250) { r = await cmd("HELO mailgate.local"); if (r.code !== 250) die(r, "EHLO"); }

    if (sec === "starttls") {
      r = await cmd("STARTTLS");
      if (r.code !== 220) die(r, "STARTTLS");
      try { S.r.releaseLock(); } catch (e) {} S.r = null;
      try { S.w.releaseLock(); } catch (e) {} S.w = null;
      const tls = sock.startTls();
      await tls.opened;
      await attach(tls);
      r = await cmd(EHLO);
      if (r.code !== 250) die(r, "STARTTLS 后 EHLO");
    }

    if (cfg.smtpUser) {
      r = await cmd("AUTH LOGIN");
      if (r.code !== 334) die(r, "AUTH LOGIN 不受支持");
      r = await cmd(b64s(String(cfg.smtpUser)));
      if (r.code !== 334) die(r, "认证用户名被拒绝");
      r = await cmd(b64s(String(cfg.smtpPass || "")));
      if (r.code !== 235) die(r, "认证密码被拒绝");
    }
    const fromName = String(cfg.smtpFromName || "").trim();
    r = await cmd("MAIL FROM:<" + from + ">");
    if (r.code !== 250) die(r, "MAIL FROM 被拒绝");
    r = await cmd("RCPT TO:<" + toAddr + ">");
    if (r.code !== 250 && r.code !== 251) die(r, "RCPT TO 被拒绝");
    r = await cmd("DATA");
    if (r.code !== 354) die(r, "DATA 被拒绝");
    await send(buildMime(from, fromName, toAddr, subject, htmlBody) + ".");
    r = await reply();
    if (r.code !== 250) die(r, "最终投递");
    try { await cmd("QUIT"); } catch (e) {}
  } finally {
    try { if (S.r) S.r.releaseLock(); } catch (e) {}
    try { if (S.w) S.w.releaseLock(); } catch (e) {}
    try { if (S.sock && S.sock !== sock) S.sock.close(); } catch (e) {}
    try { sock.close(); } catch (e) {}
  }
}

async function deliver(cfg, to, subject, htmlBody) {
  if (cfg.sendMode === "resend") {
    const key = String(cfg.resendApiKey || "").trim();
    if (!key) throw new Error("未配置 Resend API Key");
    const from = String(cfg.smtpFrom || "").trim();
    if (!isEmail(from)) throw new Error("请填写发件地址（Resend 需已验证域名）");
    const name = String(cfg.smtpFromName || "").trim();
    const r = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { Authorization: "Bearer " + key, "Content-Type": "application/json" },
      body: JSON.stringify({ from: name ? name + " <" + from + ">" : from, to: [to], subject: subject, html: htmlBody })
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error("Resend 返回 " + r.status + "：" + (j.message || "未知错误"));
    return;
  }
  await Promise.race([smtpSend(cfg, to, subject, htmlBody), withTimeout(30000, "SMTP 整体超时")]);
}

/* ------------------------------- 人机验证 ------------------------------- */
async function newCaptcha(env) {
  const cfg = await loadCfg(env);
  const a = 2 + Math.floor(Math.random() * 8);
  const b = 1 + Math.floor(Math.random() * 9);
  const ans = String(a + b);
  const exp = String(Date.now() + 600000);
  const sig = await sign(cfg.hmacSecret, "cap|" + ans + "|" + exp);
  return { q: a + " + " + b, exp: exp, sig: sig };
}
async function verifyCaptcha(env, cfg, body, ip) {
  if (cfg.turnstileSiteKey && cfg.turnstileSecret) {
    const tok = String(body.turnstile || "");
    if (!tok) return { ok: false, msg: "请先完成人机验证" };
    const fd = new FormData();
    fd.append("secret", cfg.turnstileSecret);
    fd.append("response", tok);
    if (ip) fd.append("remoteip", ip);
    let j;
    try {
      const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: fd });
      j = await r.json();
    } catch (e) { return { ok: false, msg: "人机验证服务暂不可用" }; }
    if (!j.success) return { ok: false, msg: "人机验证未通过，请重试" };
    return { ok: true };
  }
  const c = body.captcha || {};
  const ans = String(c.ans || "").trim();
  const exp = String(c.exp || "");
  const sig = String(c.sig || "");
  if (!ans || !exp || !sig) return { ok: false, msg: "请先回答人机验证题" };
  if (!/^\d+$/.test(ans)) return { ok: false, msg: "请先回答人机验证题" };
  if (Date.now() > parseInt(exp, 10)) return { ok: false, msg: "验证题已过期，请刷新换一题" };
  const want = await sign(cfg.hmacSecret, "cap|" + ans + "|" + exp);
  if (!eqStr(want, sig)) return { ok: false, msg: "人机验证答案不正确" };
  const ck = "cap:" + sig.slice(0, 32);
  if (await kGet(env, ck)) return { ok: false, msg: "该验证题已使用，请换一题" };
  await kPut(env, ck, "1", 600);
  return { ok: true };
}

/* ------------------------------ 验证码流程 ------------------------------ */
function codeKey(email) { return "code:" + email; }
async function addLog(env, mail, ok, note) {
  try {
    const arr = (await kGet(env, LOG_KEY, "json")) || [];
    arr.unshift({ t: Date.now(), m: mail, ok: ok ? 1 : 0, n: String(note || "").slice(0, 80) });
    arr.length = Math.min(arr.length, 15);
    await kPut(env, LOG_KEY, JSON.stringify(arr), 0);
  } catch (e) {}
}

/* -------------------------------- intent -------------------------------- */
/* 页面渲染时签发：绑定 redirect 与来源页携带参数，防止客户端篡改 */
async function makeIntent(cfg, redirect, extra) {
  const payload = JSON.stringify({ u: redirect || "", e: extra || [], x: Date.now() + 3600000 });
  const sig = await sign(cfg.hmacSecret, "it|" + payload);
  return b64url(te.encode(payload)) + "." + sig;
}
async function openIntent(cfg, s) {
  try {
    const i = String(s || "").lastIndexOf(".");
    if (i < 0) return null;
    const sig = s.slice(i + 1);
    const payload = td.decode(unb64url(s.slice(0, i)));
    if (!eqStr(await sign(cfg.hmacSecret, "it|" + payload), sig)) return null;
    const o = JSON.parse(payload);
    if (!o.x || o.x < Date.now()) return null;
    return o;
  } catch (e) { return null; }
}

/* -------------------------------- ticket --------------------------------- */
async function makeTicket(cfg, email, ts, exp) {
  const payload = email + "|" + ts + "|" + exp;
  const sig = await sign(cfg.hmacSecret, "tk|" + payload);
  return "v1." + b64url(te.encode(email)) + "." + ts + "." + exp + "." + sig;
}
async function checkTicket(cfg, ticket) {
  try {
    const p = String(ticket || "").split(".");
    if (p.length !== 5 || p[0] !== "v1") return null;
    const email = td.decode(unb64url(p[1]));
    const ts = p[2], exp = parseInt(p[3], 10);
    if (!isEmail(email) || !ts || !exp) return null;
    if (Date.now() > exp) return null;
    const want = await sign(cfg.hmacSecret, "tk|" + email + "|" + ts + "|" + exp);
    if (!eqStr(want, p[4])) return null;
    return { email: email, ts: ts, exp: exp };
  } catch (e) { return null; }
}

function originAllowed(cfg, u) {
  const list = String(cfg.allowedOrigins || "").split(/\r?\n|,| /).map(s => s.trim()).filter(Boolean);
  if (!list.length) return true;
  const h = u.hostname.toLowerCase();
  const full = u.origin;
  return list.some(e => {
    e = e.toLowerCase();
    if (/^https?:\/\//.test(e)) {
      try { const eu = new URL(e); return eu.origin === full; } catch (x) { return false; }
    }
    if (e.startsWith("*.")) return h === e.slice(2) || h.endsWith(e.slice(1));
    return h === e;
  });
}
async function buildReturn(cfg, intent, email) {
  if (!intent || !intent.u) return null;
  let u;
  try { u = new URL(intent.u); } catch (e) { return null; }
  const now = Date.now();
  const ts = String(now);
  const exp = String(now + (parseInt(cfg.ticketTtlSec, 10) || 600) * 1000);
  const ticket = await makeTicket(cfg, email, ts, exp);
  for (const p of intent.e || []) {
    if (p && p[0] && !u.searchParams.has(p[0])) u.searchParams.set(p[0], p[1]);
  }
  u.searchParams.set("email", email);
  u.searchParams.set("ticket", ticket);
  u.searchParams.set("ts", ts);
  /* 供下游站点 SSO 端点识别：邮箱验证即登录 / 注册成功 */
  u.searchParams.set("oauth_success", "1");
  u.searchParams.set("provider", "email");
  return { url: u.toString(), ticket: ticket };
}

/* ------------------------------ 页面样式 CSS ----------------------------- */
const CSS = `
  /* 整体视觉参考 cmliu/edgetunnel：浅底 + 樱花粉渐变主题(#ffb7c5) + 毛玻璃圆角卡片 */
  :root{--paper:#f8fafc;--card:#fff;--card-95:rgba(255,255,255,.75);
        --bg:url("https://t.alcy.cc/ycy");
        --ink:#1f2937;--ink-2:#6b7280;--ink-3:#9ca3af;
        --line:#e5e7eb;--line-2:#d1d5db;--input-bg:#f3f4f6;
        --o1:#ffb7c5;--o2:#ff8fa8;--o3:#e0567e;--blue:#2563eb;
        --green:#16a34a;--green-bg:#f0fdf4;--red:#dc2626;--red-bg:#fef2f2;
        --mono:"Fira Code","SFMono-Regular",Consolas,Menlo,"Courier New",monospace}
  *{box-sizing:border-box;margin:0;padding:0}
  [hidden]{display:none!important}
  body{font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei","Hiragino Sans GB",system-ui,sans-serif;
       background:var(--paper);
       color:var(--ink);line-height:1.7;min-height:100vh;display:flex;padding:40px 16px;-webkit-font-smoothing:antialiased}
  /* 背景图：横屏取 ycy、竖屏取 mp（见文末 orientation 媒体查询），缓慢缩放制造呼吸感 */
  body::before{content:"";position:fixed;inset:0;z-index:-1;background:var(--bg) center/cover no-repeat;
       animation:bgDrift 30s ease-in-out infinite alternate;will-change:transform}
  a{color:var(--o3)}
  @keyframes containerAppear{0%{opacity:0;transform:translateY(30px) scale(.98)}100%{opacity:1;transform:translateY(0) scale(1)}}
  @keyframes gradientShift{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}
  @keyframes bgDrift{0%{transform:scale(1.04)}100%{transform:scale(1.14)}}
  @keyframes riseIn{0%{opacity:0;transform:translateY(14px)}100%{opacity:1;transform:translateY(0)}}
  @keyframes logoIn{0%{opacity:0;transform:translateY(-12px) scale(.9)}100%{opacity:1;transform:translateY(0) scale(1)}}
  @keyframes softFloat{0%,100%{translate:0 0}50%{translate:0 -5px}}
  .card{position:relative;width:100%;max-width:376px;margin:auto;background:var(--card-95);
        -webkit-backdrop-filter:blur(22px) saturate(1.2);backdrop-filter:blur(22px) saturate(1.2);
        border:1px solid rgba(255,255,255,.65);
        border-radius:24px;padding:36px 32px 30px;overflow:hidden;
        box-shadow:0 20px 60px rgba(0,0,0,.12),0 2px 8px rgba(0,0,0,.04);
        animation:containerAppear .8s ease-out backwards}
  .card::before{content:"";position:absolute;top:0;left:0;right:0;height:4px;
        background:linear-gradient(90deg,var(--o1) 0,var(--o2) 50%,var(--o1) 100%);
        background-size:200% 100%;animation:gradientShift 3s ease infinite}
  .card-login{max-width:640px}
  /* 登录类页面（Oauth / 邮箱 / 服务台登录）：电脑端收窄到内容所需宽度 */
  .card-login.card-narrow{max-width:420px}
  .card-admin{max-width:704px}
  .brand{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;
         font-size:13px;color:var(--ink-2);margin:6px 0 16px}
  .brand b{color:var(--ink);font-weight:700;letter-spacing:.02em}
  h1{font-size:24px;font-weight:800;margin:0 0 6px;letter-spacing:-.3px;
     background:linear-gradient(135deg,var(--o2) 0,var(--o3) 100%);
     -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  .ttl{text-align:center;font-size:28px;font-weight:800;margin:0 0 22px;letter-spacing:-.5px;
       background:linear-gradient(135deg,var(--o2) 0,var(--o3) 100%);
       -webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
  /* 站点 Logo（代替文字标题）：居中、按比例缩放、带入场与轻微浮动动画 */
  .logo{display:block;height:58px;width:auto;max-width:100%;margin:8px auto 22px;
        filter:drop-shadow(0 8px 18px rgba(255,143,168,.28));
        animation:logoIn .7s cubic-bezier(.34,1.56,.64,1) both,softFloat 5s ease-in-out 1s infinite}
  .topbar{margin:0 0 16px;animation:riseIn .45s ease both}
  .back{display:inline-flex;align-items:center;gap:6px;font-size:13px;font-weight:600;line-height:1.2;color:#374151;
        text-decoration:none;border:0;border-radius:10px;padding:9px 16px;background:#e5e7eb;
        cursor:pointer;box-sizing:border-box;-webkit-appearance:none;appearance:none;transition:all .3s ease}
  .back:hover{background:#d1d5db;transform:translateY(-2px);box-shadow:0 4px 15px rgba(0,0,0,.08)}
  .back:active{transform:translateY(0)}
  .en{font:600 11px/1.6 var(--mono);letter-spacing:.2em;text-transform:uppercase;color:var(--ink-3);margin:0 0 16px}
  .st{font:600 11px/1 var(--mono);letter-spacing:.08em;border:1px solid var(--line);border-radius:999px;
      padding:6px 12px;color:var(--ink-2);background:#f9fafb;white-space:nowrap}
  .lnk{font-size:13px;color:var(--o3);text-decoration:none;border-bottom:1px solid transparent;text-underline-offset:3px}
  .lnk:hover{color:var(--o2);border-bottom-color:currentColor}

  /* 左侧信息栏 / 平台信息 */
  .platform{background:linear-gradient(160deg,#fff,#f9fafb);border:1px solid var(--line);border-radius:16px;
            padding:16px 18px;font-size:13px;box-shadow:0 1px 3px rgba(0,0,0,.04)}
  .platform .r{display:flex;justify-content:space-between;gap:16px;padding:3px 0;
               animation:riseIn .5s ease both}
  .platform .r:nth-child(2){animation-delay:.06s}
  .platform .r:nth-child(3){animation-delay:.12s}
  .platform .r:nth-child(4){animation-delay:.18s}
  .platform .r:nth-child(5){animation-delay:.24s}
  .platform .r:nth-child(6){animation-delay:.30s}
  .platform .r:nth-child(7){animation-delay:.36s}
  .platform .r:nth-child(8){animation-delay:.42s}
  .platform dt{color:var(--ink-2);flex-shrink:0}
  .platform dd{margin:0;text-align:right;word-break:break-all;color:var(--ink)}
  .platform dd.mono,.mono{font-family:var(--mono);font-size:12px;color:var(--ink)}

  /* 两列布局 + 两个入口按钮 */
  .cols{display:grid;grid-template-columns:1fr;gap:18px;align-items:start}
  .col-plat,.col-login{min-width:0}
  .mbtns{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;width:100%}
  .mbtn{flex:1 1 0;min-width:0;display:flex;align-items:center;justify-content:center;gap:9px;
        padding:13px 26px;border:0;border-radius:12px;color:#fff;text-decoration:none;
        background:linear-gradient(135deg,#ffb7c5 0,#ff8fa8 100%);
        font-family:inherit;font-size:15px;font-weight:600;letter-spacing:.5px;line-height:1.3;cursor:pointer;
        box-shadow:0 4px 15px rgba(255,183,197,.18);transition:all .3s ease;
        position:relative;overflow:hidden;-webkit-appearance:none;appearance:none;
        animation:riseIn .55s ease both}
  .mbtn::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;
        background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);transition:left .5s ease}
  .mbtn:hover::before{left:100%}
  .mbtn:hover{transform:translateY(-2px);box-shadow:0 6px 25px rgba(255,183,197,.3)}
  .mbtn:active{transform:translateY(0);box-shadow:0 2px 10px rgba(255,143,168,.4)}
  .mbtn.on{box-shadow:0 0 0 3px rgba(255,143,168,.35),0 6px 25px rgba(255,183,197,.3)}
  .mbtn:nth-child(1){animation-delay:.10s}
  .mbtn:nth-child(2){animation-delay:.22s}
  .panel{margin-top:14px;min-width:0}
  .plabel{font:10px/1.2 var(--mono);letter-spacing:.24em;color:var(--ink-2);
          text-transform:uppercase;margin:2px 0 4px}

  /* 登录方式列表 */
  .providers{margin:0}
  .pv{display:flex;align-items:center;gap:12px;padding:13px 16px;margin:10px 0;
      border:1px solid var(--line);border-radius:14px;background:#fff;color:var(--ink);text-decoration:none;
      font-size:14px;box-shadow:0 1px 3px rgba(0,0,0,.04);transition:all .25s ease;
      animation:riseIn .5s ease both}
  .pv:nth-child(1){animation-delay:.08s}
  .pv:nth-child(2){animation-delay:.16s}
  .pv:nth-child(3){animation-delay:.24s}
  .pv:nth-child(4){animation-delay:.32s}
  .pv:nth-child(5){animation-delay:.40s}
  .pv:nth-child(6){animation-delay:.48s}
  .pv:nth-child(n+7){animation-delay:.56s}
  .pv:hover{transform:translateY(-2px);border-color:transparent;box-shadow:0 10px 24px rgba(255,143,168,.16)}
  .lg{width:32px;height:32px;border-radius:10px;background:#f9fafb;border:1px solid var(--line);
      flex-shrink:0;display:inline-flex;align-items:center;justify-content:center}
  .lg svg{width:17px;height:17px;display:block}
  .nm{font-weight:600}
  .arr{margin-left:auto;color:var(--o3);font-size:15px}
  .empty{font-size:13px;color:var(--ink-2);text-align:center;padding:18px 12px;
         border:1px dashed var(--line-2);border-radius:14px;background:#fafafa}

  /* 表单控件 */
  label.fl{display:block;font-size:13.5px;font-weight:600;color:#374151;margin:16px 0 8px;letter-spacing:.3px}
  input[type=email],input[type=text],input[type=password],input[type=number],input[type=url],
  select,textarea{width:100%;font-size:15px;font-family:inherit;line-height:1.5;color:var(--ink);background:#fff;
                  border:2px solid var(--line);border-radius:12px;padding:13px 15px;box-sizing:border-box;
                  -webkit-appearance:none;appearance:none;transition:all .3s ease}
  input:focus,select:focus,textarea:focus{outline:0;border-color:var(--o2);box-shadow:0 0 0 4px rgba(255,143,168,.12);background:#fff}
  textarea{resize:vertical;min-height:96px;font-family:var(--mono);font-size:13px}
  .btn{font-family:inherit;font-size:15px;font-weight:600;letter-spacing:.5px;padding:11px 22px;
       background:linear-gradient(135deg,#ffb7c5 0,#ff8fa8 100%);color:#fff;border:0;border-radius:12px;cursor:pointer;
       white-space:nowrap;box-sizing:border-box;-webkit-appearance:none;appearance:none;
       position:relative;overflow:hidden;box-shadow:0 4px 15px rgba(255,183,197,.18);transition:all .3s ease}
  .btn::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;
       background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);transition:left .5s ease}
  .btn:hover::before{left:100%}
  .btn:hover{transform:translateY(-2px);box-shadow:0 6px 25px rgba(255,183,197,.3)}
  .btn:active{transform:translateY(0);box-shadow:0 2px 10px rgba(255,143,168,.4)}
  .btn.ghost{background:#e5e7eb;color:#374151;box-shadow:none}
  .btn.ghost::before{content:none}
  .btn.ghost:hover{background:#d1d5db;color:#374151;transform:translateY(-2px);box-shadow:0 4px 15px rgba(0,0,0,.08)}
  .btn.ghost:active{transform:translateY(0);box-shadow:none}
  .btn:disabled{opacity:.5;cursor:not-allowed;pointer-events:none;transform:none;box-shadow:none}
  .btn.sm{padding:8px 14px;font-size:13px;border-radius:10px}
  .panel .btn{width:100%;margin-top:14px}
  .row{display:flex;gap:10px}
  .row input{flex:1}

  /* 验证页步骤 */
  .step{padding:20px 0 4px;animation:riseIn .5s ease both}
  .step+.step{border-top:1px dashed var(--line-2);margin-top:18px;padding-top:18px}
  .sh{display:flex;align-items:baseline;gap:10px;margin-bottom:14px}
  .sh i{font-style:normal;font:600 15px/1 var(--mono);color:var(--o3);letter-spacing:.06em}
  .sh em{font-style:normal;font-size:15px;font-weight:700}
  .sh u{flex:1;text-decoration:none;border-bottom:1px dashed var(--line-2);transform:translateY(-4px)}
  .cap{margin-top:14px;border:1px solid var(--line);background:#f9fafb;border-radius:14px;padding:14px 16px;max-width:100%;overflow:hidden}
  .cap .lb{font:600 10px/1.2 var(--mono);letter-spacing:.24em;color:var(--ink-3);text-transform:uppercase;margin-bottom:12px}
  .math{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .math .q{font:700 16px/1 var(--mono);background:linear-gradient(135deg,var(--o1),var(--o2));color:#fff;padding:12px 16px;
           letter-spacing:.08em;border-radius:10px;box-shadow:0 4px 12px rgba(255,143,168,.3)}
  .math input{max-width:112px;text-align:center}
  .cap a{color:var(--o3);font-size:13px;cursor:pointer}
  /* Turnstile 人机验证组件：外层跟随卡片内容并左右居中（上限 300px）。
     组件按 300×65 自然尺寸渲染，脚本按可用宽度整体等比缩放（transform，原点左上），
     任何宽度（含窄屏竖屏）都完整显示、不裁剪、不溢出；缩放后的宽高由脚本预留，避免下方跳动 */
  .cf-wrap{width:100%;max-width:300px;margin:0 auto}
  .cf-turnstile{width:300px;height:65px;line-height:0;transform-origin:left top}
  .err{margin-top:13px;border:1px solid #fecaca;background:var(--red-bg);color:#b91c1c;
       padding:10px 14px;font-size:13.5px;border-radius:10px}
  .tip{margin:0 0 4px;font-size:13.5px;color:var(--ink-2);background:#f9fafb;border:1px solid var(--line);
       border-radius:10px;padding:10px 14px}
  .tip b{font-family:var(--mono);color:var(--ink)}
  .codes{display:flex;gap:8px;justify-content:center;margin:18px 0 6px}
  input.codebox{flex:1 1 0;min-width:0;max-width:52px;height:62px;text-align:center;
                font:600 clamp(18px,5vw,30px)/62px var(--mono);
                border:2px solid var(--line);border-radius:12px;background:#fff;padding:0;color:var(--ink);transition:all .3s ease}
  input.codebox:focus{outline:0;border-color:var(--o2);box-shadow:0 0 0 4px rgba(255,143,168,.12)}
  .acts{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:18px}

  /* 结果 / 状态 */
  .status{padding:14px 16px;border-radius:12px;font-size:14px;margin:14px 0;line-height:1.7}
  .status .t{font-weight:700}
  .status.ok{background:var(--green-bg);border:1px solid #bbf7d0;color:#15803d}
  .status.fail{background:var(--red-bg);border:1px solid #fecaca;color:#b91c1c}
  .okinfo p{margin:4px 0}
  .okinfo b{font-family:var(--mono)}
  .okinfo code{display:inline-block;max-width:100%;overflow-wrap:anywhere;font:12px/1.6 var(--mono);
               background:#f9fafb;border:1px solid var(--line);border-radius:10px;padding:10px 12px;
               margin:8px 0;color:var(--ink)}
  .dtable{margin:6px 0 4px;border-top:1px solid var(--line)}
  .dtable .r{display:flex;justify-content:space-between;gap:16px;padding:9px 0;
             border-bottom:1px solid var(--line);font-size:13.5px}
  .dtable dt{color:var(--ink-2);flex-shrink:0}
  .dtable dd{margin:0;text-align:right;word-break:break-all}
  .profile{display:flex;align-items:center;gap:12px;margin:0 0 16px;background:#f9fafb;
           border:1px solid var(--line);border-radius:14px;padding:14px 16px}
  .avatar,.profile img{width:44px;height:44px;border-radius:50%}
  .avatar{background:linear-gradient(135deg,var(--o1),var(--o2));color:#fff;font-size:16px;font-weight:700;flex-shrink:0;
          display:flex;align-items:center;justify-content:center}
  .profile img{object-fit:cover}
  .profile .nm{font-weight:700;font-size:15px}
  .profile .em{color:var(--ink-2);font-size:13px;margin-top:1px}

  /* 服务台 */
  .sec{border:1px solid var(--line);border-radius:16px;padding:20px 20px 18px;margin:0 0 18px;
       background:var(--card-95);box-shadow:0 4px 14px rgba(0,0,0,.06)}
  .sec legend{padding:0 10px;font-weight:700;letter-spacing:.08em;background:transparent;
              font-size:13px;color:var(--ink-2)}
  .frm{display:grid;grid-template-columns:175px minmax(0,1fr);gap:13px 18px;align-items:center}
  .frm .lb{text-align:right;font-size:14px;font-weight:600;color:#374151}
  .frm .lb i{display:block;font-style:normal;font:600 10px/1.6 var(--mono);color:var(--ink-3);
             letter-spacing:.12em;text-transform:uppercase}
  .hint{font:12px/1.7 var(--mono);color:var(--ink-2);margin-top:5px}
  .msg{margin-top:12px;border:1px solid #bbf7d0;border-left:4px solid var(--green);
       background:var(--green-bg);color:#15803d;padding:10px 14px;font-size:13.5px;border-radius:10px}
  .msg.bad{border-color:#fecaca;border-left-color:var(--red);background:var(--red-bg);color:#b91c1c}
  .warn{margin:0 0 16px;border:1px solid #ffc9d6;border-left:4px solid var(--o2);
        background:#fff1f5;color:#b23a5f;padding:10px 14px;font-size:13px;border-radius:10px}
  details{border:1px solid var(--line);border-radius:14px;background:#fff;margin:0 0 16px;overflow:hidden}
  summary{cursor:pointer;padding:12px 16px;font-weight:700;font-size:13.5px;background:#f9fafb}
  details pre{margin:0;padding:14px;border-top:1px solid var(--line);font:12px/1.7 var(--mono);
              white-space:pre-wrap;word-break:break-all;background:#fff}
  table{width:100%;border-collapse:collapse;font:12.5px/1.7 var(--mono);background:#fff}
  th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
  th{background:#f9fafb;color:var(--ink);letter-spacing:.06em;font-weight:700}
  tr:nth-child(even) td{background:#fcfcfd}

  .ft{margin-top:24px;padding-top:14px;border-top:1px solid var(--line);font:11px/1.8 var(--mono);
      color:var(--ink-2);letter-spacing:.14em;display:flex;justify-content:space-between;
      flex-wrap:wrap;gap:6px}
  .ft a{color:var(--ink-2);text-decoration:none;border-bottom:1px solid transparent}
  .ft a:hover{color:var(--o3);border-bottom-color:currentColor}

  /* 登录结果弹窗 */
  .modal-overlay{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;
                 background:rgba(15,23,42,.45);opacity:0;visibility:hidden;
                 transition:opacity .35s ease,visibility .35s ease}
  .modal-overlay.show{opacity:1;visibility:visible}
  .modal{position:relative;overflow:hidden;background:#fff;border-radius:20px;max-width:300px;width:calc(100% - 48px);padding:46px 28px 28px;
         text-align:center;box-shadow:0 24px 64px rgba(0,0,0,.28);
         transform:translateY(30px) scale(.8);transition:transform .5s cubic-bezier(.34,1.56,.64,1)}
  .modal::before{content:"";position:absolute;top:0;left:0;right:0;height:4px;
         background:linear-gradient(90deg,var(--o1),var(--o2),var(--o1));background-size:200% 100%;
         animation:gradientShift 3s ease infinite}
  .modal-overlay.show .modal{transform:translateY(0) scale(1)}
  .modal-overlay.fail.show .modal{animation:modalShake .45s ease .95s}
  @keyframes modalShake{0%,100%{transform:translateX(0)}20%{transform:translateX(-9px)}
                        40%{transform:translateX(9px)}60%{transform:translateX(-6px)}80%{transform:translateX(6px)}}
  .modal-icon{width:76px;height:76px;margin:0 auto 14px}
  .modal-icon svg{width:100%;height:100%;display:block}
  .modal-icon .c{stroke-width:3;fill:none;stroke-dasharray:157;stroke-dashoffset:157;
                 animation:modalStroke .5s cubic-bezier(.65,0,.45,1) forwards .25s}
  .modal-icon.ok .c{stroke:var(--green)}
  .modal-icon.fail .c{stroke:var(--red)}
  .modal-icon .m{stroke-width:3.5;fill:none;stroke-linecap:round;stroke-linejoin:round;
                 stroke-dasharray:48;stroke-dashoffset:48;
                 animation:modalStroke .35s cubic-bezier(.65,0,.45,1) forwards .65s}
  .modal-icon.ok .m{stroke:var(--green)}
  .modal-icon.fail .m{stroke:var(--red);stroke-dasharray:70;stroke-dashoffset:70}
  @keyframes modalStroke{to{stroke-dashoffset:0}}
  .modal-overlay.ok .modal-title{color:var(--green)}
  .modal-overlay.fail .modal-title{color:var(--red)}
  .modal-title{font-size:19px;font-weight:700}
  .modal-btn{margin-top:18px;padding:10px 34px;border:0;border-radius:12px;cursor:pointer;
             font-family:inherit;font-size:14px;font-weight:600;letter-spacing:.5px;color:#fff;
             background:linear-gradient(135deg,#ffb7c5 0,#ff8fa8 100%);
             box-shadow:0 4px 15px rgba(255,183,197,.18);transition:all .3s ease;
             position:relative;overflow:hidden;-webkit-appearance:none;appearance:none}
  .modal-btn::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;
             background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);transition:left .5s ease}
  .modal-btn:hover::before{left:100%}
  .modal-btn:hover{transform:translateY(-2px);box-shadow:0 6px 25px rgba(255,183,197,.3)}
  .modal-btn:active{transform:translateY(0);box-shadow:0 2px 10px rgba(255,143,168,.4)}

  @media (min-width:680px){
    /* 左侧信息栏略宽，保证内容能完整显示 */
    .cols{grid-template-columns:1.15fr .85fr;align-items:stretch;gap:18px}
    .col-plat .platform{height:100%}
    /* 电脑：内容整体上下居中，按钮纵向排列并铺满整行宽度 */
    .col-login{display:flex;flex-direction:column;justify-content:center;min-height:0}
    /* 两个入口按钮：铺满整行（左顶信息栏 → 卡片右边缘） */
    .mbtns{flex:0 0 auto;flex-direction:column;align-items:stretch;width:100%;max-width:none;margin:0}
    .mbtn{flex:0 0 auto;width:100%;min-height:auto}
    /* 无信息栏时（登录类页面）单列铺满 */
    .cols.solo{grid-template-columns:1fr}
    .panel{flex:0 0 auto;width:100%}
  }
  @media (max-width:640px){
    body{padding:24px 14px}
    .card{padding:30px 22px 26px;border-radius:20px}
    .ttl{font-size:24px}
    /* 手机：两个入口按钮并排各占一半，横向留白收窄以防文字换行 */
    .mbtn{padding:13px 12px}
    .frm{grid-template-columns:1fr}
    .frm .lb{text-align:left}
    .row{flex-direction:column}
    .sec{margin-bottom:14px}
    .logo{height:48px;margin-bottom:18px}
  }
  /* 背景图按屏幕方向切换：横屏 ycy / 竖屏 mp */
  @media (orientation:portrait){:root{--bg:url("https://t.alcy.cc/mp")}}
  /* 尊重系统「减少动态效果」设置 */
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
`;

/* -------------------------------- 用户页 --------------------------------- */
/* 站点 Logo（代替文字标题，横纵比 434x120） */
const LOGO_URL = "https://img.107211.xyz/file/img/yP9XFpEh.webp";
function logoImg(alt) {
  return `<img class="logo" src="${LOGO_URL}" width="434" height="120" alt="${esc(alt || SITE_TITLE)}" decoding="async">`;
}
/* 主页：标题 + 左侧信息栏 + 两个跳转按钮 */
async function pgHome(req, env) {
  const url = new URL(req.url);
  const suffix = esc(url.search || "");
  const platform = enrichPlatform(req.headers.get("User-Agent") || "", req);
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${SITE_TITLE}</title>
<style>${CSS}</style>
</head>
<body>
<main class="card card-login">
  ${logoImg()}
  <div class="cols">
    <div class="col-plat">${platformBlock(platform)}</div>
    <div class="col-login">
      <div class="mbtns">
        <a class="mbtn" href="/oauth${suffix}">Oauth</a>
        <a class="mbtn" href="/email${suffix}">Email</a>
      </div>
    </div>
  </div>
</main>
</body>
</html>`;
  return page(html);
}

/* 返回按钮：弹窗内关闭弹窗；否则回到访问前的来源页 / 浏览器后退 / 首页 */
function backHref(req) {
  const url = new URL(req.url);
  const referer = req.headers.get("Referer") || "";
  if (referer) {
    try { if (new URL(referer).origin !== url.origin) return referer; } catch (e) {}
  }
  return "/";
}
function backBar(req) {
  const href = backHref(req);
  const js = "(function(){var a=document.getElementById('mgBack');if(!a)return;" +
    "a.addEventListener('click',function(e){" +
    "e.preventDefault();" +
    "if(window.self!==window.top){try{window.parent.postMessage({type:'oauth-center-close'},'*');}catch(_){}return;}" +
    "if(window.opener&&!window.opener.closed){try{window.close();}catch(_){}return;}" +
    "try{if(document.referrer){var u=new URL(document.referrer);" +
    "if(u.origin!==location.origin){location.href=document.referrer;return;}}}catch(_){}" +
    "if(history.length>1){history.back();return;}" +
    "location.href='/';});})();";
  return '<div class="topbar"><a class="back" id="mgBack" href="' + esc(href) + '">← 返回</a></div>' +
    '<scr' + 'ipt>' + js + '</scr' + 'ipt>';
}

/* Oauth 页：左上返回 + 已配置的登录方式列表 */
async function pgOauth(req, env) {
  const url = new URL(req.url);
  const ref = normalizeRef(url.searchParams.get("ref") || req.headers.get("Referer") || "");
  const provBtns = configuredProviders(env).map(p =>
    // target="_top": 在站内内嵌(iframe)时，第三方提供方页面禁止被框架内嵌，
    // 因此点登录方式一律跳转顶层窗口，保证第三方授权能正常进行
    '<a class="pv" target="_top" href="/auth/' + p.id + (ref ? '?ref=' + encodeURIComponent(ref) : "") +
    '"><span class="lg">' + (PROVIDER_ICONS[p.id] || esc(p.icon)) +
    '</span><span class="nm">' + esc(p.label) + '</span><span class="arr">›</span></a>').join("");
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${SITE_TITLE}</title>
<style>${CSS}</style>
</head>
<body>
<main class="card card-login card-narrow">
  ${backBar(req)}
  ${logoImg()}
  <div class="cols solo">
    <div class="col-login">
      <div class="providers">${provBtns || '<div class="empty">尚未配置任何登录方式</div>'}</div>
    </div>
  </div>
</main>
</body>
</html>`;
  return page(html);
}

/* 邮箱页上下文：校验 redirect、生成验证题与 intent */
async function mailContext(req, env) {
  const cfg = await loadCfg(env);
  const url = new URL(req.url);
  const qs = url.searchParams;
  const redirect = qs.get("redirect") || "";
  const extra = [...qs.entries()].filter(e => e[0] !== "redirect");

  let redUrl = null, host = "独立模式（无来源站点）";
  if (redirect) {
    try { redUrl = new URL(redirect); } catch (e) {
      return { error: page(errPage(cfg, "来源地址无效", "redirect 参数必须是完整的 http(s) 链接，例如 https://example.com/callback")) };
    }
    if (!/^https?:$/.test(redUrl.protocol)) {
      return { error: page(errPage(cfg, "来源地址无效", "仅允许 http / https 链接")) };
    }
    if (!originAllowed(cfg, redUrl)) {
      return { error: page(errPage(cfg, "站点未获授权", "来源站点 " + esc(redUrl.hostname) + " 不在服务台允许列表中，请联系站点管理员处理。")) };
    }
    host = redUrl.host;
  }

  const mode = cfg.turnstileSiteKey && cfg.turnstileSecret ? "turnstile" : "math";
  const cap = mode === "math" ? await newCaptcha(env) : null;
  const intent = await makeIntent(cfg, redirect, extra);

  let capHtml;
  if (mode === "turnstile") {
    /* data-tskey（而非 data-sitekey）避免 api.js 隐式渲染，统一由脚本手动渲染并控制尺寸；
   回调与主题等参数已显式传入 turnstile.render，无需 data-* 属性 */
    capHtml = '<div class="cf-wrap"><div class="cf-turnstile" data-tskey="' + esc(cfg.turnstileSiteKey) + '"></div></div>';
  } else {
    capHtml = '<div class="math"><span class="q" id="capQ">' + esc(cap.q) + ' = ?</span>' +
      '<input id="capA" type="text" inputmode="numeric" autocomplete="off">' +
      '<a href="#" id="capNew">换一题</a></div>' +
      '<input type="hidden" id="capExp" value="' + esc(cap.exp) + '">' +
      '<input type="hidden" id="capSig" value="' + esc(cap.sig) + '">';
  }

  const jsCfg = jss({
    codeLen: parseInt(cfg.codeLength, 10) || 6,
    gap: parseInt(cfg.resendGapSec, 10) || 60,
    mode: mode, host: host, hasGo: !!redUrl
  });
  const tsScript = mode === "turnstile" ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer onload="mgTsApiReady&&mgTsApiReady()"></script>' : "";
  return { cfg, capHtml, intent, jsCfg, tsScript };
}

/* 邮箱页：左上返回 + 邮箱验证码流程 */
async function pgMail(req, env) {
  const m = await mailContext(req, env);
  if (m.error) return m.error;

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${SITE_TITLE}</title>
<style>${CSS}</style>
</head>
<body>
<main class="card card-login card-narrow">
  ${backBar(req)}
  ${logoImg()}
  <div class="cols solo">
    <div class="col-login">
      <section class="step" id="s1">
        <p class="fl" style="margin-bottom:8px">请输入邮箱</p>
        <div class="row">
          <input id="email" type="email" autocomplete="email" spellcheck="false">
          <button class="btn" id="sendBtn" type="button">获取验证码</button>
        </div>
        <div class="cap">${m.capHtml}</div>
        <div class="err" id="e1" hidden></div>
      </section>
      <section class="step" id="s2" hidden>
        <p class="tip"><b id="toMail"></b></p>
        <div class="codes" id="codes"></div>
        <div class="acts">
          <button class="btn" id="okBtn" type="button">确认并返回</button>
          <button class="btn ghost" id="reBtn" type="button" disabled>重新发送</button>
          <a class="lnk" href="#" id="backBtn">← 修改邮箱</a>
        </div>
        <div class="err" id="e2" hidden></div>
      </section>
      <section class="step" id="s3" hidden>
        <div class="status ok"><div class="t">验证通过</div></div>
        <div class="okinfo">
          <p class="oks">已通过邮箱验证：<b id="okMail"></b></p>
          <p class="oks" id="okGo" hidden>正在返回 <b id="okHost"></b> …</p>
          <p class="oks" id="okDone" hidden>登录结果已生成，请返回原页面继续操作。</p>
        </div>
      </section>
    </div>
  </div>
</main>
<input type="hidden" id="intent" value="${esc(m.intent)}">
<script>
var MG = ${m.jsCfg};
var mgTsToken = "";
function mgTsDone(t){ mgTsToken = t; }
function mgTsExp(){ mgTsToken = ""; }
function el(i){ return document.getElementById(i); }
function err(i,m){ var n=el(i); if(!m){ n.hidden=true; n.textContent=""; } else { n.hidden=false; n.textContent="× " + m; } }
function post(u,d){ return fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)}).then(function(r){return r.json();}).catch(function(){return {ok:false,msg:"网络异常，请重试"};}); }
/* 组件按 300×65 自然尺寸手动渲染，依据可用宽度整体等比缩放并居中：
   缩放原点左上 + 缩放后的宽高由脚本预留，任何屏幕（含窄屏竖屏）都完整显示、不裁剪 */
function fitTs(){
  var d=document.querySelector(".cf-turnstile"); if(!d) return;
  var box=d.parentElement; if(!box) return;
  var avail=box.clientWidth; if(avail<=0) return;
  var W=300,H=65, s=Math.min(1,avail/W);
  d.style.transformOrigin="left top";
  d.style.transform = s<1 ? "scale("+s+")" : "";
  d.style.width = Math.round(W*s)+"px";
  d.style.height = Math.round(H*s)+"px";
}
function mgTsMount(){
  if(MG.mode!=="turnstile") return;
  var w=document.querySelector(".cf-turnstile");
  if(!w || typeof turnstile==="undefined") return;
  var ifs=w.querySelectorAll("iframe");
  for(var i=0;i<ifs.length;i++) ifs[i].parentNode.removeChild(ifs[i]);
  turnstile.render(w, { sitekey: w.getAttribute("data-tskey"), callback: mgTsDone, "expired-callback": mgTsExp, theme: "light", size: "normal" });
  fitTs();
}
function mgTsApiReady(){ try{ mgTsMount(); }catch(e){} fitTs(); }
mgTsMount();
if(MG.mode==="turnstile"){
  fitTs();
  window.addEventListener("resize", fitTs, {passive:true});
  window.addEventListener("orientationchange", function(){ setTimeout(fitTs,300); });
  window.addEventListener("load", fitTs);
  setTimeout(fitTs,200); setTimeout(fitTs,1200);
}

var sending = false;
function errSink(){ return el("s1").hidden ? "e2" : "e1"; }
function doSend(){
  if(sending) return;
  err("e1",""); err("e2","");
  var em = el("email");
  if(!em.value.trim() || !em.validity.valid){ err(errSink(),"请填写正确的邮箱地址"); return; }
  var d = { email: em.value.trim(), intent: el("intent").value };
  if(MG.mode === "turnstile"){
    if(!mgTsToken){ err(errSink(),"请先完成人机验证"); return; }
    d.turnstile = mgTsToken;
  } else {
    var a = el("capA").value.trim();
    if(!a){ err(errSink(),"请先回答人机验证题"); return; }
    d.captcha = { ans:a, exp:el("capExp").value, sig:el("capSig").value };
  }
  sending = true;
  var b = el("sendBtn"); b.disabled = true; b.textContent = "发送中…";
  post("/api/send", d).then(function(j){
    sending = false; b.disabled = false; b.textContent = "获取验证码";
    if(!j.ok){
      err(errSink(), j.msg || "发送失败，请稍后再试");
      recaptcha();
      return;
    }
    el("s1").hidden = true;
    el("s2").hidden = false;
    el("toMail").textContent = d.email;
    buildBoxes();
    startGap(j.gap || MG.gap);
    el("codes").firstChild.focus();
    window.scrollTo(0, 0);
  });
}
function makeBox(b){
  b.addEventListener("input", function(){
    var v = b.value;
    var clean = "";
    for(var i=0;i<v.length;i++){ var c = v.charCodeAt(i); if(c>=48 && c<=57) clean += v.charAt(i); }
    b.value = clean.slice(-1);
    if(clean.length>0){
      var n = b.nextSibling;
      while(n && n.nodeType!==1) n = n.nextSibling;
      if(n && n.className==="codebox") n.focus();
      else maybeVerify();
    }
  });
  b.addEventListener("keydown", function(e){
    if(e.key==="Backspace" && !b.value){
      var p = b.previousSibling;
      while(p && p.nodeType!==1) p = p.previousSibling;
      if(p && p.className==="codebox"){ p.value=""; p.focus(); }
    }
  });
  b.addEventListener("focus", function(){ b.select(); });
}
function buildBoxes(){
  var w = el("codes"); w.innerHTML = "";
  for(var i=0;i<MG.codeLen;i++){
    var b = document.createElement("input");
    b.type = "text"; b.className = "codebox"; b.maxLength = "2";
    b.inputMode = "numeric"; b.autocomplete = "off"; b.setAttribute("aria-label","验证码第"+(i+1)+"位");
    makeBox(b); w.appendChild(b);
  }
}
function getCode(){
  var el2 = el("codes").children, s = "";
  for(var i=0;i<el2.length;i++) s += el2[i].value;
  return s;
}
function maybeVerify(){ if(getCode().length === MG.codeLen) verify(); }
function verify(){
  if(sending) return; err("e2","");
  var code = getCode();
  if(code.length !== MG.codeLen){ err("e2","请输入完整的 " + MG.codeLen + " 位验证码"); return; }
  sending = true;
  var b = el("okBtn"); b.disabled = true; b.textContent = "校验中…";
  post("/api/verify", { email: el("email").value.trim(), code: code, intent: el("intent").value }).then(function(j){
    sending = false; b.disabled = false; b.textContent = "确认并返回";
    if(!j.ok){ err("e2", j.msg || "验证失败，请重试"); return; }
    el("s2").hidden = true;
    el("s3").hidden = false;
    el("okMail").textContent = j.email || "";
    window.scrollTo(0,0);
    if(j.url){
      el("okGo").hidden = false;
      el("okHost").textContent = MG.host;
      setTimeout(function(){ location.href = j.url; }, 1300);
    } else {
      el("okDone").hidden = false;
    }
  });
}
var timer = null;
function startGap(s){
  var n = Math.max(1, Math.floor(s));
  var b = el("reBtn"); b.disabled = true; b.textContent = "重新发送(" + n + "s)";
  if(timer) clearInterval(timer);
  timer = setInterval(function(){
    n--;
    if(n<=0){ clearInterval(timer); b.disabled=false; b.textContent="重新发送"; }
    else b.textContent = "重新发送(" + n + "s)";
  }, 1000);
}
function refreshCap(){
  return fetch("/api/captcha").then(function(r){return r.json();}).then(function(j){
    if(!j.ok) return false;
    el("capQ").textContent = j.q + " = ?";
    el("capExp").value = j.exp;
    el("capSig").value = j.sig;
    el("capA").value = "";
    return true;
  }).catch(function(){ return false; });
}
function recaptcha(){
  if(MG.mode === "turnstile"){
    if(typeof turnstile!=="undefined" && turnstile.reset) turnstile.reset();
    mgTsToken = "";
  } else refreshCap();
}
(function(){
  el("sendBtn").addEventListener("click", doSend);
  el("okBtn").addEventListener("click", verify);
  el("reBtn").addEventListener("click", function(){
    err("e2",""); err("e1","");
    el("s2").hidden = true;
    el("s1").hidden = false;
    recaptcha();
    window.scrollTo(0, 0);
    if(MG.mode === "turnstile") el("email").focus();
    else el("capA").focus();
  });
  el("backBtn").addEventListener("click", function(e){
    e.preventDefault();
    el("s2").hidden = true; el("e2").hidden = true;
    el("s1").hidden = false;
    recaptcha();
    el("email").focus();
  });
  var capNew = el("capNew");
  if(capNew) capNew.addEventListener("click", function(e){ e.preventDefault(); refreshCap(); });
})();
</script>
${m.tsScript}
</body>
</html>`;
  return page(html);
}

function errPage(cfg, title, msg) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${esc(title)} · ${SITE_TITLE}</title><style>${CSS}</style>
</head>
<body>
<main class="card card-login">
  <div class="topbar"><a class="back" href="/">← 返回</a></div>
  <h1 class="ttl">${esc(title)}</h1>
  <div class="status fail">${msg}</div>
</main>
</body>
</html>`;
}

/* --------------------------------- 服务台 -------------------------------- */
async function pgAdmin(req, env) {
  const cfg = await loadCfg(env);
  const authed = await requireAdmin(req, env, cfg);
  if (!cfg.adminPw) return page(loginPage(true, req, env));
  if (!authed) return page(loginPage(false, req, env));
  const log = (await kGet(env, LOG_KEY, "json")) || [];
  const kvOn = !!kvOf(env);

  const s = (key) => { /* 单选/文本取值 */
    return cfg[key] == null ? "" : String(cfg[key]);
  };

  const warn = kvOn ? "" : '<div class="warn"><b>警告：</b>未绑定 KV（变量名 STORE），配置与验证码仅保存在内存中，Worker 重启后丢失。请在 Settings → Bindings 添加 KV Namespace。</div>';

  const logHtml = log.length ? '<details><summary>发信记录（' + log.length + ' 条）</summary><table><tr><th>时间</th><th>邮箱</th><th>结果</th><th>备注</th></tr>' +
    log.map(x => '<tr><td>' + new Date(x.t).toLocaleString() + '</td><td>' + esc(x.m) + '</td><td>' + (x.ok ? '成功' : '失败') + '</td><td>' + esc(x.n) + '</td></tr>').join("") + '</table></details>' : '';

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>服务台 · ${esc(cfg.siteName)}</title><style>${CSS}</style>
</head>
<body>
<main class="card card-admin">
   <div class="topbar"><a class="back" href="/">← 返回主页</a><a class="lnk" href="/admin/logout">注销</a></div>
   <div class="brand"><b>MAILGATE</b><span class="st">${kvOn ? "KV 已连接" : "仅内存"}</span></div>
   <h1>服务台 · 发信与验证配置</h1>
  ${warn}

  <div class="step">
    <fieldset class="sec"><legend>01 发信通道 / transport</legend><div class="frm">
      <div class="lb">发送方式<i>send mode</i></div>
      <div><select id="f_sendMode" name="sendMode" onchange="mgMode()">
        <option value="smtp"${s("sendMode")==="smtp"?" selected":""}>SMTP（QQ/163/Gmail 等通用邮箱）</option>
        <option value="resend"${s("sendMode")==="resend"?" selected":""}>Resend API（需已验证域名）</option>
      </select></div>
      ${fld(cfg, "smtpHost", "服务器地址", "smtp host", "smtp.qq.com 等", "g_smtp")}
      ${fld(cfg, "smtpPort", "端口", "port", "465", "g_smtp", "number")}
      <div class="lb grp1"><i>加密方式</i></div>
      <div class="grp1"><select name="smtpSecurity" id="f_smtpSecurity">
        <option value="ssl"${s("smtpSecurity")==="ssl"?" selected":""}>SSL / 隐式 TLS（465）</option>
        <option value="starttls"${s("smtpSecurity")==="starttls"?" selected":""}>STARTTLS（587）</option>
        <option value="plain"${s("smtpSecurity")==="plain"?" selected":""}>不加密</option>
      </select></div>
      ${fld(cfg, "smtpUser", "登录账号", "username", "", "g_smtp")}
      ${fldWo(cfg, "smtpPass", "登录密码 / 授权码", "password", "授权码", "g_smtp")}
      ${fld(cfg, "smtpFrom", "发件地址", "from", "", "", "text")}
      ${fld(cfg, "smtpFromName", "发件人名称", "from name", "", "", "text")}
      ${fldWo(cfg, "resendApiKey", "Resend API Key", "api key", "密钥", "g_resend")}
      <div class="lb grp2"><i>get key</i></div>
      <div class="grp2">
        <a class="lnk" href="https://dashboard.resend.com/api-keys" target="_blank" rel="noopener noreferrer">Resend 控制台 · API Keys ↗</a>
      </div>
    </div></fieldset>

    <fieldset class="sec"><legend>02 验证码规则 / rules</legend><div class="frm">
      ${fld(cfg, "codeLength", "验证码位数", "code length", "", "", "number")}
      ${fld(cfg, "codeTtlSec", "验证码有效期（秒）", "code ttl", "", "", "number")}
      ${fld(cfg, "resendGapSec", "重发间隔（秒）", "resend gap", "", "", "number")}
      ${fld(cfg, "maxTry", "最大尝试次数", "max attempts", "", "", "number")}
      ${fld(cfg, "ticketTtlSec", "返回凭据有效期（秒）", "ticket ttl", "", "", "number")}
    </div></fieldset>

    <fieldset class="sec"><legend>03 页面与邮件 / content</legend><div class="frm">
      ${fld(cfg, "siteName", "站点名称", "site name", "", "", "text")}
      ${fld(cfg, "subject", "邮件主题", "subject", "", "", "text")}
      ${fldTa(cfg, "bodyHtml", "邮件正文（HTML）", "email body", "", 12)}
    </div></fieldset>

    <fieldset class="sec"><legend>04 人机验证 / captcha</legend><div class="frm">
      ${fld(cfg, "turnstileSiteKey", "Turnstile Site Key", "site key", "", "", "text")}
      ${fldWo(cfg, "turnstileSecret", "Turnstile Secret Key", "secret key", "密钥", "")}
    </div></fieldset>

    <fieldset class="sec"><legend>05 返回与安全 / security</legend><div class="frm">
      ${fldTa(cfg, "allowedOrigins", "允许跳转的站点", "allowed origins", "", 4)}
      ${fld(cfg, "hmacSecret", "签名密钥", "hmac secret", "", "", "text")}
      <div class="lb">. <i>生成新密钥</i></div>
      <div><button class="btn ghost sm" id="genBtn" type="button">随机生成密钥</button></div>
    </div></fieldset>

    <fieldset class="sec"><legend>06 管理员 / admin</legend><div class="frm">
      ${fldWo(cfg, "adminPw", "修改管理员密码", "new password", "新密码", "")}
    </div></fieldset>

    <div class="acts">
      <button class="btn" id="saveBtn" type="button">保存设置</button>
      <button class="btn ghost" id="testBtn" type="button" style="margin-left:8px">发送测试邮件</button>
      <input id="testTo" type="email" placeholder="测试收件邮箱" style="max-width:240px">
      <span class="msg" id="msg" hidden></span>
    </div>
  </div>
  <div>${logHtml}</div>
  <footer class="ft"><span><a href="/">用户页</a> · <a href="/admin/logout">退出</a></span></footer>
</main>
<script>
function el(i){ return document.getElementById(i); }
function mgMode(){
  var m = el("f_sendMode").value;
  document.querySelectorAll(".grp1").forEach(function(x){ x.hidden = m !== "smtp"; });
  document.querySelectorAll(".grp2").forEach(function(x){ x.hidden = m !== "resend"; });
}
function fields(){
  var out = {};
  document.querySelectorAll("[name]").forEach(function(e){
    if(e.type === "number") out[e.name] = e.value;
    else out[e.name] = e.value;
  });
  return out;
}
function showMsg(ok, t){
  var m = el("msg"); m.hidden = false; m.className = "msg" + (ok ? "" : " bad");
  m.textContent = t;
}
el("saveBtn").addEventListener("click", function(){
  var b = this; b.disabled = true; showMsg(false, ""); el("msg").hidden = true;
  fetch("/admin/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(fields())})
    .then(function(r){return r.json();})
    .then(function(j){
      b.disabled = false;
      if(j.ok){ showMsg(true, "已保存，正在刷新…"); setTimeout(function(){location.reload();}, 700); }
      else showMsg(false, j.msg || "保存失败");
    }).catch(function(){ b.disabled=false; showMsg(false, "网络异常"); });
});
el("testBtn").addEventListener("click", function(){
  var b = this; var to = el("testTo").value.trim();
  if(!to || !el("testTo").validity.valid){ showMsg(false, "请先填写测试收件邮箱"); return; }
  b.disabled = true;
  fetch("/admin/test",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({to:to})})
    .then(function(r){return r.json();})
    .then(function(j){ b.disabled=false; showMsg(j.ok, j.ok ? ("测试邮件已发出，请查收 " + to) : (j.msg || "发送失败")); })
    .catch(function(){ b.disabled=false; showMsg(false,"网络异常"); });
});
el("genBtn").addEventListener("click", function(){
  var a = new Uint8Array(24); crypto.getRandomValues(a);
  var s = "mg-"; for(var i=0;i<a.length;i++) s += a[i].toString(16).padStart(2,"0");
  el("f_hmacSecret").value = s;
});
mgMode();
</script>
</body>
</html>`;
  return page(html);
}

/* 服务台表单控件（普通 / 只写 / 文本域） */
function fld(cfg, key, label, en, ph, grp, type, hint) {
  const v = String(cfg[key] == null ? "" : cfg[key]);
  const g = grp === "g_smtp" ? "grp1" : (grp === "g_resend" ? "grp2" : "");
  return fldRaw(key, label, en, v, ph, g, type || "text", hint);
}
function fldWo(cfg, key, label, en, ph, grp) {
  const g = grp === "g_smtp" ? "grp1" : (grp === "g_resend" ? "grp2" : "");
  const set = cfg[key] ? ph + "（已保存）" : ph + "（未设置）";
  return fldRaw(key, label, en, "", set, g, "password", "");
}
function fldTa(cfg, key, label, en, hint, rows) {
  const v = String(cfg[key] == null ? "" : cfg[key]);
  return '<div class="lb">' + label + '<i>' + en + '</i></div><div><textarea name="' + key + '" rows="' + rows + '">' + esc(v) + '</textarea>' + (hint ? '<div class="hint">' + esc(hint) + '</div>' : "") + '</div>';
}
function fldRaw(key, label, en, v, ph, cls, type, hint) {
  return '<div class="lb ' + cls + '">' + label + '<i>' + en + '</i></div><div class="' + cls + '"><input id="f_' + key + '" name="' + key + '" type="' + (type || "text") + '" value="' + esc(v) + '"' +
    (ph ? ' placeholder="' + esc(ph) + '"' : "") + '>' + (hint ? '<div class="hint">' + esc(hint) + '</div>' : "") + '</div>';
}

function loginPage(setup, req, env) {
  const vcheck = setup
    ? '  if(pw.length < 6){ var e1=document.getElementById("e0"); e1.hidden=false; e1.textContent="× 密码至少 6 位"; return; }\n' +
      '  var pw2 = document.getElementById("pw2").value;\n' +
      '  if(pw !== pw2){ var e2=document.getElementById("e0"); e2.hidden=false; e2.textContent="× 两次输入的密码不一致"; return; }\n' +
      '  d.pw2 = pw2;'
    : "";
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${setup ? "初始化服务台" : "服务台登录"} · MAILGATE</title><style>${CSS}</style>
</head>
<body>
<main class="card card-login card-narrow">
  <div class="topbar"><a class="back" href="/">← 返回主页</a></div>
  <div class="brand"><b>MAILGATE</b></div>
  <h1>${setup ? "初始化服务台" : "服务台登录"}</h1>
  <div class="cols solo">
    <div class="col-login">
      <div class="err" id="e0" hidden></div>
      <form id="lf">
        <label class="fl" for="un">账号</label>
        <input type="text" id="un" autocomplete="${setup ? "new-username" : "username"}" spellcheck="false">
        <label class="fl" for="pw">密码</label>
        <input type="password" id="pw" autocomplete="${setup ? "new-password" : "current-password"}">
        ${setup ? '<label class="fl" for="pw2">确认密码</label><input type="password" id="pw2" autocomplete="new-password">' : ""}
        <button class="btn" type="submit">${setup ? "创建并进入" : "登录"}</button>
      </form>
    </div>
  </div>
</main>
<script>

document.getElementById("lf").addEventListener("submit", function(e){
  e.preventDefault();
  var un = document.getElementById("un").value.trim();
  var pw = document.getElementById("pw").value;
  var d = { un: un, pw: pw };
${vcheck}
  fetch("/admin/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)})
    .then(function(r){return r.json();})
    .then(function(j){
      if(j.ok){ location.href = "/admin"; }
      else { var e9=document.getElementById("e0"); e9.hidden=false; e9.textContent="× " + (j.msg || "登录失败"); }
    });
});
</script>
</body>
</html>`;
}

async function requireAdmin(req, env, cfg) {
  const ck = cookieOf(req, "mg_adm");
  if (!ck) return null;
  const p = ck.split(".");
  if (p.length !== 2) return null;
  const exp = parseInt(p[0], 10);
  if (!exp || exp < Date.now()) return null;
  const s = await sign(cfg.hmacSecret, "adm|" + exp);
  return eqStr(s, p[1]) ? cfg : null;
}
function sessCookie(secret) {
  const exp = Date.now() + SESS_MAX_AGE * 1000;
  return sign(secret, "adm|" + exp).then(sig => "mg_adm=" + exp + "." + sig + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=" + SESS_MAX_AGE);
}
async function adLogin(req, env) {
  const cfg = await loadCfg(env);
  const body = await readJson(req);
  const un = String(body.un || "").trim();
  const pw = String(body.pw || "");
  if (!cfg.adminUser) cfg.adminUser = "admin";
  if (!cfg.adminPw) {
    if (un.length < 3) return json({ ok: false, msg: "账号至少 3 位" });
    if (pw.length < 6) return json({ ok: false, msg: "密码至少 6 位" });
    if (pw !== String(body.pw2 || "")) return json({ ok: false, msg: "两次输入的密码不一致" });
    cfg.adminUser = un || "admin";
    cfg.adminPw = await hashPw(pw);
    await saveCfg(env, cfg);
    const r = new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
    r.headers.append("Set-Cookie", await sessCookie(cfg.hmacSecret));
    return r;
  }
  const adminUser = cfg.adminUser || "admin";
  if (un !== adminUser) return json({ ok: false, msg: "账号或密码错误" });
  if (!(await checkPw(cfg, pw))) return json({ ok: false, msg: "账号或密码错误" });
  const r = new Response(JSON.stringify({ ok: true }), { headers: { "Content-Type": "application/json" } });
  r.headers.append("Set-Cookie", await sessCookie(cfg.hmacSecret));
  return r;
}
function adLogout() {
  return new Response("<script>location.href='/'</script>", {
    status: 302, headers: { Location: "/", "Set-Cookie": "mg_adm=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax" }
  });
}
async function adSave(req, env) {
  const cfg = await loadCfg(env);
  if (!(await requireAdmin(req, env, cfg))) return json({ ok: false, msg: "未登录或登录已过期" }, 401);
  const body = await readJson(req);
  /* adminPw 不在 DEF 中，需单独处理（否则永远存不进去） */
  if ("adminPw" in body) {
    const v = String(body.adminPw || "").trim();
    if (v) {
      if (v.length < 6) return json({ ok: false, msg: "新密码至少 6 位" });
      cfg.adminPw = await hashPw(v);
    }
  }
  for (const k of Object.keys(DEF)) {
    if (!(k in body)) continue;
    if (WRITE_ONLY.includes(k) && (body[k] == null || String(body[k]) === "")) continue; /* 留空 = 不变 */
    const v = String(body[k] == null ? "" : body[k]).trim();
    if (k === "codeLength") { const n = parseInt(v, 10); if (!(n >= 4 && n <= 8)) return json({ ok: false, msg: "验证码位数需在 4 – 8 之间" }); cfg[k] = String(n); continue; }
    if (k === "codeTtlSec" || k === "ticketTtlSec") { const n = parseInt(v, 10) || 300; cfg[k] = String(Math.min(3600, Math.max(60, n))); continue; }
    if (k === "resendGapSec") { const n = parseInt(v, 10) || 60; cfg[k] = String(Math.min(600, Math.max(15, n))); continue; }
    if (k === "maxTry") { const n = parseInt(v, 10) || 5; cfg[k] = String(Math.min(10, Math.max(1, n))); continue; }
    if (k === "smtpPort") { const n = parseInt(v, 10) || 465; cfg[k] = String(n); continue; }
    if (k === "smtpFrom" && v && !isEmail(v)) return json({ ok: false, msg: "发件地址格式不正确（需形如 no-reply@example.com）" });
    cfg[k] = v;
  }
  await saveCfg(env, cfg);
  return json({ ok: true });
}
async function adTest(req, env) {
  const cfg = await loadCfg(env);
  if (!(await requireAdmin(req, env, cfg))) return json({ ok: false, msg: "未登录或登录已过期" }, 401);
  const body = await readJson(req);
  const to = String(body.to || "").trim().toLowerCase();
  if (!isEmail(to)) return json({ ok: false, msg: "测试邮箱格式不正确" });
  const code = genCode(parseInt(cfg.codeLength, 10) || 6);
  const vars = {
    site: cfg.siteName, email: to, code: code,
    minutes: Math.max(1, Math.round((parseInt(cfg.codeTtlSec, 10) || 300) / 60))
  };
  try {
    await deliver(cfg, to, fill(cfg.subject, vars), fill(cfg.bodyHtml, Object.assign({}, vars, { email: esc(to) })));
    await addLog(env, to, 1, "test");
    return json({ ok: true });
  } catch (e) {
    await addLog(env, to, 0, "test:" + ((e && e.message) || e));
    return json({ ok: false, msg: "发送失败：" + ((e && e.message) || e) }, 502);
  }
}

/* ---------------------------------- API --------------------------------- */
async function apiCaptcha(req, env) {
  const d = await newCaptcha(env);
  return json(Object.assign({ ok: true }, d));
}
async function apiSend(req, env) {
  const cfg = await loadCfg(env);
  const body = await readJson(req);
  const email = String(body.email || "").trim().toLowerCase();
  if (!isEmail(email)) return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  /* 校验签名 intent：确保 redirect 已通过来源站白名单，直接打 API 也无法绕过 */
  const intent = await openIntent(cfg, body.intent);
  if (!intent) return json({ ok: false, msg: "页面已失效，请刷新后重新操作" }, 400);
  const ip = req.headers.get("cf-connect-ip") || req.headers.get("x-forwarded-for") || "local";

  const cap = await verifyCaptcha(env, cfg, body, ip);
  if (!cap.ok) return json({ ok: false, msg: cap.msg }, 403);

  const gap = parseInt(cfg.resendGapSec, 10) || 60;
  const gk = "gap:" + await sha256hex(email);
  const gExp = parseInt(await kGet(env, gk), 10);
  if (gExp && gExp > Date.now()) {
    return json({ ok: false, msg: "发送过于频繁，请 " + Math.ceil((gExp - Date.now()) / 1000) + " 秒后再试" }, 429);
  }
  const ik = "ip:" + await sha256hex(ip);
  const cnt = parseInt(await kGet(env, ik) || "0", 10);
  if (cnt >= 20) return json({ ok: false, msg: "当前 IP 发送次数已达上限（每小时 20 封）" }, 429);

  const ttl = Math.min(3600, Math.max(60, parseInt(cfg.codeTtlSec, 10) || 300));
  const code = genCode(parseInt(cfg.codeLength, 10) || 6);
  try { if (globalThis.__MG_ONCODE) globalThis.__MG_ONCODE(code); } catch (e) {}
  const vars = { site: String(cfg.siteName || ""), email: email, code: code, minutes: Math.round(ttl / 60) };
  try {
    /* 主题为纯文本、正文为 HTML：正文中的邮箱需转义，防模板注入 */
    await deliver(cfg, email, fill(cfg.subject, vars), fill(cfg.bodyHtml, Object.assign({}, vars, { email: esc(email) })));
  } catch (e) {
    await addLog(env, email, 0, (e && e.message) || String(e));
    return json({ ok: false, msg: "发信失败：" + ((e && e.message) || e) }, 502);
  }
  await kPut(env, codeKey(email), JSON.stringify({
    h: await sha256hex(code + "|" + email), e: Date.now() + ttl * 1000, n: 0, u: 0
  }), ttl + 60);
  await kPut(env, gk, String(Date.now() + gap * 1000), gap + 60);
  await kPut(env, ik, String(cnt + 1), 3600);
  await addLog(env, email, 1, "sent");
  return json({ ok: true, gap: gap, ttl: Math.round(ttl / 60) });
}
async function apiVerify(req, env) {
  const cfg = await loadCfg(env);
  const body = await readJson(req);
  const email = String(body.email || "").trim().toLowerCase();
  const code = String(body.code || "").replace(/\s+/g, "");
  const len = parseInt(cfg.codeLength, 10) || 6;
  if (!isEmail(email)) return json({ ok: false, msg: "邮箱格式不正确" }, 400);
  if (!/^\d+$/.test(code) || code.length !== len) return json({ ok: false, msg: "验证码格式不正确" }, 400);
  const intent = await openIntent(cfg, body.intent);
  if (!intent) return json({ ok: false, msg: "页面已失效，请刷新后重新操作" }, 400);

  const rec = await kGet(env, codeKey(email), "json");
  if (!rec) return json({ ok: false, msg: "验证码不存在或已过期，请重新获取" }, 400);
  if (rec.u) return json({ ok: false, msg: "该验证码已被使用，请重新获取" }, 400);
  if (rec.e < Date.now()) { await kDel(env, codeKey(email)); return json({ ok: false, msg: "验证码已过期，请重新获取" }, 400); }
  const maxTry = parseInt(cfg.maxTry, 10) || 5;
  if (rec.n >= maxTry) { await kDel(env, codeKey(email)); return json({ ok: false, msg: "尝试次数过多，验证码已作废" }, 429); }

  const h = await sha256hex(code + "|" + email);
  if (!eqStr(h, rec.h)) {
    rec.n = (rec.n || 0) + 1;
    if (rec.n >= maxTry) {
      await kDel(env, codeKey(email));
      return json({ ok: false, msg: "验证码错误次数过多，验证码已作废，请重新获取" }, 429);
    }
    await kPut(env, codeKey(email), JSON.stringify(rec), Math.max(60, Math.ceil((rec.e - Date.now()) / 1000) + 60));
    return json({ ok: false, msg: "验证码错误，还可尝试 " + Math.max(0, maxTry - rec.n) + " 次" }, 400);
  }
  rec.u = 1;
  await kPut(env, codeKey(email), JSON.stringify(rec), Math.max(60, Math.ceil((rec.e - Date.now()) / 1000) + 60));
  await addLog(env, email, 1, "verified");

  const ret = await buildReturn(cfg, intent, email);
  if (!ret) {
    /* 独立模式（无 redirect）：同样遵循服务台的 ticketTtlSec 设置 */
    const now = Date.now();
    const exp = String(now + (parseInt(cfg.ticketTtlSec, 10) || 600) * 1000);
    return json({ ok: true, email: email, ticket: await makeTicket(cfg, email, String(now), exp), url: null });
  }
  return json({ ok: true, email: email, ticket: ret.ticket, url: ret.url });
}
async function apiCheck(req, env) {
  const cfg = await loadCfg(env);
  const u = new URL(req.url);
  const t = u.searchParams.get("ticket");
  const r = await checkTicket(cfg, t);
  if (!r) return json({ ok: false, msg: "ticket 无效或已过期" }, 400);
  return json({ ok: true, email: r.email, ts: r.ts, exp: r.exp });
}

function pg404() {
  return page(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>404 · ${SITE_TITLE}</title><style>${CSS}</style></head><body><main class="card card-login"><div class="topbar"><a class="back" href="/">← 返回</a></div><h1 class="ttl">404</h1></main></body></html>`, 404);
}

/* ============================ OAuth 登录模块 ============================
 * 自 platform-oauth-login 合并：10 种第三方登录 + 平台检测 + 会话。
 * env.SECRET 缺省时回退到服务台签名密钥（cfg.hmacSecret）。
 * 路由：/auth/:provider  /callback/:provider  /me  /logout
 *       /api/platform  /api/providers  /api/status  /api/logs
 * 可选 KV 绑定 LOG_KV 记录登录历史。
 * ====================================================================== */

async function mgSecret(env) {
  if (env && env.SECRET) return String(env.SECRET);
  const cfg = await loadCfg(env);
  return cfg.hmacSecret;
}

function detectDevice(ua = '') {
  const u = String(ua || '').toLowerCase();
  if (u.includes('iphone')) return 'iPhone';
  if (u.includes('ipad')) return 'iPad';
  if (u.includes('windows phone')) return 'Windows Phone';
  if (u.includes('android')) {
    const m = /\(([^)]*)\)/.exec(ua);
    if (m) {
      const segs = m[1].split(';').map((s) => s.trim()).filter(Boolean);
      for (const seg of segs) {
        const low = seg.toLowerCase();
        if (low.length < 3) continue;
        if (/^[a-z]{2}(-[a-z]{2})?$/.test(low)) continue; // 语言标记 zh-cn / en
        if (/^(linux|android|build|version|wv|mobile|webkit|khtml|like|gecko|opera|mqq|qq|micromessenger|wechat|dingtalk|baiduboxapp|aweme|micro|desktop|tablet|phone|sdk|release)/.test(low)) continue;
        return seg.replace(/\s+build\/.*$/i, '').trim(); // 去掉 " Build/xxx"
      }
      const brands = [['xiaomi', '小米'], ['redmi', '红米'], ['huawei', '华为'], ['honor', '荣耀'], ['oppo', 'OPPO'], ['vivo', 'vivo'], ['oneplus', '一加'], ['realme', '真我'], ['meizu', '魅族'], ['pixel', 'Pixel'], ['samsung', '三星'], ['sony', '索尼'], ['google', 'Google']];
      for (const [k, v] of brands) {
        if (u.includes(k)) return v;
      }
    }
    return 'Android 设备';
  }
  if (/windows/.test(u) && !/windows phone/.test(u)) return 'PC';
  if (/mac os x|macintosh/.test(u)) return 'Mac';
  if (/linux|ubuntu|debian|fedora|centos/.test(u)) return 'Linux';
  return '—';
}

function detectPlatform(ua = '') {
  const u = ua.toLowerCase();
  const p = { ua, os: 'unknown', app: null, browser: 'unknown', category: 'unknown', label: '未知平台', device: detectDevice(ua) };

  // 内嵌环境（优先，其 UA 也含系统信息）
  if (u.includes('micromessenger')) { p.app = 'wechat'; p.browser = 'wechat'; p.category = 'app'; p.label = '微信内置浏览器'; }
  else if (u.includes('dingtalk')) { p.app = 'dingtalk'; p.browser = 'dingtalk'; p.category = 'app'; p.label = '钉钉内置浏览器'; }
  else if (u.includes('qq/') || u.includes('qqbrowser') || u.includes('mqqbrowser')) { p.app = 'qq'; p.browser = 'qq'; p.category = 'app'; p.label = 'QQ / QQ浏览器'; }
  else if (u.includes('xhs_') || u.includes('xhs/')) { p.app = 'xiaohongshu'; p.browser = 'xiaohongshu'; p.category = 'app'; p.label = '小红书 App'; }
  else if (u.includes('aweme') || u.includes('bytedance')) { p.app = 'douyin'; p.browser = 'douyin'; p.category = 'app'; p.label = '抖音 / 字节系 App'; }
  else if (u.includes('weibo')) { p.app = 'weibo'; p.browser = 'weibo'; p.category = 'app'; p.label = '微博 App'; }
  else if (u.includes('baiduboxapp')) { p.app = 'baidu'; p.browser = 'baidu'; p.category = 'app'; p.label = '百度 App'; }
  else if (u.includes('xiaomi')) { p.app = 'xiaomi'; p.browser = 'xiaomi'; p.category = 'app'; p.label = '小米浏览器'; }

  // 操作系统
  if (/windows/.test(u) && !/windows phone/.test(u)) { p.os = 'windows'; if (!p.app) p.label = 'Windows PC'; }
  else if (u.includes('windows phone')) { p.os = 'windows-phone'; if (!p.app) p.label = 'Windows Phone'; }
  else if (/iphone|ipad|ipod|ios/.test(u)) { p.os = 'ios'; if (!p.app) p.label = 'iPhone / iPad'; }
  else if (u.includes('android')) { p.os = 'android'; if (!p.app) p.label = 'Android 设备'; }
  else if (u.includes('mac os x') || u.includes('macintosh')) { p.os = 'macos'; if (!p.app) p.label = 'macOS'; }
  else if (/linux|ubuntu|debian|fedora|centos/.test(u)) { p.os = 'linux'; if (!p.app) p.label = 'Linux'; }

  // 浏览器
  if (!p.app) {
    if (u.includes('edg/')) { p.browser = 'edge'; p.label = `${p.label} · Edge`; }
    else if (u.includes('chrome') && !u.includes('chromium')) { p.browser = 'chrome'; p.label = `${p.label} · Chrome`; }
    else if (u.includes('firefox')) { p.browser = 'firefox'; p.label = `${p.label} · Firefox`; }
    else if (u.includes('safari') && u.includes('applewebkit')) { p.browser = 'safari'; p.label = `${p.label} · Safari`; }
  }

  if (p.category === 'unknown') {
    if (p.app) p.category = 'app';
    else if (p.os === 'windows' || p.os === 'macos' || p.os === 'linux') p.category = 'desktop';
    else if (p.os === 'android' || p.os === 'ios' || p.os === 'windows-phone') p.category = 'mobile';
    else p.category = 'other';
  }
  if (p.app && p.os !== 'unknown') p.label = `${p.label} · ${osLabel(p.os)}`;
  return p;
}

function osLabel(os) {
  return ({ windows: 'Windows', 'windows-phone': 'Windows Phone', ios: 'iOS', android: 'Android', macos: 'macOS', linux: 'Linux', unknown: '' })[os] || os;
}

function enrichPlatform(ua, request) {
  const platform = detectPlatform(ua);
  const cf = request.cf || {};
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-real-ip') || '未知';
  platform.ip = ip;
  platform.country = cf.country || '—';
  platform.city = cf.city || '—';
  platform.region = cf.region || '—';
  platform.timezone = cf.timezone || '—';
  platform.asn = cf.asn ? 'AS' + cf.asn : '—';
  platform.colo = cf.colo || '—';
  platform.httpProtocol = cf.httpProtocol || '—';
  platform.tlsVersion = cf.tlsVersion || '—';
  return platform;
}

function microsoftTenant(env) {
  return String(env.MICROSOFT_TENANT || 'common').trim() || 'common';
}

const PROVIDERS = {
  google: {
    label: 'Google', color: '#4285F4', icon: 'G',
    scope: 'openid email profile',
    authUrl: () => 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: () => 'https://oauth2.googleapis.com/token',
    userInfoUrl: () => 'https://www.googleapis.com/oauth2/v3/userinfo',
    clientId: (env) => env.GOOGLE_CLIENT_ID,
    authExtra: () => ({ response_type: 'code', prompt: 'select_account' }),
    tokenParams: (env, code, redirect) => ({
      client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code',
    }),
    extract: (info) => ({ username: '', name: info.name || info.email || '未知用户', email: info.email || '', avatar: info.picture || '' }),
  },

  github: {
    label: 'GitHub', color: '#24292F', icon: 'GH',
    scope: 'read:user user:email',
    authUrl: () => 'https://github.com/login/oauth/authorize',
    tokenUrl: () => 'https://github.com/login/oauth/access_token',
    userInfoUrl: () => 'https://api.github.com/user',
    clientId: (env) => env.GITHUB_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenHeaders: () => ({ Accept: 'application/json' }),
    tokenParams: (env, code, redirect) => ({
      client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET,
      code, redirect_uri: redirect,
    }),
    extract: (info) => ({ username: info.login || '', name: info.name || info.login || '未知用户', email: info.email || '', avatar: info.avatar_url || '' }),
  },

  microsoft: {
    label: 'Microsoft', color: '#00A4EF', icon: 'MS',
    scope: 'openid email profile User.Read',
    pkce: true,
    authUrl: (env) => `https://login.microsoftonline.com/${microsoftTenant(env)}/oauth2/v2.0/authorize`,
    tokenUrl: (env) => `https://login.microsoftonline.com/${microsoftTenant(env)}/oauth2/v2.0/token`,
    userInfoUrl: () => 'https://graph.microsoft.com/oidc/userinfo',
    clientId: (env) => env.MICROSOFT_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenHeaders: () => ({ Accept: 'application/json' }),
    tokenParams: (env, code, redirect, verifier) => ({
      client_id: env.MICROSOFT_CLIENT_ID, client_secret: env.MICROSOFT_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code', code_verifier: verifier,
      scope: 'openid email profile User.Read',
    }),
    extract: (info) => {
      const msaEmail = info.preferred_username && String(info.preferred_username).includes('@') ? info.preferred_username : '';
      return { username: '', name: info.name || msaEmail || '未知用户', email: info.email || msaEmail || '', avatar: '' };
    },
  },

  /* 独立个人账户通道：固定 /consumers 租户，只认「仅限个人账户」的应用。
   * 配置 MICROSOFT_MSA_CLIENT_ID / MICROSOFT_MSA_CLIENT_SECRET 后自动出现在登录页。 */
  microsoft_msa: {
    label: 'Microsoft 个人账户', color: '#00A4EF', icon: 'MS',
    scope: 'openid email profile User.Read',
    pkce: true,
    authUrl: () => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize',
    tokenUrl: () => 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token',
    userInfoUrl: () => 'https://graph.microsoft.com/oidc/userinfo',
    clientId: (env) => env.MICROSOFT_MSA_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenHeaders: () => ({ Accept: 'application/json' }),
    tokenParams: (env, code, redirect, verifier) => ({
      client_id: env.MICROSOFT_MSA_CLIENT_ID, client_secret: env.MICROSOFT_MSA_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code', code_verifier: verifier,
      scope: 'openid email profile User.Read',
    }),
    extract: (info) => {
      const msaEmail = info.preferred_username && String(info.preferred_username).includes('@') ? info.preferred_username : '';
      return { username: '', name: info.name || msaEmail || '未知用户', email: info.email || msaEmail || '', avatar: '' };
    },
  },

  twitter: {
    label: 'Twitter / X', color: '#1DA1F2', icon: 'X',
    scope: 'tweet.read users.read offline.access',
    pkce: true,
    authUrl: () => 'https://twitter.com/i/oauth2/authorize',
    tokenUrl: () => 'https://api.twitter.com/2/oauth2/token',
    userInfoUrl: () => 'https://api.twitter.com/2/users/me?user.fields=profile_image_url',
    clientId: (env) => env.TWITTER_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenParams: (env, code, redirect, verifier) => ({
      client_id: env.TWITTER_CLIENT_ID, client_secret: env.TWITTER_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code', code_verifier: verifier,
    }),
    extract: (info) => {
      const d = info && info.data ? info.data : {};
      return { username: d.username || '', name: d.name || d.username || '未知用户', email: '', avatar: (d.profile_image_url || '').replace('_normal', '_400x400') };
    },
  },

  gitlab: {
    label: 'GitLab', color: '#FC6D26', icon: 'GL',
    scope: 'read_user',
    authUrl: () => 'https://gitlab.com/oauth/authorize',
    tokenUrl: () => 'https://gitlab.com/oauth/token',
    userInfoUrl: () => 'https://gitlab.com/api/v4/user',
    clientId: (env) => env.GITLAB_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenParams: (env, code, redirect) => ({
      client_id: env.GITLAB_CLIENT_ID, client_secret: env.GITLAB_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code',
    }),
    extract: (info) => ({ username: info.username || '', name: info.name || info.username || '未知用户', email: info.email || info.public_email || '', avatar: info.avatar_url || '' }),
  },

  discord: {
    label: 'Discord', color: '#5865F2', icon: 'DC',
    scope: 'identify email',
    authUrl: () => 'https://discord.com/oauth2/authorize',
    tokenUrl: () => 'https://discord.com/api/oauth2/token',
    userInfoUrl: () => 'https://discord.com/api/users/@me',
    clientId: (env) => env.DISCORD_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenHeaders: () => ({ Accept: 'application/json' }),
    tokenParams: (env, code, redirect) => ({
      client_id: env.DISCORD_CLIENT_ID, client_secret: env.DISCORD_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code',
    }),
    extract: (info) => ({
      username: info.username || '',
      name: info.global_name || info.username || '未知用户',
      email: info.email || '',
      avatar: (info.id && info.avatar) ? `https://cdn.discordapp.com/avatars/${info.id}/${info.avatar}.png?size=128` : '',
    }),
  },

  wechat: {
    label: '微信扫码', color: '#07C160', icon: '微',
    scope: 'snsapi_login',
    authUrl: () => 'https://open.weixin.qq.com/connect/qrconnect',
    tokenUrl: () => 'https://api.weixin.qq.com/sns/oauth2/access_token',
    clientId: (env) => env.WECHAT_APP_ID,
    tokenMethod: 'GET',
    userInfoAuth: 'query',
    authHash: '#wechat_redirect',
    authExtra: () => ({ response_type: 'code' }),
    tokenParams: (env, code, redirect) => ({
      appid: env.WECHAT_APP_ID, secret: env.WECHAT_APP_SECRET,
      code, grant_type: 'authorization_code',
    }),
    identity: async (env, token) => ({ openid: token.openid }),
    userInfoUrl: (env, token, extra) =>
      `https://api.weixin.qq.com/sns/userinfo?access_token=${encodeURIComponent(token.access_token)}&openid=${encodeURIComponent(extra.openid)}&lang=zh_CN`,
    extract: (info) => ({ username: info.nickname || '', name: info.nickname || '微信用户', email: '', avatar: info.headimgurl || '' }),
  },

  weibo: {
    label: '微博', color: '#E6162D', icon: '博',
    scope: '',
    authUrl: () => 'https://api.weibo.com/oauth2/authorize',
    tokenUrl: () => 'https://api.weibo.com/oauth2/access_token',
    clientId: (env) => env.WEIBO_CLIENT_ID,
    authExtra: () => ({ response_type: 'code' }),
    tokenHeaders: () => ({ Accept: 'application/json' }),
    tokenParams: (env, code, redirect) => ({
      client_id: env.WEIBO_CLIENT_ID, client_secret: env.WEIBO_CLIENT_SECRET,
      code, redirect_uri: redirect, grant_type: 'authorization_code',
    }),
    identity: async (env, token) => ({ uid: token.uid }),
    userInfoUrl: (env, token, extra) =>
      `https://api.weibo.com/2/users/show.json?access_token=${encodeURIComponent(token.access_token)}&uid=${encodeURIComponent(extra.uid)}`,
    extract: (info) => ({ username: info.screen_name || '', name: info.screen_name || info.name || '微博用户', email: '', avatar: (info.avatar_large || info.profile_image_url || '') }),
  },

  qq: {
    label: 'QQ', color: '#12B7F5', icon: 'Q',
    scope: 'get_user_info',
    authUrl: () => 'https://graph.qq.com/oauth2.0/authorize',
    tokenUrl: () => 'https://graph.qq.com/oauth2.0/token',
    clientId: (env) => env.QQ_APP_ID,
    tokenMethod: 'GET',
    tokenParse: 'form',
    userInfoAuth: 'query',
    authExtra: () => ({ response_type: 'code' }),
    tokenParams: (env, code, redirect) => ({
      grant_type: 'authorization_code',
      client_id: env.QQ_APP_ID, client_secret: env.QQ_APP_SECRET,
      code, redirect_uri: redirect,
    }),
    identity: async (env, token) => {
      const res = await fetch(`https://graph.qq.com/oauth2.0/me?fmt=json&access_token=${encodeURIComponent(token.access_token)}`);
      const data = await res.json();
      if (!data.openid) throw new Error('获取 QQ openid 失败');
      return { openid: data.openid };
    },
    userInfoUrl: (env, token, extra) =>
      `https://graph.qq.com/user/get_user_info?access_token=${encodeURIComponent(token.access_token)}&oauth_consumer_key=${encodeURIComponent(env.QQ_APP_ID)}&openid=${encodeURIComponent(extra.openid)}`,
    extract: (info) => ({ username: info.nickname || '', name: info.nickname || 'QQ用户', email: '', avatar: (info.figureurl_qq_2 || info.figureurl_qq_1 || '') }),
  },
};

function configuredProviders(env) {
  return Object.entries(PROVIDERS)
    .filter(([_, p]) => p.clientId(env))
    .map(([key, p]) => ({ id: key, label: p.label, color: p.color, icon: p.icon, pkce: !!p.pkce }));
}

/* 各 provider 对应 Secret 环境变量名（用于体检识别） */
const SECRET_VARS = {
  google: 'GOOGLE_CLIENT_SECRET',
  github: 'GITHUB_CLIENT_SECRET',
  microsoft: 'MICROSOFT_CLIENT_SECRET',
  microsoft_msa: 'MICROSOFT_MSA_CLIENT_SECRET',
  twitter: 'TWITTER_CLIENT_SECRET',
  gitlab: 'GITLAB_CLIENT_SECRET',
  discord: 'DISCORD_CLIENT_SECRET',
  wechat: 'WECHAT_APP_SECRET',
  weibo: 'WEIBO_CLIENT_SECRET',
  qq: 'QQ_APP_SECRET',
};

/* 各 provider 对应的官方品牌图标（内联 SVG，viewBox 0 0 24 24，品牌色） */
const PROVIDER_ICONS = {
  google: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>',
  github: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#181717"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>',
  microsoft: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="11" height="11" fill="#F25022"/><rect x="12" y="1" width="11" height="11" fill="#7FBA00"/><rect x="1" y="12" width="11" height="11" fill="#00A4EF"/><rect x="12" y="12" width="11" height="11" fill="#FFB900"/></svg>',
  microsoft_msa: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><rect x="1" y="1" width="11" height="11" fill="#F25022"/><rect x="12" y="1" width="11" height="11" fill="#7FBA00"/><rect x="1" y="12" width="11" height="11" fill="#00A4EF"/><rect x="12" y="12" width="11" height="11" fill="#FFB900"/></svg>',
  twitter: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#000000"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>',
  gitlab: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#FC6D26"><path d="m23.6004 9.5927-.0337-.0862L20.3.9814a.851.851 0 0 0-.3362-.405.8748.8748 0 0 0-.9997.0539.8748.8748 0 0 0-.29.4399l-2.2055 6.748H7.5375l-2.2057-6.748a.8573.8573 0 0 0-.29-.4412.8748.8748 0 0 0-.9997-.0537.8585.8585 0 0 0-.3362.4049L.4332 9.5015l-.0325.0862a6.0657 6.0657 0 0 0 2.0119 7.0105l.0113.0087.03.0213 4.976 3.7264 2.462 1.8633 1.4995 1.1321a1.0085 1.0085 0 0 0 1.2197 0l1.4995-1.1321 2.4619-1.8633 5.006-3.7489.0125-.01a6.0682 6.0682 0 0 0 2.0094-7.003z"/></svg>',
  discord: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#5865F2"><path d="M20.317 4.3698a19.7913 19.7913 0 00-4.8851-1.5152.0741.0741 0 00-.0785.0371c-.211.3753-.4447.8648-.6083 1.2495-1.8447-.2762-3.68-.2762-5.4868 0-.1636-.3933-.4058-.8742-.6177-1.2495a.077.077 0 00-.0785-.037 19.7363 19.7363 0 00-4.8852 1.515.0699.0699 0 00-.0321.0277C.5334 9.0458-.319 13.5799.0992 18.0578a.0824.0824 0 00.0312.0561c2.0528 1.5076 4.0413 2.4228 5.9929 3.0294a.0777.0777 0 00.0842-.0276c.4616-.6304.8731-1.2952 1.226-1.9942a.076.076 0 00-.0416-.1057c-.6528-.2476-1.2743-.5495-1.8722-.8923a.077.077 0 01-.0076-.1277c.1258-.0943.2517-.1923.3718-.2914a.0743.0743 0 01.0776-.0105c3.9278 1.7933 8.18 1.7933 12.0614 0a.0739.0739 0 01.0785.0095c.1202.099.246.1981.3728.2924a.077.077 0 01-.0066.1276 12.2986 12.2986 0 01-1.873.8914.0766.0766 0 00-.0407.1067c.3604.698.7719 1.3628 1.225 1.9932a.076.076 0 00.0842.0286c1.961-.6067 3.9495-1.5219 6.0023-3.0294a.077.077 0 00.0313-.0552c.5004-5.177-.8382-9.6739-3.5485-13.6604a.061.061 0 00-.0312-.0286zM8.02 15.3312c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9555-2.4189 2.157-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.9555 2.4189-2.1569 2.4189zm7.9748 0c-1.1825 0-2.1569-1.0857-2.1569-2.419 0-1.3332.9554-2.4189 2.1569-2.4189 1.2108 0 2.1757 1.0952 2.1568 2.419 0 1.3332-.946 2.4189-2.1568 2.4189Z"/></svg>',
  wechat: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#07C160"><path d="M8.691 2.188C3.891 2.188 0 5.476 0 9.53c0 2.212 1.17 4.203 3.002 5.55a.59.59 0 0 1 .213.665l-.39 1.48c-.019.07-.048.141-.048.213 0 .163.13.295.29.295a.326.326 0 0 0 .167-.054l1.903-1.114a.864.864 0 0 1 .717-.098 10.16 10.16 0 0 0 2.837.403c.276 0 .543-.027.811-.05-.857-2.578.157-4.972 1.932-6.446 1.703-1.415 3.882-1.98 5.853-1.838-.576-3.583-4.196-6.348-8.596-6.348zM5.785 5.991c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178A1.17 1.17 0 0 1 4.623 7.17c0-.651.52-1.18 1.162-1.18zm5.813 0c.642 0 1.162.529 1.162 1.18a1.17 1.17 0 0 1-1.162 1.178 1.17 1.17 0 0 1-1.162-1.178c0-.651.52-1.18 1.162-1.18zm5.34 2.867c-1.797-.052-3.746.512-5.28 1.786-1.72 1.428-2.687 3.72-1.78 6.22.942 2.453 3.666 4.229 6.884 4.229.826 0 1.622-.12 2.361-.336a.722.722 0 0 1 .598.082l1.584.926a.272.272 0 0 0 .14.047c.134 0 .24-.111.24-.247 0-.06-.023-.12-.038-.177l-.327-1.233a.582.582 0 0 1-.023-.156.49.49 0 0 1 .201-.398C23.024 18.48 24 16.82 24 14.98c0-3.21-2.931-5.837-6.656-6.088V8.89c-.135-.01-.27-.027-.407-.03zm-2.53 3.274c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.97-.982zm4.844 0c.535 0 .969.44.969.982a.976.976 0 0 1-.969.983.976.976 0 0 1-.969-.983c0-.542.434-.982.969-.982z"/></svg>',
  weibo: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#E6162D"><path d="M10.098 20.323c-3.977.391-7.414-1.406-7.672-4.02-.259-2.609 2.759-5.047 6.74-5.441 3.979-.394 7.413 1.404 7.671 4.018.259 2.6-2.759 5.049-6.737 5.439l-.002.004zM9.05 17.219c-.384.616-1.208.884-1.829.602-.612-.279-.793-.991-.406-1.593.379-.595 1.176-.861 1.793-.601.622.263.82.972.442 1.592zm1.27-1.627c-.141.237-.449.353-.689.253-.236-.09-.313-.361-.177-.586.138-.227.436-.346.672-.24.239.09.315.36.18.601l.014-.028zm.176-2.719c-1.893-.493-4.033.45-4.857 2.118-.836 1.704-.026 3.591 1.886 4.21 1.983.64 4.318-.341 5.132-2.179.8-1.793-.201-3.642-2.161-4.149zm7.563-1.224c-.346-.105-.57-.18-.405-.615.375-.977.42-1.804 0-2.404-.781-1.112-2.915-1.053-5.364-.03 0 0-.766.331-.571-.271.376-1.217.315-2.224-.27-2.809-1.338-1.337-4.869.045-7.888 3.08C1.309 10.87 0 13.273 0 15.348c0 3.981 5.099 6.395 10.086 6.395 6.536 0 10.888-3.801 10.888-6.82 0-1.822-1.547-2.854-2.915-3.284v.01zm1.908-5.092c-.766-.856-1.908-1.187-2.96-.962-.436.09-.706.511-.616.932.09.42.511.691.932.602.511-.105 1.067.044 1.442.465.376.421.466.977.316 1.473-.136.406.089.856.51.992.405.119.857-.105.992-.512.33-1.021.12-2.178-.646-3.035l.03.045zm2.418-2.195c-1.576-1.757-3.905-2.419-6.054-1.968-.496.104-.812.587-.706 1.081.104.496.586.813 1.082.707 1.532-.331 3.185.15 4.296 1.383 1.112 1.246 1.429 2.943.947 4.416-.165.48.106 1.007.586 1.157.479.165.991-.104 1.157-.586.675-2.088.241-4.478-1.338-6.235l.03.045z"/></svg>',
  qq: '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="#12B7F5"><path d="M21.395 15.035a39.548 39.548 0 0 0-.803-2.264l-1.079-2.695c.001-.032.014-.562.014-.836C19.526 4.632 17.351 0 12 0S4.474 4.632 4.474 9.241c0 .274.013.804.014.836l-1.08 2.695a38.97 38.97 0 0 0-.802 2.264c-1.021 3.283-.69 4.643-.438 4.673.54.065 2.103-2.472 2.103-2.472 0 1.469.756 3.387 2.394 4.771-.612.188-1.363.479-1.845.835-.434.32-.379.646-.301.778.343.578 5.883.369 7.482.189 1.6.18 7.14.389 7.483-.189.078-.132.132-.458-.301-.778-.483-.356-1.233-.646-1.846-.836 1.637-1.384 2.393-3.302 2.393-4.771 0 0 1.563 2.537 2.103 2.472.251-.03.581-1.39-.438-4.673zM12.662 4.846c.039-1.052.659-1.878 1.385-1.846s1.281.912 1.242 1.964c-.039 1.051-.659 1.878-1.385 1.846s-1.282-.912-1.242-1.964zM9.954 3c.725-.033 1.345.794 1.384 1.846.04 1.052-.517 1.931-1.242 1.963-.726.033-1.346-.794-1.385-1.845C8.672 3.912 9.228 3.033 9.954 3zM7.421 8.294c.194-.43 2.147-.908 4.566-.908h.026c2.418 0 4.372.479 4.566.908a.14.14 0 0 1 .014.061c0 .031-.01.059-.026.083-.163.238-2.333 1.416-4.553 1.416h-.026c-2.221 0-4.39-1.178-4.553-1.416a.136.136 0 0 1-.014-.144zm10.422 8.622c-.22 3.676-2.403 5.987-5.774 6.021h-.137c-3.37-.033-5.554-2.345-5.773-6.021-.081-1.35.001-2.496.147-3.43.318.063.638.122.958.176v3.506s1.658.334 3.318.103v-3.225c.488.027.96.04 1.406.034h.025c1.678.021 3.714-.204 5.683-.594.146.934.227 2.08.147 3.43zM10.48 5.804c.313-.041.542-.409.508-.825-.033-.415-.314-.72-.629-.679-.313.04-.541.409-.508.824.034.417.315.72.629.68zM14.479 5.156c.078.037.221.042.289-.146.035-.095.025-.165-.009-.214-.023-.033-.133-.118-.371-.176-.904-.22-1.341.384-1.405.499-.04.072-.012.176.056.227.067.051.139.037.179-.006.58-.628 1.21-.208 1.261-.184z"/></svg>',
};

/* 配置体检：识别每个平台的 ID / Secret 是否齐全 */
function statusReport(env) {
  return {
    secretSet: !!env.SECRET,
    kvBound: !!env.LOG_KV,
    microsoftTenant: env.MICROSOFT_TENANT || 'common',
    providers: Object.entries(PROVIDERS).map(([id, p]) => {
      const hasId = !!p.clientId(env);
      const hasSecret = !!env[SECRET_VARS[id]];
      return { id, label: p.label, configured: hasId, complete: hasId && hasSecret };
    }),
  };
}

async function createState(env, payload) {
  const data = base64UrlEncode(JSON.stringify({ ...payload, exp: Date.now() + 10 * 60 * 1000 }));
  const sig = await hmacHex(await mgSecret(env), data);
  return `${data}.${sig}`;
}

async function verifyState(env, token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = await hmacHex(await mgSecret(env), data);
  if (sig !== expected) return null;
  try {
    const payload = JSON.parse(base64UrlDecode(data));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function sessionCookieName() { return 'plogin_session'; }

async function createSession(env, { provider, platform, profile }) {
  const data = base64UrlEncode(JSON.stringify({
    provider, platform, profile, at: Date.now(),
    exp: Date.now() + 24 * 60 * 60 * 1000, // 与 cookie Max-Age 一致的 24h 会话
  }));
  const sig = await hmacHex(await mgSecret(env), data);
  return `${data}.${sig}`;
}

async function readSession(request, env) {
  const cookie = parseCookies(request.headers.get('Cookie') || '');
  const raw = cookie[sessionCookieName()];
  if (!raw) return null;
  const payload = await verifyState(env, raw); // 结构同为 data.sig
  if (!payload || !payload.provider) return null;
  return payload;
}

function sessionCookie(value) {
  return `${sessionCookieName()}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${60 * 60 * 24}; Secure`;
}

function clearSessionCookie() {
  return `${sessionCookieName()}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function parseCookies(header) {
  const out = {};
  header.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

/* ================================================================
 * OAuth 流程
 * ================================================================ */
async function handleAuth(request, env, url, provider) {
  const p = PROVIDERS[provider];
  const origin = url.origin;
  const redirectUri = `${origin}/callback/${provider}`;
  const platform = enrichPlatform(request.headers.get('User-Agent') || '', request);
  const pl = { label: platform.label, os: platform.os, app: platform.app, browser: platform.browser, category: platform.category, device: platform.device, ip: platform.ip, country: platform.country, city: platform.city, region: platform.region, timezone: platform.timezone, asn: platform.asn, colo: platform.colo, httpProtocol: platform.httpProtocol, tlsVersion: platform.tlsVersion, ua: platform.ua ? platform.ua.slice(0, 120) : '' };

  let verifier = null;
  let challenge = null;
  if (p.pkce) {
    verifier = randomBase64Url(32);
    challenge = await pkceChallenge(verifier);
  }

  const state = await createState(env, { provider, pl, verifier: verifier || null, ref: normalizeRef(url.searchParams.get('ref') || '') });

  const params = new URLSearchParams({
    client_id: p.clientId(env),
    redirect_uri: redirectUri,
    scope: p.scope,
    state,
    ...p.authExtra(env, redirectUri),
  });
  if (challenge) {
    params.set('code_challenge', challenge);
    params.set('code_challenge_method', 'S256');
  }

  let authUrl = `${p.authUrl(env)}?${params.toString()}`;
  if (p.authHash) authUrl += p.authHash;
  return Response.redirect(authUrl, 302);
}

async function handleCallback(request, env, url, provider) {
  const p = PROVIDERS[provider];
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const oauthError = url.searchParams.get('error');
  const curPlatform = enrichPlatform(request.headers.get('User-Agent') || '', request);

  const failPage = (reason, errText) => renderResultPage({
    ok: false, title: '登录失败', reason,
    hint: oauthErrorHint(errText || reason),
    platform: payloadPlatform(state) || curPlatform,
  });

  if (!p) return htmlResponse(failPage(`不支持的登录方式：${provider}`));
  if (oauthError) return htmlResponse(failPage(`对方拒绝了授权（${oauthError}）`, oauthError));
  if (!code || !state) return htmlResponse(failPage('缺少 code 或 state 参数'));

  const payload = await verifyState(env, state);
  if (!payload || payload.provider !== provider) {
    return htmlResponse(failPage('state 校验失败或已过期，请重新发起登录'));
  }

  // 1) 换 token
  let token;
  try {
    token = await exchangeToken(p, env, code, `${url.origin}/callback/${provider}`, payload.verifier);
  } catch (e) {
    return htmlResponse(failPage(`获取 access_token 失败：${e.message}`, e.message));
  }

  // 2) 部分 provider 需要额外身份标识（openid / uid）
  let extra = null;
  if (p.identity) {
    try { extra = await p.identity(env, token); }
    catch (e) { return htmlResponse(failPage(`获取身份标识失败：${e.message}`, e.message)); }
  }

  // 3) 拉用户信息
  let info = {};
  try {
    info = await fetchUserInfo(p, env, token, extra);
  } catch (e) {
    return htmlResponse(failPage(`获取用户信息失败：${e.message}`, e.message));
  }

  const profile = p.extract(info || {}, token, extra);
  const platform = payload.pl || curPlatform;

  // 4) 签发会话 cookie（可选 KV 记录）
  const session = await createSession(env, { provider, platform, profile });
  const res = htmlResponse(renderResultPage({ ok: true, title: '登录成功', provider, platform, profile, ref: payload.ref || '' }));
  res.headers.append('Set-Cookie', sessionCookie(session));
  if (env.LOG_KV) { ctxSafe(env.LOG_KV.put(`log:${Date.now()}`, JSON.stringify({ at: Date.now(), provider, platform, profile }))); }
  return res;
}

async function exchangeToken(p, env, code, redirect, verifier) {
  const params = new URLSearchParams(p.tokenParams(env, code, redirect, verifier));
  const headers = { Accept: 'application/json', ...(p.tokenHeaders ? p.tokenHeaders() : {}) };
  let res;
  if (p.tokenMethod === 'GET') {
    res = await fetch(`${p.tokenUrl(env)}?${params.toString()}`, { headers, method: 'GET' });
  } else {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    res = await fetch(p.tokenUrl(env), { method: 'POST', headers, body: params.toString() });
  }

  let data;
  if (p.tokenParse === 'form') {
    const text = await res.text();
    data = Object.fromEntries(new URLSearchParams(text));
  } else {
    data = await res.json().catch(() => ({}));
  }
  if (p.tokenUnwrap && data && data.data) data = data.data;
  if (!data.access_token) {
    throw new Error(data.error_description || data.error || data.errmsg || `HTTP ${res.status}`);
  }
  return data;
}

async function fetchUserInfo(p, env, token, extra) {
  const url = p.userInfoUrl(env, token, extra);
  const headers = { Accept: 'application/json', 'User-Agent': 'platform-oauth-login/1.0' };
  if (p.userInfoAuth !== 'query') headers.Authorization = `Bearer ${token.access_token}`;
  const res = await fetch(url, { headers });
  return res.json();
}

/* 尽快执行 KV 写入，不阻塞响应（失败静默） */
function ctxSafe(promise) {
  promise.catch(() => {});
}

async function readLogs(kv) {
  const list = await kv.list({ prefix: 'log:', limit: 50 });
  const items = await Promise.all(
    list.keys.map(async (k) => {
      try { return JSON.parse(await kv.get(k.name)); } catch { return null; }
    })
  );
  return items.filter(Boolean).sort((a, b) => (b.at || 0) - (a.at || 0));
}

async function pkceChallenge(verifier) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return bytesToBase64Url(new Uint8Array(bytes));
}

function randomBase64Url(byteLength) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToBase64Url(bytes);
}

function bytesToBase64Url(bytes) {
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ================================================================
 * 加解密工具
 * ================================================================ */
function base64UrlEncode(str) {
  return bytesToBase64Url(new TextEncoder().encode(str));
}

function base64UrlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret || 'dev-secret'),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function payloadPlatform(state) {
  try {
    if (!state || !state.includes('.')) return null;
    const payload = JSON.parse(base64UrlDecode(state.split('.')[0]));
    return payload.pl || null;
  } catch { return null; }
}

function jsonResponse(obj, cors = false, status = 200) {
  const headers = { 'Content-Type': 'application/json; charset=utf-8' };
  if (cors) headers['Access-Control-Allow-Origin'] = '*';
  return new Response(JSON.stringify(obj, null, 2), { status, headers });
}

function htmlResponse(html, status = 200) {
  return new Response(html, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': "frame-ancestors 'self' https://*.107211.xyz" } });
}

/* ip.107211.xyz —— 显示访问者公网 IP（?raw=1 或 Accept: text/plain 返回纯文本） */
function ipPage(request, url) {
  const cf = request.cf || {};
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('x-real-ip') || '未知';
  const wantPlain = url.searchParams.get('raw') === '1' || (request.headers.get('Accept') || '').startsWith('text/plain');
  if (wantPlain) {
    return new Response(ip + '\n', { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  const platform = detectPlatform(request.headers.get('User-Agent') || '');
  const device = platform.device || '—';
  const os = platform.os || '—';
  const browser = platform.browser ? browserLabel(platform.browser) : '—';
  const location = [cf.country, cf.city, cf.region].filter(v => v && v !== '—').join(', ') || '—';
  const rows = [
    ['设备', device],
    ['平台', os],
    ['浏览器', browser],
    ['访问IP', ip],
    ['地区', location],
    ['时区', cf.timezone || '—'],
    ['数据中心', cf.colo || '—'],
  ];
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>IP 查询 · 107211.xyz</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;background:radial-gradient(circle at 15% -10%,rgba(255,143,168,.10),transparent 42%),#f8fafc;color:#1f2937;line-height:1.7;min-height:100vh;display:flex;padding:40px 16px;-webkit-font-smoothing:antialiased}
    .card{position:relative;width:100%;max-width:368px;margin:auto;background:rgba(255,255,255,.95);-webkit-backdrop-filter:blur(20px);backdrop-filter:blur(20px);border-radius:24px;padding:36px 32px 30px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.12),0 2px 8px rgba(0,0,0,.04)}
    .card::before{content:"";position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,#ffb7c5 0,#ff8fa8 50%,#ffb7c5 100%);background-size:200% 100%;animation:gs 3s ease infinite}
    @keyframes gs{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}
    .brand{font-size:13px;color:#6b7280;margin:6px 0 16px}.brand b{color:#1f2937;font-weight:700}
    .ip{font-size:30px;font-weight:800;letter-spacing:-.3px;word-break:break-all;margin:0 0 4px;background:linear-gradient(135deg,#ffb7c5,#ff8fa8);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
    .note{font-size:12.5px;color:#6b7280;margin:0 0 14px}
    .note a{color:#e0567e}
    .t{border-top:1px solid #e5e7eb;margin-top:8px}
    .t .r{display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid #e5e7eb;font-size:13.5px}
    .t dt{color:#6b7280;flex-shrink:0}.t dd{margin:0;text-align:right;word-break:break-all;font-family:"Fira Code",Consolas,Menlo,monospace;font-size:12.5px}
    .meta{margin-top:18px;padding-top:14px;border-top:1px solid #e5e7eb;font-size:12.5px;color:#6b7280}
    .meta a{color:#e0567e;text-decoration:none}
  </style>
</head>
<body>
  <main class="card">
    <div class="brand"><b>IP 查询</b> · 107211.xyz</div>
    <div class="ip">${esc(ip)}</div>
    <dl class="t">
      ${rows.map(([k, v]) => `<div class="r"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join('')}
    </dl>
    <div class="meta"><a href="https://oauth.107211.xyz">回到登录页</a></div>
  </main>
</body>
</html>`;
  return htmlResponse(html);
}

/* 来源页校验：只允许 http/https，禁止本站自身，防开放重定向 */
function normalizeRef(ref) {
  if (!ref) return '';
  ref = String(ref).trim();
  if (ref.length > 500) ref = ref.slice(0, 500);
  if (!/^https?:\/\//i.test(ref)) return '';
  try {
    const u = new URL(ref);
    if (u.hostname === 'oauth.107211.xyz' || u.hostname === 'ip.107211.xyz') return '';
  } catch { return ''; }
  return ref;
}

function oauthErrorHint(errText) {
  const t = String(errText || '');
  const map = [
    ['AADSTS700016', '该应用未在对应账户目录生效：通过个人 Microsoft 账户登录时，请确认 Azure「受支持的账户类型」包含「个人 Microsoft 账户」；仍不行可翻转一次账户类型或重新注册应用（consumers 副本同步问题）'],
    ['AADSTS7000215', 'Client Secret 无效或已过期：请到 Azure「证书和密码」重建客户端密码，并重新 wrangler secret put'],
    ['AADSTS50011', '回调地址不匹配：请确认重定向 URI 与 https://oauth.107211.xyz/callback/microsoft 完全一致（结尾无斜杠）'],
    ['AADSTS65001', '缺少权限同意：请在应用「API 权限」中为 openid / email / profile / User.Read 添加并授予同意'],
    ['AADSTS53003', '请求被租户 Conditional Access 策略拦截：请在 Azure 侧为该应用配置访问例外，或改用允许的账户类型'],
    ['AADSTS50049', '租户不存在或拼写错误：请检查 MICROSOFT_TENANT 配置'],
    ['AADSTS90002', '租户参数无效：请检查 MICROSOFT_TENANT 配置'],
    ['unauthorized_client', '应用未获该账户类型授权：请确认 Azure「受支持的账户类型」包含「个人 Microsoft 账户」；仍不行可翻转一次账户类型或重新注册应用'],
    ['invalid_grant', '授权码已失效或已使用：请重新发起登录'],
  ];
  const hit = map.find(([code]) => t.includes(code));
  return hit ? hit[1] : '';
}

function browserLabel(browser) {
  return ({ edge: 'Edge', chrome: 'Chrome', firefox: 'Firefox', safari: 'Safari', wechat: '微信', qq: 'QQ', dingtalk: '钉钉', weibo: '微博', xiaohongshu: '小红书', douyin: '抖音', baidu: '百度', xiaomi: '小米', unknown: '—' })[browser] || browser || '—';
}

function platformBlock(platform) {
  if (!platform) return '';
  const device = platform.device || '—';
  const os = platform.os || '—';
  const browser = platform.browser ? browserLabel(platform.browser) : '—';
  const ip = platform.ip || '—';
  const locParts = [platform.country, platform.city, platform.region].filter(v => v && v !== '—');
  const location = locParts.length ? locParts.join(', ') : '—';
  const ua = platform.ua ? esc(platform.ua.slice(0, 120)) : '';
  return `
    <section class="platform">
      <dl>
        <div class="r"><dt>设备</dt><dd class="mono">${esc(device)}</dd></div>
        <div class="r"><dt>平台</dt><dd class="mono">${esc(os)}</dd></div>
        <div class="r"><dt>浏览器</dt><dd class="mono">${esc(browser)}</dd></div>
        <div class="r"><dt>访问IP</dt><dd class="mono">${esc(ip)}</dd></div>
        <div class="r"><dt>地区</dt><dd class="mono">${esc(location)}</dd></div>
        <div class="r"><dt>时区</dt><dd class="mono">${esc(platform.timezone || '—')}</dd></div>
        <div class="r"><dt>数据中心</dt><dd class="mono">${esc(platform.colo || '—')}</dd></div>
        ${ua ? `<div class="r"><dt>User-Agent</dt><dd class="mono">${ua}</dd></div>` : ''}
      </dl>
    </section>`;
}

function renderResultPage({ ok, title, reason = "", hint = "", provider = "", platform = null, profile = null, ref = "" }) {
  const modalIcon = ok
    ? `<svg viewBox="0 0 52 52"><circle class="c" cx="26" cy="26" r="25"/><path class="m" d="M14.1 27.2l7.1 7.2 16.7-16.8"/></svg>`
    : `<svg viewBox="0 0 52 52"><circle class="c" cx="26" cy="26" r="25"/><path class="m" d="M16 16 36 36M36 16 16 36"/></svg>`;
  const modal = `
  <div class="modal-overlay ${ok ? 'ok' : 'fail'}" id="resultModal">
    <div class="modal">
      <div class="modal-icon ${ok ? 'ok' : 'fail'}">${modalIcon}</div>
      <div class="modal-title">${esc(title)}</div>
      <button class="modal-btn" onclick="closeResultModal()">${ok ? '完成' : '关闭'}</button>
    </div>
  </div>
  <script>
  (function(){
    var m = document.getElementById('resultModal');
    function close(){
      m.classList.remove('show');
      setTimeout(function(){ m.style.display = 'none'; }, 400);
    }
    window.closeResultModal = close;
    requestAnimationFrame(function(){
      requestAnimationFrame(function(){ m.classList.add('show'); });
    });
    m.addEventListener('click', function(e){ if (e.target === m) close(); });
    setTimeout(close, 3500);
  })();
  </script>`;

  // 登录成功且存在来源页：弹窗展示 3 秒后，携带参数自动返回来源页
  const redirectJS = ok && ref
    ? `<script>
  (function(){
    var base = ${JSON.stringify(ref)};
    var args = {
      oauth_success: '1',
      provider: ${JSON.stringify(provider || '')},
      username: ${JSON.stringify((profile && profile.username) || '')},
      name: ${JSON.stringify((profile && profile.name) || '')},
      email: ${JSON.stringify((profile && profile.email) || '')},
      avatar: ${JSON.stringify((profile && profile.avatar) || '')}
    };
    var q = [];
    for (var k in args) if (args[k]) q.push(encodeURIComponent(k) + '=' + encodeURIComponent(args[k]));
    var url = base + (base.indexOf('?') >= 0 ? '&' : '?') + q.join('&');
    setTimeout(function(){ location.href = url; }, 3000);
  })();
  </script>`
    : '';

  let profileBox = '';
  if (ok && profile) {
    const initial = (profile.name || '?').trim().charAt(0) || '?';
    profileBox = `
      <div class="profile">
        ${profile.avatar
          ? `<img src="${esc(profile.avatar)}" alt="avatar"/>`
          : `<span class="avatar">${esc(initial)}</span>`}
        <div>
          <div class="nm">${esc(profile.name || '未知用户')}</div>
          ${profile.email ? `<div class="em">${esc(profile.email)}</div>` : ''}
        </div>
      </div>`;
  }

  const pName = provider && PROVIDERS[provider] ? PROVIDERS[provider].label : provider;
  const os = platform ? (platform.os || '—') : '—';
  const device = platform ? (platform.device || '—') : '—';
  const browser = platform && platform.browser ? browserLabel(platform.browser) : '—';
  const ipAddr = platform ? (platform.ip || '—') : '—';
  const locParts = platform ? [platform.country, platform.city, platform.region].filter(v => v && v !== '—') : [];
  const location = locParts.length ? locParts.join(', ') : '—';
  const timezone = platform ? (platform.timezone || '—') : '—';
  const uaText = platform && platform.ua ? esc(platform.ua.slice(0, 120)) : '';
  const rows = `
    <dl class="dtable">
      <div class="r"><dt>设备</dt><dd class="mono">${esc(device)}</dd></div>
      <div class="r"><dt>平台</dt><dd class="mono">${esc(os)}</dd></div>
      <div class="r"><dt>浏览器</dt><dd class="mono">${esc(browser)}</dd></div>
      <div class="r"><dt>访问IP</dt><dd class="mono">${esc(ipAddr)}</dd></div>
      <div class="r"><dt>地区</dt><dd class="mono">${esc(location)}</dd></div>
      <div class="r"><dt>时区</dt><dd class="mono">${esc(timezone)}</dd></div>
      <div class="r"><dt>数据中心</dt><dd class="mono">${esc(platform ? (platform.colo || '—') : '—')}</dd></div>
      ${uaText ? `<div class="r"><dt>User-Agent</dt><dd class="mono">${uaText}</dd></div>` : ''}
      ${provider ? `<div class="r"><dt>登录方式</dt><dd>${esc(pName)}</dd></div>` : ''}
    </dl>`;

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>${esc(title)} · MAILGATE</title>
  <style>${CSS}</style>
</head>
<body>
  ${modal}
  ${redirectJS}
  <main class="card">
    <div class="brand"><b>MAILGATE</b></div>
    <h1>${esc(title)}</h1>
    ${!ok && (reason || hint) ? `<div class="status fail">${reason ? `<div class="why">${esc(reason)}</div>` : ""}${hint ? `<div class="hint">${esc(hint)}</div>` : ""}</div>` : ""}
    ${profileBox}
    ${rows}
    <footer class="meta">
      <a href="/">返回登录页</a>
    </footer>
  </main>
</body>
</html>`;
}

/* ---------------------------------- 路由 --------------------------------- */
export default {
  async fetch(req, env) {
    const u0 = new URL(req.url);
    let p = u0.pathname.replace(/\/+$/, "");
    if (p === "") p = "/";
    try {
      /* ip.107211.xyz：仅提供 IP 查询服务，其他路径一律 404 */
      if (u0.hostname.toLowerCase() === "ip.107211.xyz") {
        if (p === "/" || p === "/ip" || p === "/index.html") return ipPage(req, u0);
        return new Response("Not Found", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8" } });
      }
      /* OAuth 登录 */
      if (req.method === "GET" && p === "/api/platform") return jsonResponse(enrichPlatform(req.headers.get("User-Agent") || "", req), true);
      if (req.method === "GET" && p === "/api/providers") return jsonResponse({ providers: configuredProviders(env) }, true);
      if (req.method === "GET" && p === "/api/status") return jsonResponse(statusReport(env), true);
      if (req.method === "GET" && p === "/api/logs") {
        const ol = env.LOG_KV ? await readLogs(env.LOG_KV) : [];
        return jsonResponse({ logs: ol, kvBound: !!env.LOG_KV }, true);
      }
      if (req.method === "GET" && p === "/me") {
        const sess = await readSession(req, env);
        if (!sess) return jsonResponse({ loggedIn: false }, true, 401);
        return jsonResponse({ loggedIn: true, ...sess }, true);
      }
      if (req.method === "GET" && p === "/logout") {
        return new Response("", { status: 302, headers: { Location: "/", "Set-Cookie": clearSessionCookie() } });
      }
      if (req.method === "GET" && p.startsWith("/auth/")) {
        const prov = p.slice("/auth/".length);
        if (!PROVIDERS[prov]) {
          return htmlResponse(renderResultPage({
            ok: false, title: "登录失败", reason: "不支持的登录方式：" + prov,
            platform: enrichPlatform(req.headers.get("User-Agent") || "", req)
          }));
        }
        return await handleAuth(req, env, u0, prov);
      }
      if (req.method === "GET" && p.startsWith("/callback/")) {
        return await handleCallback(req, env, u0, p.slice("/callback/".length));
      }
      /* MAILGATE 验证网关 */
      if (req.method === "GET" && p === "/") return await pgHome(req, env);
      if (req.method === "GET" && p === "/oauth") return await pgOauth(req, env);
      if (req.method === "GET" && (p === "/email" || p === "/mail")) return await pgMail(req, env);
      if (req.method === "GET" && (p === "/admin" || p === "/service" || p === "/manage")) return await pgAdmin(req, env);
      if (req.method === "POST" && p === "/admin/login") return await adLogin(req, env);
      if (req.method === "GET" && p === "/admin/logout") return adLogout();
      if (req.method === "POST" && p === "/admin/save") return await adSave(req, env);
      if (req.method === "POST" && p === "/admin/test") return await adTest(req, env);
      if (req.method === "GET" && p === "/api/captcha") return await apiCaptcha(req, env);
      if (req.method === "POST" && p === "/api/send") return await apiSend(req, env);
      if (req.method === "POST" && p === "/api/verify") return await apiVerify(req, env);
      if (req.method === "GET" && p === "/api/check") return await apiCheck(req, env);
      if (p === "/favicon.ico") return new Response(null, { status: 204 });
      return pg404();
    } catch (e) {
      return json({ ok: false, msg: "服务器内部错误：" + ((e && e.message) || e) }, 500);
    }
  }
};