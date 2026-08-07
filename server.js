const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const APP_USER = process.env.APP_USER || "ahmad";
// كلمة السر الافتراضية: tire2026 (غيّرها عبر متغير بيئة APP_PASS وقت النشر)
const APP_PASS = process.env.APP_PASS || "tire2026";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-please";

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.json");

// إعدادات التخزين الدائم على GitHub (اختياري لكن يُنصح به بشدة على Render)
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";
const GITHUB_REPO = process.env.GITHUB_REPO || ""; // مثال: ahmaadbrk-collab/tire-shops-app
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";
const GITHUB_DATA_PATH = process.env.GITHUB_DATA_PATH || "data.json";
const GITHUB_ENABLED = !!(GITHUB_TOKEN && GITHUB_REPO);

const EMPTY_DB = { sales: [], expenses: [], income: [], employees: [], custody: [], network: [], cashClose: [], transfers: [], counters: {} };

const BRANCH_CODES = { "فخامة الاطار": "FAK", "روائع الافق": "RAF", "روعة المنار": "RMN" };

let db = { ...EMPTY_DB };
let githubSha = null; // نحتاجه لتحديث الملف بـ GitHub API

/* ============ تخزين GitHub (دائم) ============ */
async function githubGetFile() {
  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_DATA_PATH}?ref=${GITHUB_BRANCH}`;
  const r = await fetch(url, {
    headers: { Authorization: `token ${GITHUB_TOKEN}`, Accept: "application/vnd.github+json" },
  });
  if (r.status === 404) return null; // الملف ما موجود بعد
  if (!r.ok) throw new Error(`GitHub GET failed: ${r.status} ${await r.text()}`);
  const json = await r.json();
  githubSha = json.sha;
  const content = Buffer.from(json.content, "base64").toString("utf8");
  return JSON.parse(content);
}

async function githubPutFile(dataObj) {
  const url = `https://api.github.com/repos/${GITHUB_REPO}/contents/${GITHUB_DATA_PATH}`;
  const content = Buffer.from(JSON.stringify(dataObj, null, 2), "utf8").toString("base64");
  const body = {
    message: `تحديث بيانات النظام - ${new Date().toISOString()}`,
    content,
    branch: GITHUB_BRANCH,
  };
  if (githubSha) body.sha = githubSha;
  const r = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `token ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`GitHub PUT failed: ${r.status} ${await r.text()}`);
  const json = await r.json();
  githubSha = json.content.sha; // نحدّث الـ sha لآخر نسخة حتى تنجح التحديثات الجايه
}

/* ============ تخزين محلي (احتياطي عند عدم توفر GitHub) ============ */
function localLoad() {
  try {
    if (!fs.existsSync(DB_PATH)) return { ...EMPTY_DB };
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch (e) {
    console.error("Local DB load error:", e.message);
    return { ...EMPTY_DB };
  }
}
function localSave(dataObj) {
  const tmp = DB_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(dataObj, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

async function loadDB() {
  if (GITHUB_ENABLED) {
    try {
      const remote = await githubGetFile();
      if (remote) {
        console.log("✅ تم تحميل البيانات من GitHub (تخزين دائم)");
        return { ...EMPTY_DB, ...remote, counters: remote.counters || {} };
      }
      console.log("ℹ️ لا يوجد ملف بيانات على GitHub بعد، سيبدأ ملف جديد.");
      return { ...EMPTY_DB };
    } catch (e) {
      console.error("⚠️ فشل تحميل البيانات من GitHub:", e.message, "— سيتم استخدام نسخة محلية إن وجدت.");
      return localLoad();
    }
  }
  console.warn("⚠️ تحذير: GITHUB_TOKEN أو GITHUB_REPO غير مُعرّفين. البيانات ستُخزَّن محلياً فقط وقد تُمسح عند إعادة النشر!");
  return localLoad();
}

// طابور حفظ متسلسل لتفادي تعارض الكتابة المتزامنة
let saveQueue = Promise.resolve();
function saveDB(dataObj) {
  saveQueue = saveQueue
    .then(async () => {
      localSave(dataObj); // نسخة محلية سريعة دايماً (احتياط إضافي)
      if (GITHUB_ENABLED) {
        await githubPutFile(dataObj);
      }
    })
    .catch((e) => console.error("⚠️ فشل حفظ البيانات:", e.message));
  return saveQueue;
}

function nextArchiveNo(prefix, branch) {
  const code = BRANCH_CODES[branch] || "GEN";
  const key = `${prefix}-${code}`;
  db.counters[key] = (db.counters[key] || 0) + 1;
  return `${key}-${String(db.counters[key]).padStart(3, "0")}`;
}

const app = express();
app.use(express.json());

const PASS_HASH = bcrypt.hashSync(APP_PASS, 10);
const AUTH_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 30; // شهر

function sign(payload) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("hex");
}
function makeAuthCookie() {
  const expires = Date.now() + AUTH_MAX_AGE_MS;
  const payload = `${APP_USER}.${expires}`;
  return `${payload}.${sign(payload)}`;
}
function parseCookies(header) {
  const out = {};
  (header || "").split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx === -1) return;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}
function isValidAuthCookie(value) {
  if (!value) return false;
  const parts = value.split(".");
  if (parts.length !== 3) return false;
  const [user, expiresStr, sig] = parts;
  const payload = `${user}.${expiresStr}`;
  if (sign(payload) !== sig) return false;
  if (user !== APP_USER) return false;
  if (Date.now() > Number(expiresStr)) return false;
  return true;
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  if (isValidAuthCookie(cookies.auth)) return next();
  return res.status(401).json({ error: "unauthorized" });
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

/* ---------- تسجيل الدخول ---------- */
// نظام تسجيل الدخول يعتمد على كوكيز موقّعة (HMAC) لا على ذاكرة السيرفر،
// فيصمد حتى لو السيرفر توقف مؤقتاً وشغّل نفسه من جديد (شائع بالخطط المجانية).
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === APP_USER && bcrypt.compareSync(password || "", PASS_HASH)) {
    const cookieVal = makeAuthCookie();
    res.setHeader(
      "Set-Cookie",
      `auth=${encodeURIComponent(cookieVal)}; Max-Age=${Math.floor(AUTH_MAX_AGE_MS / 1000)}; Path=/; HttpOnly; SameSite=Lax`
    );
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
});
app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "auth=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax");
  res.json({ ok: true });
});
app.get("/api/me", (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  res.json({ loggedIn: isValidAuthCookie(cookies.auth), storage: GITHUB_ENABLED ? "github" : "local" });
});

/* ---------- بيانات ---------- */
app.get("/api/data", requireAuth, (req, res) => {
  res.json(db);
});

function makeCollectionRoutes(name, fields, numericFields, routeName, booleanFields, archivePrefix) {
  numericFields = numericFields || [];
  booleanFields = booleanFields || [];
  const route = routeName || name;
  app.post(`/api/${route}`, requireAuth, async (req, res) => {
    const b = req.body || {};
    const record = { id: genId(), created_at: new Date().toISOString() };
    fields.forEach((f) => {
      if (numericFields.includes(f)) record[f] = Number(b[f]) || 0;
      else if (booleanFields.includes(f)) record[f] = !!b[f];
      else record[f] = b[f] !== undefined && b[f] !== null ? b[f] : "";
    });
    if (archivePrefix) record.archiveNo = nextArchiveNo(archivePrefix, b.branch);
    db[name].unshift(record);
    try {
      await saveDB(db);
    } catch (e) {
      return res.status(500).json({ error: "save failed" });
    }
    res.json({ id: record.id, archiveNo: record.archiveNo });
  });
  app.delete(`/api/${route}/:id`, requireAuth, async (req, res) => {
    db[name] = db[name].filter((r) => r.id !== req.params.id);
    try {
      await saveDB(db);
    } catch (e) {
      return res.status(500).json({ error: "save failed" });
    }
    res.json({ ok: true });
  });
}

makeCollectionRoutes("sales", ["date", "branch", "type", "box", "gross", "rate", "net", "notes"], ["gross", "rate", "net"], null, null, "SAL");
makeCollectionRoutes("expenses", ["date", "branch", "code", "box", "amount", "employee", "invoiceNo", "supplier", "notes"], ["amount"], null, null, "EXP");
makeCollectionRoutes("income", ["date", "branch", "company", "box", "amount", "notes"], ["amount"]);
makeCollectionRoutes("employees", ["name", "branch"], []);
makeCollectionRoutes("custody", ["date", "branch", "box", "amount", "collector", "notes"], ["amount"], "custody", ["forwarded"], "CUS");
makeCollectionRoutes("network", ["date", "branch", "bank_deposit", "notes"], ["bank_deposit"]);
makeCollectionRoutes("cashClose", ["date", "branch", "actual_cash", "notes"], ["actual_cash"], "cash-close", ["closed"]);
makeCollectionRoutes("transfers", ["date", "branch", "fromBox", "toBox", "amount", "notes"], ["amount"], "transfers", null, "TRF");

/* ---------- تبديل حالة (رحّل / أُقفل) ---------- */
app.patch("/api/custody/:id/forwarded", requireAuth, async (req, res) => {
  const rec = db.custody.find((r) => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  rec.forwarded = !rec.forwarded;
  try { await saveDB(db); } catch (e) { return res.status(500).json({ error: "save failed" }); }
  res.json({ forwarded: rec.forwarded });
});
app.patch("/api/cash-close/:id/closed", requireAuth, async (req, res) => {
  const rec = db.cashClose.find((r) => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  rec.closed = !rec.closed;
  try { await saveDB(db); } catch (e) { return res.status(500).json({ error: "save failed" }); }
  res.json({ closed: rec.closed });
});

/* ---------- نسخة احتياطية ---------- */
app.get("/api/backup", requireAuth, (req, res) => {
  res.json({ ...db, exportedAt: new Date().toISOString() });
});

/* ---------- الملفات الثابتة (الواجهة) ---------- */
app.use(express.static(__dirname));
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

loadDB().then((loaded) => {
  db = loaded;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(GITHUB_ENABLED ? "🔒 التخزين الدائم على GitHub مفعّل." : "⚠️ التخزين محلي فقط (غير دائم على Render المجاني).");
  });
});
