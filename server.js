const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const APP_USER = process.env.APP_USER || "ahmad";
// كلمة السر الافتراضية: tire2026 (غيّرها عبر متغير بيئة APP_PASS وقت النشر)
const APP_PASS = process.env.APP_PASS || "tire2026";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-please";

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.json");

const EMPTY_DB = { sales: [], expenses: [], income: [], employees: [], custody: [], network: [], cashClose: [], transfers: [], counters: {} };

const BRANCH_CODES = { "فخامة الاطار": "FAK", "روائع الافق": "RAF", "روعة المنار": "RMN" };

function loadDB() {
  try {
    if (!fs.existsSync(DB_PATH)) {
      fs.writeFileSync(DB_PATH, JSON.stringify(EMPTY_DB, null, 2));
      return { ...EMPTY_DB };
    }
    const raw = fs.readFileSync(DB_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return { ...EMPTY_DB, ...parsed, counters: parsed.counters || {} };
  } catch (e) {
    console.error("DB load error, starting fresh:", e.message);
    return { ...EMPTY_DB };
  }
}

function saveDB(db) {
  // كتابة آمنة: نكتب لملف مؤقت ثم نستبدل، لتفادي تلف البيانات لو انقطع التشغيل أثناء الكتابة
  const tmp = DB_PATH + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_PATH);
}

let db = loadDB();

function nextArchiveNo(prefix, branch) {
  const code = BRANCH_CODES[branch] || "GEN";
  const key = `${prefix}-${code}`;
  db.counters[key] = (db.counters[key] || 0) + 1;
  return `${key}-${String(db.counters[key]).padStart(3, "0")}`;
}

const app = express();
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 30 }, // شهر
  })
);

const PASS_HASH = bcrypt.hashSync(APP_PASS, 10);

function requireAuth(req, res, next) {
  if (req.session && req.session.loggedIn) return next();
  return res.status(401).json({ error: "unauthorized" });
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

/* ---------- تسجيل الدخول ---------- */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username === APP_USER && bcrypt.compareSync(password || "", PASS_HASH)) {
    req.session.loggedIn = true;
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "بيانات الدخول غير صحيحة" });
});
app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});
app.get("/api/me", (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.loggedIn) });
});

/* ---------- بيانات ---------- */
app.get("/api/data", requireAuth, (req, res) => {
  res.json(db);
});

function makeCollectionRoutes(name, fields, numericFields, routeName, booleanFields, archivePrefix) {
  numericFields = numericFields || [];
  booleanFields = booleanFields || [];
  const route = routeName || name;
  app.post(`/api/${route}`, requireAuth, (req, res) => {
    const b = req.body || {};
    const record = { id: genId(), created_at: new Date().toISOString() };
    fields.forEach((f) => {
      if (numericFields.includes(f)) record[f] = Number(b[f]) || 0;
      else if (booleanFields.includes(f)) record[f] = !!b[f];
      else record[f] = b[f] !== undefined && b[f] !== null ? b[f] : "";
    });
    if (archivePrefix) record.archiveNo = nextArchiveNo(archivePrefix, b.branch);
    db[name].unshift(record);
    saveDB(db);
    res.json({ id: record.id, archiveNo: record.archiveNo });
  });
  app.delete(`/api/${route}/:id`, requireAuth, (req, res) => {
    db[name] = db[name].filter((r) => r.id !== req.params.id);
    saveDB(db);
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
app.patch("/api/custody/:id/forwarded", requireAuth, (req, res) => {
  const rec = db.custody.find((r) => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  rec.forwarded = !rec.forwarded;
  saveDB(db);
  res.json({ forwarded: rec.forwarded });
});
app.patch("/api/cash-close/:id/closed", requireAuth, (req, res) => {
  const rec = db.cashClose.find((r) => r.id === req.params.id);
  if (!rec) return res.status(404).json({ error: "not found" });
  rec.closed = !rec.closed;
  saveDB(db);
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

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
