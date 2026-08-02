const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

const PORT = process.env.PORT || 3000;
const APP_USER = process.env.APP_USER || "ahmad";
// كلمة السر الافتراضية: tire2026 (غيّرها عبر متغير بيئة APP_PASS وقت النشر)
const APP_PASS = process.env.APP_PASS || "tire2026";
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-please";

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data.sqlite");
const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS sales (
  id TEXT PRIMARY KEY, date TEXT, branch TEXT, type TEXT, box TEXT,
  gross REAL, rate REAL, net REAL, notes TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY, date TEXT, branch TEXT, code TEXT, box TEXT,
  amount REAL, employee TEXT, notes TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS income (
  id TEXT PRIMARY KEY, date TEXT, branch TEXT, company TEXT, box TEXT,
  amount REAL, notes TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS employees (
  id TEXT PRIMARY KEY, name TEXT, created_at TEXT
);
`);

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
  const sales = db.prepare("SELECT * FROM sales ORDER BY created_at DESC").all();
  const expenses = db.prepare("SELECT * FROM expenses ORDER BY created_at DESC").all();
  const income = db.prepare("SELECT * FROM income ORDER BY created_at DESC").all();
  const employees = db.prepare("SELECT * FROM employees ORDER BY created_at DESC").all();
  res.json({ sales, expenses, income, employees });
});

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 9);
}

app.post("/api/sales", requireAuth, (req, res) => {
  const b = req.body;
  const id = genId();
  db.prepare(
    `INSERT INTO sales (id,date,branch,type,box,gross,rate,net,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).run(id, b.date, b.branch, b.type, b.box, b.gross || 0, b.rate || 0, b.net || 0, b.notes || "", new Date().toISOString());
  res.json({ id });
});
app.delete("/api/sales/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM sales WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/expenses", requireAuth, (req, res) => {
  const b = req.body;
  const id = genId();
  db.prepare(
    `INSERT INTO expenses (id,date,branch,code,box,amount,employee,notes,created_at) VALUES (?,?,?,?,?,?,?,?,?)`
  ).run(id, b.date, b.branch, b.code, b.box, b.amount || 0, b.employee || "", b.notes || "", new Date().toISOString());
  res.json({ id });
});
app.delete("/api/expenses/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM expenses WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/income", requireAuth, (req, res) => {
  const b = req.body;
  const id = genId();
  db.prepare(
    `INSERT INTO income (id,date,branch,company,box,amount,notes,created_at) VALUES (?,?,?,?,?,?,?,?)`
  ).run(id, b.date, b.branch, b.company, b.box, b.amount || 0, b.notes || "", new Date().toISOString());
  res.json({ id });
});
app.delete("/api/income/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM income WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

app.post("/api/employees", requireAuth, (req, res) => {
  const b = req.body;
  const id = genId();
  db.prepare(`INSERT INTO employees (id,name,created_at) VALUES (?,?,?)`).run(id, b.name, new Date().toISOString());
  res.json({ id });
});
app.delete("/api/employees/:id", requireAuth, (req, res) => {
  db.prepare("DELETE FROM employees WHERE id=?").run(req.params.id);
  res.json({ ok: true });
});

/* ---------- نسخة احتياطية ---------- */
app.get("/api/backup", requireAuth, (req, res) => {
  const sales = db.prepare("SELECT * FROM sales").all();
  const expenses = db.prepare("SELECT * FROM expenses").all();
  const income = db.prepare("SELECT * FROM income").all();
  const employees = db.prepare("SELECT * FROM employees").all();
  res.json({ sales, expenses, income, employees, exportedAt: new Date().toISOString() });
});

/* ---------- الملفات الثابتة (الواجهة) ---------- */
app.use(express.static(path.join(__dirname, "public")));
app.use((req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
