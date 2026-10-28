"use strict";
/* Educlawd CRM · Server
   - serves the website (index.html, css/, js/)
   - exposes POST /api/rpc/<function> with the same functions the app used to call on Supabase
   - stores everything in MySQL (Railway) using the tables in schema.sql */

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const webpush = require("web-push");

const PORT = process.env.PORT || 3000;
const DB_URL = process.env.MYSQL_URL || process.env.DATABASE_URL;
if (!DB_URL) {
  console.error("MYSQL_URL is not set. In Railway: app service -> Variables -> add MYSQL_URL = ${{MySQL.MYSQL_URL}}");
  process.exit(1);
}

const pool = mysql.createPool({
  uri: DB_URL,
  waitForConnections: true,
  connectionLimit: 10,
  timezone: "Z",
  charset: "utf8mb4",
});

const SESSION_DAYS = 30;
const MAX_DOC_BYTES = 1000000;
const MAX_FAILS = 8;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const DUMMY_HASH = bcrypt.hashSync("not-a-real-password", 10);

class ApiError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.code = code;
    this.status = status;
  }
}

/* ---------- helpers ---------- */
const iso = (d) => (d instanceof Date ? d.toISOString() : d ? new Date(d).toISOString() : null);
const pub = (u) => ({
  id: u.id,
  name: u.name,
  username: u.username,
  role: u.role,
  active: !!u.active,
  created: iso(u.created_at),
  createdBy: u.created_by,
});
const rand = (bytes) => crypto.randomBytes(bytes).toString("hex");

async function checkPassword(plain, hash) {
  const pw = String(plain == null ? "" : plain);
  if (await bcrypt.compare(pw, hash)) return true;
  const trimmed = pw.trim();
  return trimmed !== pw ? bcrypt.compare(trimmed, hash) : false;
}

async function auth(token) {
  if (!token || typeof token !== "string" || token.length > 64) throw new ApiError("unauthorized", 401);
  const [rows] = await pool.query(
    `SELECT u.* FROM crm_sessions s
       JOIN crm_users u ON u.id = s.user_id
      WHERE s.token = ? AND u.active = 1
        AND s.created_at > (UTC_TIMESTAMP() - INTERVAL ${SESSION_DAYS} DAY)`,
    [token]
  );
  if (!rows.length) throw new ApiError("unauthorized", 401);
  return rows[0];
}

/* login throttling (per IP + username, kept in memory) */
const fails = new Map();
function lockSeconds(key) {
  const f = fails.get(key);
  if (!f) return 0;
  const age = Date.now() - f.first;
  if (age > FAIL_WINDOW_MS) {
    fails.delete(key);
    return 0;
  }
  return f.n >= MAX_FAILS ? Math.ceil((FAIL_WINDOW_MS - age) / 1000) : 0;
}
function recordFail(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.first > FAIL_WINDOW_MS) fails.set(key, { n: 1, first: Date.now() });
  else f.n++;
}
setInterval(() => {
  for (const [k, f] of fails) if (Date.now() - f.first > FAIL_WINDOW_MS) fails.delete(k);
}, 10 * 60 * 1000).unref();

/* ---------- the crm_* functions ---------- */
const fns = {
  async crm_login(a, req) {
    const un = String(a.p_username || "").trim().toLowerCase();
    const key = req.ip + "|" + un;
    const wait = lockSeconds(key);
    if (wait) return { error: "locked", seconds: wait };

    const [rows] = await pool.query("SELECT * FROM crm_users WHERE username = ?", [un]);
    const u = rows[0];
    const ok = u ? await checkPassword(a.p_password, u.password_hash) : (await bcrypt.compare("x", DUMMY_HASH), false);
    if (!ok) {
      recordFail(key);
      return { error: "invalid_login" };
    }
    if (!u.active) return { error: "disabled" };

    fails.delete(key);
    const token = rand(24); // 48 hex characters
    await pool.query("INSERT INTO crm_sessions (token, user_id, created_at) VALUES (?, ?, ?)", [token, u.id, new Date()]);
    await pool.query("DELETE FROM crm_sessions WHERE created_at < (UTC_TIMESTAMP() - INTERVAL ? DAY)", [SESSION_DAYS]);
    return { token, user: pub(u) };
  },

  /* ---- phone notifications for task due times ---- */
  async crm_push_key(a) {
    await auth(a.p_token);
    if (!VAPID) throw new ApiError("push_unavailable", 503);
    return { key: VAPID.pub };
  },

  async crm_push_sub(a) {
    const u = await auth(a.p_token);
    const sub = a.p_sub || {};
    const ep = String(sub.endpoint || "");
    if (!/^https:\/\//.test(ep) || ep.length > 1000 || !sub.keys || !sub.keys.p256dh || !sub.keys.auth) throw new ApiError("bad_request");
    const clean = JSON.stringify({ endpoint: ep, keys: { p256dh: String(sub.keys.p256dh), auth: String(sub.keys.auth) } });
    await pool.query("REPLACE INTO crm_push (id, user_id, sub, created_at) VALUES (?, ?, ?, ?)", [subId(ep), u.id, clean, new Date()]);
    return true;
  },

  async crm_push_unsub(a) {
    const u = await auth(a.p_token);
    if (a.p_endpoint) await pool.query("DELETE FROM crm_push WHERE id = ? AND user_id = ?", [subId(a.p_endpoint), u.id]);
    return true;
  },

  async crm_push_test(a) {
    const u = await auth(a.p_token);
    const [rows] = await pool.query("SELECT id, sub FROM crm_push WHERE user_id = ?", [u.id]);
    let n = 0;
    for (const r of rows) if (await pushTo(r, { title: "🔔 Notifications are on", body: "You'll get an alert 15 minutes before a task is due and again at the due time.", tag: "push-test", url: "/?go=tasks" })) n++;
    return { sent: n };
  },

  async crm_me(a) {
    return pub(await auth(a.p_token));
  },

  async crm_logout(a) {
    if (a.p_endpoint) await pool.query("DELETE FROM crm_push WHERE id = ?", [subId(a.p_endpoint)]); // this phone stops getting this user's reminders
    if (a.p_token) await pool.query("DELETE FROM crm_sessions WHERE token = ?", [String(a.p_token)]);
    return true;
  },

  async crm_list(a) {
    const u = await auth(a.p_token);
    const [rows] =
      u.role === "admin"
        ? await pool.query("SELECT id, owner_id AS owner, data FROM crm_docs")
        : await pool.query("SELECT id, owner_id AS owner, data FROM crm_docs WHERE owner_id = ?", [u.id]);
    return rows.map((r) => ({ id: r.id, owner: r.owner, data: typeof r.data === "string" ? JSON.parse(r.data) : r.data }));
  },

  async crm_put(a) {
    const u = await auth(a.p_token);
    const id = String(a.p_id || "");
    const data = a.p_data;
    if (!id || id.length > 64 || !data || typeof data !== "object" || Array.isArray(data)) throw new ApiError("bad_request");
    const json = JSON.stringify(data);
    if (Buffer.byteLength(json) > MAX_DOC_BYTES) throw new ApiError("too_large");

    let newOwner = null;
    if (a.p_owner && u.role === "admin") {
      const [o] = await pool.query("SELECT id FROM crm_users WHERE id = ? AND active = 1", [String(a.p_owner)]);
      if (!o.length) throw new ApiError("bad_owner");
      newOwner = o[0].id;
    }

    const [ex] = await pool.query("SELECT owner_id FROM crm_docs WHERE id = ?", [id]);
    if (ex.length) {
      if (u.role !== "admin" && ex[0].owner_id !== u.id) throw new ApiError("forbidden", 403);
      if (newOwner) await pool.query("UPDATE crm_docs SET data = ?, owner_id = ? WHERE id = ?", [json, newOwner, id]);
      else await pool.query("UPDATE crm_docs SET data = ? WHERE id = ?", [json, id]);
    } else {
      await pool.query("INSERT INTO crm_docs (id, owner_id, data) VALUES (?, ?, ?)", [id, newOwner || u.id, json]);
    }
    return true;
  },

  async crm_delete(a) {
    const u = await auth(a.p_token);
    const id = String(a.p_id || "");
    if (u.role === "admin") await pool.query("DELETE FROM crm_docs WHERE id = ?", [id]);
    else await pool.query("DELETE FROM crm_docs WHERE id = ? AND owner_id = ?", [id, u.id]);
    return true;
  },

  async crm_team_list(a) {
    const u = await auth(a.p_token);
    const [rows] =
      u.role === "admin"
        ? await pool.query("SELECT * FROM crm_users ORDER BY created_at, username")
        : await pool.query("SELECT * FROM crm_users WHERE id = ?", [u.id]);
    return rows.map(pub);
  },

  async crm_team_save(a) {
    const u = await auth(a.p_token);
    if (u.role !== "admin") throw new ApiError("forbidden", 403);
    const un = String(a.p_username || "").toLowerCase().replace(/\s+/g, "");
    const pw = String(a.p_password || "").trim();
    const name = String(a.p_name || "").trim();
    if (!name) throw new ApiError("name_required");
    if (!/^[a-z0-9._-]{3,}$/.test(un)) throw new ApiError("bad_username");

    const [taken] = await pool.query("SELECT id FROM crm_users WHERE username = ? AND id <> ?", [un, String(a.p_id || "")]);
    if (taken.length) throw new ApiError("username_taken");

    try {
      if (!a.p_id) {
        if (pw.length < 6) throw new ApiError("weak_password");
        const id = "u-" + rand(6);
        const hash = await bcrypt.hash(pw, 10);
        await pool.query(
          "INSERT INTO crm_users (id, username, name, role, active, password_hash, created_at, created_by) VALUES (?, ?, ?, 'member', 1, ?, ?, ?)",
          [id, un, name, hash, new Date(), u.name]
        );
        const [r] = await pool.query("SELECT * FROM crm_users WHERE id = ?", [id]);
        return pub(r[0]);
      }

      const [rows] = await pool.query("SELECT * FROM crm_users WHERE id = ?", [String(a.p_id)]);
      const t = rows[0];
      if (!t) throw new ApiError("not_found");
      if (t.role === "admin") throw new ApiError("admin_locked");
      if (pw && pw.length < 6) throw new ApiError("weak_password");

      const active = a.p_active === null || a.p_active === undefined ? !!t.active : !!a.p_active;
      if (pw) {
        const hash = await bcrypt.hash(pw, 10);
        await pool.query("UPDATE crm_users SET name = ?, username = ?, active = ?, password_hash = ? WHERE id = ?", [name, un, active ? 1 : 0, hash, t.id]);
      } else {
        await pool.query("UPDATE crm_users SET name = ?, username = ?, active = ? WHERE id = ?", [name, un, active ? 1 : 0, t.id]);
      }
      if (pw || !active) await pool.query("DELETE FROM crm_sessions WHERE user_id = ?", [t.id]);
      const [r] = await pool.query("SELECT * FROM crm_users WHERE id = ?", [t.id]);
      return pub(r[0]);
    } catch (e) {
      if (e && e.code === "ER_DUP_ENTRY") throw new ApiError("username_taken");
      throw e;
    }
  },

  async crm_team_delete(a) {
    const u = await auth(a.p_token);
    if (u.role !== "admin") throw new ApiError("forbidden", 403);
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [rows] = await conn.query("SELECT * FROM crm_users WHERE id = ? FOR UPDATE", [String(a.p_id || "")]);
      const t = rows[0];
      if (!t) {
        await conn.rollback();
        return true;
      }
      if (t.role === "admin" || t.id === u.id) throw new ApiError("admin_locked");
      await conn.query("UPDATE crm_docs SET owner_id = ? WHERE owner_id = ?", [u.id, t.id]); // hand their schools to the admin
      await conn.query("DELETE FROM crm_users WHERE id = ?", [t.id]); // sessions are removed by ON DELETE CASCADE
      await conn.commit();
      return true;
    } catch (e) {
      await conn.rollback().catch(() => {});
      throw e;
    } finally {
      conn.release();
    }
  },

  async crm_change_password(a) {
    const u = await auth(a.p_token);
    if (!(await checkPassword(a.p_current, u.password_hash))) throw new ApiError("wrong_current");
    const n = String(a.p_new || "").trim();
    if (n.length < 6) throw new ApiError("weak_password");
    const hash = await bcrypt.hash(n, 10);
    await pool.query("UPDATE crm_users SET password_hash = ? WHERE id = ?", [hash, u.id]);
    await pool.query("DELETE FROM crm_sessions WHERE user_id = ? AND token <> ?", [u.id, String(a.p_token)]);
    return true;
  },
};

/* ---------- task reminders (web push) ----------
   Every minute: for each user with notifications on, look at the tasks in the schools they own and
   send "due in 15 minutes" and "due now" alerts. Each alert is recorded in crm_push_sent so it goes
   out once. VAPID keys come from VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY, or are created once and kept
   in crm_kv so nothing has to be set up in Railway. */
let VAPID = null;
const REMIND_MIN = 15;
const LATE_MS = 10 * 60 * 1000; // after a restart, still send alerts that fell due in the last 10 minutes
const subId = (ep) => crypto.createHash("sha256").update(String(ep)).digest("hex");
const NON_SCHOOL = /^(pay_|exp_|exc_|clm_)/;

async function ensureVapid() {
  let pubK = process.env.VAPID_PUBLIC_KEY, privK = process.env.VAPID_PRIVATE_KEY;
  if (!pubK || !privK) {
    const [r] = await pool.query("SELECT v FROM crm_kv WHERE k = 'vapid'");
    if (!r.length) {
      const k = webpush.generateVAPIDKeys();
      await pool.query("INSERT IGNORE INTO crm_kv (k, v) VALUES ('vapid', ?)", [JSON.stringify({ pub: k.publicKey, priv: k.privateKey })]);
    }
    const [r2] = await pool.query("SELECT v FROM crm_kv WHERE k = 'vapid'");
    ({ pub: pubK, priv: privK } = JSON.parse(r2[0].v));
  }
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || "mailto:admin@educlawd.com", pubK, privK);
  VAPID = { pub: pubK };
}

async function pushTo(row, payload) {
  try {
    await webpush.sendNotification(JSON.parse(row.sub), JSON.stringify(payload), { TTL: 3600, urgency: "high" });
    return true;
  } catch (e) {
    if (e && (e.statusCode === 404 || e.statusCode === 410)) await pool.query("DELETE FROM crm_push WHERE id = ?", [row.id]); // phone unsubscribed
    else console.warn("push failed:", e && (e.statusCode || e.message));
    return false;
  }
}

const tz = (d) => new Date(d).toLocaleString("en-IN", { timeZone: process.env.APP_TZ || "Asia/Kolkata", hour: "numeric", minute: "2-digit", day: "numeric", month: "short" });

let ticking = false;
async function pushTick() {
  if (!VAPID || ticking) return;
  ticking = true;
  try {
    const [subs] = await pool.query("SELECT id, user_id, sub FROM crm_push");
    if (!subs.length) return;
    const byUser = new Map();
    subs.forEach((r) => byUser.set(r.user_id, (byUser.get(r.user_id) || []).concat(r)));
    const [docs] = await pool.query("SELECT id, owner_id, data FROM crm_docs WHERE owner_id IN (?)", [[...byUser.keys()]]);
    const now = Date.now();
    for (const d of docs) {
      if (NON_SCHOOL.test(d.id)) continue;
      const s = typeof d.data === "string" ? JSON.parse(d.data) : d.data || {};
      if (s._kind) continue;
      for (const t of s.tasks || []) {
        const due = Date.parse(t.due);
        if (!t.id || isNaN(due)) continue;
        for (const [kind, at] of [["soon", due - REMIND_MIN * 60000], ["due", due]]) {
          if (at > now || now - at > LATE_MS) continue;
          if (kind === "soon" && now >= due) continue; // already due — the "due now" alert covers it
          const key = (d.id + ":" + t.id + ":" + t.due + ":" + kind).slice(0, 190);
          const [ins] = await pool.query("INSERT IGNORE INTO crm_push_sent (k, sent_at) VALUES (?, ?)", [key, new Date()]);
          if (!ins.affectedRows) continue;
          const what = (t.type ? t.type + ": " : "") + (t.title || "Task");
          const payload = {
            title: (kind === "soon" ? "⏰ In " + REMIND_MIN + " min · " : "🔔 Due now · ") + (s.name || "Task"),
            body: what + " — " + tz(due),
            tag: "task-" + t.id,
            url: "/?go=tasks",
          };
          for (const row of byUser.get(d.owner_id) || []) await pushTo(row, payload);
        }
      }
    }
  } catch (e) {
    console.warn("pushTick:", e.message);
  } finally {
    ticking = false;
  }
}
setInterval(pushTick, 60 * 1000).unref();
setInterval(() => pool.query("DELETE FROM crm_push_sent WHERE sent_at < (UTC_TIMESTAMP() - INTERVAL 7 DAY)").catch(() => {}), 6 * 3600 * 1000).unref();

/* ---------- web server ---------- */
const app = express();
app.set("trust proxy", 1); // Railway sits behind a proxy
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.set("X-Content-Type-Options", "nosniff");
  res.set("Referrer-Policy", "same-origin");
  res.set("X-Frame-Options", "DENY");
  next();
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

app.post("/api/rpc/:fn", express.json({ limit: "2mb" }), async (req, res) => {
  const fn = req.params.fn;
  res.set("Cache-Control", "no-store");
  if (!Object.prototype.hasOwnProperty.call(fns, fn)) return res.status(404).json({ message: "not_found" });
  try {
    const out = await fns[fn](req.body && typeof req.body === "object" ? req.body : {}, req);
    res.json(out === undefined ? true : out);
  } catch (e) {
    if (e instanceof ApiError) return res.status(e.status).json({ message: e.code });
    console.error("rpc", fn, e);
    res.status(500).json({ message: "Server error. Please try again." });
  }
});

// malformed JSON etc.
app.use((err, req, res, next) => {
  if (err && err.type === "entity.too.large") return res.status(413).json({ message: "too_large" });
  if (err && err.status === 400) return res.status(400).json({ message: "bad_request" });
  next(err);
});

// only these website files are public (server.js, schema.sql, .env are not)
const sendFile = (name, type) => (req, res) => {
  res.set("Cache-Control", "no-cache");
  if (type) res.type(type);
  res.sendFile(path.join(__dirname, name));
};
app.get("/", sendFile("index.html"));
app.get("/index.html", sendFile("index.html"));
app.get("/sw.js", sendFile("sw.js", "application/javascript"));
app.get("/manifest.webmanifest", sendFile("manifest.webmanifest", "application/manifest+json"));
app.use("/icons", express.static(path.join(__dirname, "icons"), { maxAge: "7d" }));

/* ---------- start-up: create tables + first admin if missing ---------- */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function ensureSchema() {
  const sql = fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8");
  const stmts = sql
    .split("\n")
    .filter((l) => !l.trim().startsWith("--"))
    .join("\n")
    .split(";")
    .map((x) => x.trim())
    .filter(Boolean);
  for (const st of stmts) await pool.query(st); // all are CREATE TABLE IF NOT EXISTS
}

/* one-time rename of the admin from the old default name, everywhere the name was stored */
async function renameAdmin() {
  const OLD = "Educlawd Admin", NEW = "Auqib Bhat";
  try {
    await pool.query("UPDATE crm_users SET name = ? WHERE role = 'admin' AND name = ?", [NEW, OLD]);
    await pool.query("UPDATE crm_users SET created_by = ? WHERE created_by = ?", [NEW, OLD]);
    const [r] = await pool.query(
      "UPDATE crm_docs SET data = REPLACE(CAST(data AS CHAR), ?, ?) WHERE CAST(data AS CHAR) LIKE ?",
      [JSON.stringify(OLD), JSON.stringify(NEW), "%" + OLD + "%"]
    );
    if (r && r.affectedRows) console.log("Renamed admin in " + r.affectedRows + " record(s).");
  } catch (e) {
    console.warn("Admin rename skipped: " + e.message);
  }
}

async function ensureAdmin() {
  const [r] = await pool.query("SELECT id FROM crm_users WHERE role = 'admin' LIMIT 1");
  if (r.length) return;
  const pw = process.env.ADMIN_PASSWORD || "";
  const un = String(process.env.ADMIN_USERNAME || "educlawdcrm").trim().toLowerCase();
  if (pw.length < 6) {
    console.warn("No admin user exists yet. Set ADMIN_PASSWORD (6+ characters) in the Variables tab and redeploy.");
    return;
  }
  const hash = await bcrypt.hash(pw, 10);
  await pool.query(
    "INSERT INTO crm_users (id, username, name, role, active, password_hash, created_at, created_by) VALUES ('u-admin', ?, 'Auqib Bhat', 'admin', 1, ?, ?, 'setup')",
    [un, hash, new Date()]
  );
  console.log("Created admin user '" + un + "'. You can remove ADMIN_PASSWORD from Variables now.");
}

(async () => {
  for (let i = 1; ; i++) {
    try {
      await ensureSchema();
      await ensureAdmin();
      await renameAdmin();
      await ensureVapid().catch((e) => console.warn("Push notifications off: " + e.message));
      break;
    } catch (e) {
      console.error("Database not ready (" + i + "/10): " + e.message);
      if (i >= 10) process.exit(1); // Railway restarts the service
      await sleep(3000);
    }
  }
  app.listen(PORT, () => console.log("Educlawd CRM running on port " + PORT));
})();
