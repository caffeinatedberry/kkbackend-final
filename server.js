// server.js
// Backend for KK with Firebase Phone Auth + Postgres profiles

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 8080;

/* ============================ CORS ============================ */
app.use(
  cors({
    // allow curl/Postman/no-origin
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      // any localhost:<port> in dev
      if (/^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)) return cb(null, true);
      // single prod origin if provided
      if (process.env.CORS_ORIGIN && origin === process.env.CORS_ORIGIN) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '1mb' }));

/* ============================ DB ============================= */
// Render external Postgres typically needs SSL from local/dev.
// On Render, SSL with rejectUnauthorized:false is fine.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === 'false'
      ? false
      : { rejectUnauthorized: false },
});

async function initDb() {
  await pool.query(`
    create table if not exists users (
      id serial primary key,
      phone text unique not null,
      full_name text,
      age int,
      address text,
      avatar_url text,
      created_at timestamptz default now(),
      updated_at timestamptz default now()
    );

    create or replace function set_updated_at()
    returns trigger as $$
    begin
      new.updated_at = now();
      return new;
    end;
    $$ language plpgsql;

    drop trigger if exists trg_users_updated on users;
    create trigger trg_users_updated
      before update on users
      for each row execute procedure set_updated_at();
  `);
  console.log('✅ DB ready');
}
initDb().catch((e) => {
  console.error('❌ DB init error:', e);
  process.exit(1);
});

/* ====================== Firebase Admin ======================= */
/**
 * Use ONE of these on Render (Environment settings):
 *  A) FIREBASE_SERVICE_ACCOUNT_BASE64 = base64(serviceAccount.json)
 *     (recommended)
 *  B) FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY
 *     (PRIVATE_KEY may contain \n escapes; we handle that)
 *
 * Toggle auth requirement:
 *   AUTH_REQUIRED=false   -> dev mode (no token verification)
 *   (omit or true)        -> verify Firebase ID tokens (recommended for prod)
 */
const AUTH_REQUIRED = process.env.AUTH_REQUIRED !== 'false';

function initFirebaseAdmin() {
  if (!AUTH_REQUIRED) {
    console.log('🔓 AUTH_REQUIRED=false — dev mode (no Firebase token check)');
    return; // skip admin init in dev mode
  }

  try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_BASE64) {
      const json = Buffer.from(
        process.env.FIREBASE_SERVICE_ACCOUNT_BASE64,
        'base64'
      ).toString('utf8');
      const sa = JSON.parse(json);
      admin.initializeApp({ credential: admin.credential.cert(sa) });
      console.log('✅ Firebase Admin initialized (base64)');
      return;
    }

    const pid = process.env.FIREBASE_PROJECT_ID;
    const email = process.env.FIREBASE_CLIENT_EMAIL;
    let key = process.env.FIREBASE_PRIVATE_KEY;

    if (pid && email && key) {
      // handle \n escape sequences and possible surrounding quotes
      if (key.startsWith('"') && key.endsWith('"')) {
        key = key.slice(1, -1);
      }
      key = key.replace(/\\n/g, '\n');

      admin.initializeApp({
        credential: admin.credential.cert({
          project_id: pid,
          client_email: email,
          private_key: key,
        }),
      });
      console.log('✅ Firebase Admin initialized (separate env vars)');
      return;
    }

    throw new Error('No Firebase Admin credentials found in env');
  } catch (err) {
    console.error('❌ Firebase Admin init failed:', err?.message || err);
    process.exit(1);
  }
}
initFirebaseAdmin();

/* ===================== Auth Middleware ======================= */
async function requireAuth(req, res, next) {
  if (!AUTH_REQUIRED) return next(); // dev mode

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.auth = decoded; // contains phone_number (E.164) if using phone auth
    return next();
  } catch (e) {
    console.error('ID token verify failed:', e?.message || e);
    return res.status(401).json({ error: 'invalid_token' });
  }
}

/* =========================== Routes ========================== */
app.get('/', (_req, res) => res.send('KK backend OK (Firebase)'));

app.get('/db', async (_req, res) => {
  const r = await pool.query('select now() as now');
  res.json(r.rows[0]);
});

/**
 * GET /me
 *  - PROD (AUTH_REQUIRED=true): phone from Firebase token (req.auth.phone_number)
 *  - DEV  (AUTH_REQUIRED=false): pass ?phone=+65xxxx
 */
app.get('/me', requireAuth, async (req, res) => {
  try {
    const phone = AUTH_REQUIRED
      ? (req.auth?.phone_number || req.auth?.phoneNumber || null)
      : (req.query.phone || null);

    if (!phone) return res.status(400).json({ error: 'missing_phone' });

    const r = await pool.query('select * from users where phone=$1', [phone]);
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'me_failed' });
  }
});

/**
 * PUT /me
 * Body: { fullName?, age?, address?, avatarUrl? }
 *  - PROD: phone comes from Firebase token
 *  - DEV : include phone in body
 */
app.put('/me', requireAuth, async (req, res) => {
  try {
    const phone = AUTH_REQUIRED
      ? (req.auth?.phone_number || req.auth?.phoneNumber || null)
      : (req.body?.phone || null);

    if (!phone) return res.status(400).json({ error: 'missing_phone' });

    const { fullName, age, address, avatarUrl } = req.body || {};
    const r = await pool.query(
      `insert into users (phone, full_name, age, address, avatar_url)
       values ($1, $2, $3, $4, $5)
       on conflict (phone) do update
       set full_name = excluded.full_name,
           age       = excluded.age,
           address   = excluded.address,
           avatar_url= excluded.avatar_url
       returning *`,
      [phone, fullName ?? null, age ?? null, address ?? null, avatarUrl ?? null]
    );

    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'update_failed' });
  }
});

/* ========================== Boot ============================= */
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
