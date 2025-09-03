// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 8080;

/* --------------------------- CORS --------------------------- */
app.use(
  cors({
    origin: (origin, cb) => {
      // allow curl/Postman/no-origin
      if (!origin) return cb(null, true);
      // any localhost:<port> in dev
      if (/^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)) return cb(null, true);
      // allow one prod origin if provided
      if (process.env.CORS_ORIGIN && origin === process.env.CORS_ORIGIN) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '1mb' }));

/* ------------------------- Postgres ------------------------- */
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
    begin new.updated_at = now(); return new; end;
    $$ language plpgsql;

    drop trigger if exists trg_users_updated on users;
    create trigger trg_users_updated before update on users
    for each row execute procedure set_updated_at();
  `);
  console.log('✅ DB ready');
}
initDb().catch((e) => {
  console.error('❌ DB init error:', e);
  process.exit(1);
});

/* ------------------- Firebase Admin (optional) --------------- */
/**
 * If AUTH_REQUIRED !== 'false', we verify Firebase ID tokens.
 * Set these env vars from your Service Account:
 *   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY
 * Make sure FIREBASE_PRIVATE_KEY keeps newlines escaped (\\n) in Render.
 */
const AUTH_REQUIRED = process.env.AUTH_REQUIRED !== 'false';

if (AUTH_REQUIRED) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: process.env.FIREBASE_PROJECT_ID,
        clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
        privateKey: (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n'),
      }),
    });
    console.log('🔐 Firebase Admin initialized (auth required)');
  } catch (e) {
    console.error('Firebase Admin init failed:', e.message);
    process.exit(1);
  }
} else {
  console.log('🔓 AUTH_REQUIRED=false — dev mode (no Firebase token check)');
}

async function requireAuth(req, res, next) {
  if (!AUTH_REQUIRED) return next(); // dev mode; not verifying token

  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });

  try {
    const decoded = await admin.auth().verifyIdToken(token);
    req.auth = decoded; // contains phone_number (from Firebase)
    return next();
  } catch (e) {
    console.error('ID token verify failed:', e.message);
    return res.status(401).json({ error: 'invalid_token' });
  }
}

/* --------------------------- Routes -------------------------- */
app.get('/', (_req, res) => res.send('KK backend OK'));

app.get('/db', async (_req, res) => {
  const r = await pool.query('select now() as now');
  res.json(r.rows[0]);
});

/**
 * GET /me
 * - If AUTH_REQUIRED=true   -> use phone from verified Firebase token
 * - If AUTH_REQUIRED=false  -> accept ?phone= for dev
 */
app.get('/me', requireAuth, async (req, res) => {
  try {
    const phone = AUTH_REQUIRED
      ? (req.auth?.phone_number || req.auth?.phoneNumber)
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
 * - Phone is derived from token (auth) or from body (dev).
 */
app.put('/me', requireAuth, async (req, res) => {
  try {
    const phone = AUTH_REQUIRED
      ? (req.auth?.phone_number || req.auth?.phoneNumber)
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

/* --------------------------- Boot ---------------------------- */
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
