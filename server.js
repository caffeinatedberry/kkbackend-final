// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const twilio = require('twilio')(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const app = express();
const PORT = process.env.PORT || 8080;

/* ------------------------- Middleware ------------------------- */
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (/^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)) return cb(null, true);
      if (process.env.CORS_ORIGIN && origin === process.env.CORS_ORIGIN) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '1mb' }));

/* ------------------------- Postgres --------------------------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
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

/* --------------------------- Routes --------------------------- */
app.get('/', (_req, res) => res.send('KK backend OK'));
app.get('/db', async (_req, res) => {
  const r = await pool.query('select now() as now');
  res.json(r.rows[0]);
});

/* ----------------- REAL OTP via Twilio Verify ----------------- */
const toE164 = (s) => (s?.startsWith('+') ? s : `+${s}`);

app.post('/auth/start', async (req, res) => {
  try {
    const { phone, channel = 'sms' } = req.body || {};
    if (!phone) return res.status(400).json({ error: 'missing_phone' });

    await twilio.verify.v2
      .services(process.env.TWILIO_VERIFY_SID)
      .verifications.create({ to: toE164(phone), channel });

    res.json({ ok: true }); // <- no devCode now
  } catch (e) {
    console.error('start_failed:', e?.message || e);
    res.status(500).json({ error: 'start_failed' });
  }
});

app.post('/auth/verify', async (req, res) => {
  try {
    const { phone, code } = req.body || {};
    if (!phone || !code) return res.status(400).json({ error: 'missing_params' });

    const check = await twilio.verify.v2
      .services(process.env.TWILIO_VERIFY_SID)
      .verificationChecks.create({ to: toE164(phone), code });

    if (check.status !== 'approved') {
      return res.status(401).json({ error: 'invalid_code' });
    }

    const upsert = await pool.query(
      `insert into users (phone) values ($1)
       on conflict (phone) do update set phone = excluded.phone
       returning *`,
      [toE164(phone)]
    );

    res.json({ user: upsert.rows[0] });
  } catch (e) {
    console.error('verify_failed:', e?.message || e);
    res.status(500).json({ error: 'verify_failed' });
  }
});

/* ----------------------- Profile endpoints -------------------- */
app.get('/me', async (req, res) => {
  try {
    const { phone } = req.query;
    if (!phone) return res.status(400).json({ error: 'missing_phone' });
    const r = await pool.query('select * from users where phone=$1', [phone]);
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'me_failed' });
  }
});

app.put('/me', async (req, res) => {
  try {
    const { phone, fullName, age, address, avatarUrl } = req.body || {};
    if (!phone) return res.status(400).json({ error: 'missing_phone' });
    const r = await pool.query(
      `update users
       set full_name=$1, age=$2, address=$3, avatar_url=$4
       where phone=$5
       returning *`,
      [fullName ?? null, age ?? null, address ?? null, avatarUrl ?? null, phone]
    );
    res.json(r.rows[0] || null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'update_failed' });
  }
});

app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
