import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-render';
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('Missing DATABASE_URL environment variable.');
  process.exit(1);
}

if (JWT_SECRET === 'change-this-secret-in-render') {
  console.warn('WARNING: JWT_SECRET is using the development fallback. Set JWT_SECRET in Render.');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,
});

app.disable('x-powered-by');

app.use(cors({
  origin: '*',
  credentials: false
}));

app.use(express.json({ limit: '1mb' }));

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'buyer'
        CHECK (role IN ('buyer', 'seller', 'admin')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS listings (
      id BIGSERIAL PRIMARY KEY,
      seller_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      price NUMERIC(12,2) NOT NULL CHECK (price > 0),
      status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'sold', 'cancelled')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,
      listing_id BIGINT NOT NULL
        REFERENCES listings(id) ON DELETE RESTRICT,
      buyer_id BIGINT NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'paid', 'completed', 'cancelled')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_listings_status_created
      ON listings(status, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_orders_buyer
      ON orders(buyer_id, created_at DESC);
  `);
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'unauthorized'
      });
    }

    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      error: 'unauthorized'
    });
  }
}

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'efootball-market-api',
    health: '/api/health'
  });
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'efootball-market-api'
    });
  } catch (error) {
    console.error('Health check failed:', error);

    res.status(503).json({
      ok: false,
      error: 'database unavailable'
    });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = String(
      req.body?.email || ''
    ).trim().toLowerCase();

    const password = String(
      req.body?.password || ''
    );

    const role =
      req.body?.role === 'seller'
        ? 'seller'
        : 'buyer';

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return res.status(400).json({
        error: 'valid email required'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: 'password must be at least 6 characters'
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
        (email, password_hash, role)
       VALUES
        ($1, $2, $3)
       RETURNING
        id, email, role, created_at`,
      [
        email,
        passwordHash,
        role
      ]
    );

    const user = result.rows[0];

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    res.status(201).json({
      token,
      user
    });

  } catch (error) {

    if (error.code === '23505') {
      return res.status(409).json({
        error: 'email already exists'
      });
    }

    console.error(
      'Register error:',
      error
    );

    res.status(500).json({
      error: 'server error'
    });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(
      req.body?.email || ''
    ).trim().toLowerCase();

    const password = String(
      req.body?.password || ''
    );

    const result = await pool.query(
      `SELECT
        id,
        email,
        password_hash,
        role,
        created_at
       FROM users
       WHERE email = $1`,
      [email]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        password,
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: 'invalid credentials'
      });
    }

    const row = result.rows[0];

    const user = {
      id: row.id,
      email: row.email,
      role: row.role,
      created_at: row.created_at
    };

    const token = jwt.sign(
      user,
      JWT_SECRET,
      {
        expiresIn: '7d'
      }
    );

    res.json({
      token,
      user
    });

  } catch (error) {

    console.error(
      'Login error:',
      error
    );

    res.status(500).json({
      error: 'server error'
    });
  }
});

app.get('/api/listings', async (_req, res) => {
  try {

    const result = await pool.query(`
      SELECT
        l.id,
        l.title,
        l.price,
        l.status,
        l.created_at,
        u.email AS seller_email
      FROM listings l
      JOIN users u
        ON u.id = l.seller_id
      WHERE l.status = 'active'
      ORDER BY l.created_at DESC
    `);

    res.json(result.rows);

  } catch (error) {

    console.error(
      'Listings error:',
      error
    );

    res.status(500).json({
      error: 'server error'
    });
  }
});

app.post('/api/listings', auth, async (req, res) => {
  try {

    const title = String(
      req.body?.title || ''
    ).trim();

    const price = Number(
      req.body?.price
    );

    if (
      !title ||
      !Number.isFinite(price) ||
      price <= 0
    ) {
      return res.status(400).json({
        error: 'title and positive price required'
      });
    }

    const result = await pool.query(
      `INSERT INTO listings
        (seller_id, title, price)
       VALUES
        ($1, $2, $3)
       RETURNING
        id,
        seller_id,
        title,
        price,
        status,
        created_at`,
      [
        req.user.id,
        title,
        price
      ]
    );

    res.status(201).json(
      result.rows[0]
    );

  } catch (error) {

    console.error(
      'Create listing error:',
      error
    );

    res.status(500).json({
      error: 'server error'
    });
  }
});

app.post('/api/orders', auth, async (req, res) => {
  try {

    const listingId = Number(
      req.body?.listing_id
    );

    if (
      !Number.isInteger(listingId) ||
      listingId <= 0
    ) {
      return res.status(400).json({
        error: 'valid listing_id required'
      });
    }

    const result = await pool.query(
      `INSERT INTO orders
        (listing_id, buyer_id)
       SELECT
        $1,
        $2
       WHERE EXISTS (
         SELECT 1
         FROM listings
         WHERE id = $1
         AND status = 'active'
       )
       RETURNING
        id,
        listing_id,
        buyer_id,
        status,
        created_at`,
      [
        listingId,
        req.user.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: 'listing not found or not active'
      });
    }

    res.status(201).json(
      result.rows[0]
    );

  } catch (error) {

    console.error(
      'Create order error:',
      error
    );

    res.status(500).json({
      error: 'server error'
    });
  }
});

app.use(
  (err, _req, res, _next) => {
    console.error(
      'Unhandled error:',
      err
    );

    res.status(500).json({
      error: 'server error'
    });
  }
);

app.get('/health', (_req, res) => {
  res.status(200).json({ ok: true });
});

async function start() {

  await initDatabase();

  const server = app.listen(
  PORT,
  '0.0.0.0',
  () => {
      console.log(
        `eFootball Market API listening on port ${PORT}`
      );
    }
  );

  const shutdown = async () => {

    server.close(
      async () => {
        await pool.end();
        process.exit(0);
      }
    );
  };

  process.on(
    'SIGTERM',
    shutdown
  );

  process.on(
    'SIGINT',
    shutdown
  );
}

start().catch(
  (error) => {
    console.error(
      'Startup failed:',
      error
    );

    process.exit(1);
  }
);
