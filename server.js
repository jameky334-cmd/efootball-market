import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { Pool } = pg;
const app = express();

const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = String(
  process.env.FRONTEND_ORIGIN || ''
).trim();
const NODE_ENV = process.env.NODE_ENV || 'production';

if (!DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is missing.');
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error('ERROR: JWT_SECRET is missing.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  ssl:
    NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
});

pool.on('error', (err) => {
  console.error('PostgreSQL pool error:', err);
});

app.disable('x-powered-by');

app.use(
  cors({
    origin: FRONTEND_ORIGIN
      ? FRONTEND_ORIGIN
          .split(',')
          .map((v) => v.trim())
          .filter(Boolean)
      : '*',
    credentials: false
  })
);

app.use(
  express.json({
    limit: '1mb'
  })
);

const fail = (res, status, error) =>
  res.status(status).json({ error });

function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';

    if (!header.startsWith('Bearer ')) {
      return fail(res, 401, 'unauthorized');
    }

    req.user = jwt.verify(
      header.slice(7),
      JWT_SECRET
    );

    next();
  } catch {
    return fail(res, 401, 'unauthorized');
  }
}

function role(...roles) {
  return (req, res, next) => {
    if (
      !req.user ||
      !roles.includes(req.user.role)
    ) {
      return fail(res, 403, 'forbidden');
    }

    next();
  };
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'buyer'
        CHECK (
          role IN ('buyer','seller','admin')
        ),
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS listings (
      id BIGSERIAL PRIMARY KEY,
      seller_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

      title TEXT NOT NULL,

      description TEXT NOT NULL DEFAULT '',

      price NUMERIC(12,2) NOT NULL
        CHECK (price > 0),

      status TEXT NOT NULL DEFAULT 'active'
        CHECK (
          status IN (
            'active',
            'sold',
            'cancelled'
          )
        ),

      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS
      description TEXT NOT NULL DEFAULT '';

    CREATE TABLE IF NOT EXISTS orders (
      id BIGSERIAL PRIMARY KEY,

      listing_id BIGINT NOT NULL
        REFERENCES listings(id)
        ON DELETE RESTRICT,

      buyer_id BIGINT NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
          status IN (
            'pending',
            'paid',
            'completed',
            'cancelled'
          )
        ),

      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS
      idx_listings_status_created
      ON listings(status, created_at DESC);

    CREATE INDEX IF NOT EXISTS
      idx_listings_seller
      ON listings(seller_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS
      idx_orders_buyer
      ON orders(buyer_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS
      idx_orders_listing
      ON orders(listing_id, created_at DESC);

    CREATE UNIQUE INDEX IF NOT EXISTS
      uniq_open_order_per_listing
      ON orders(listing_id)
      WHERE status IN ('pending','paid');
  `);

  console.log('Database initialized.');
}

/* =========================
   HEALTH
========================= */

app.get('/', (_req, res) => {
  res.json({
    ok: true,
    service: 'efootball-market-api',
    version: '3.0.0',
    health: '/health',
    apiHealth: '/api/health'
  });
});

app.get('/health', (_req, res) => {
  res.status(200).json({
    ok: true,
    service: 'efootball-market-api'
  });
});

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'efootball-market-api',
      database: 'connected'
    });
  } catch (err) {
    console.error(
      'API health database error:',
      err
    );

    res.status(503).json({
      ok: false,
      service: 'efootball-market-api',
      database: 'unavailable'
    });
  }
});

/* =========================
   REGISTER
========================= */

app.post(
  '/api/auth/register',
  async (req, res) => {
    try {
      const email = String(
        req.body?.email || ''
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body?.password || ''
      );

      if (
        !/^\S+@\S+\.\S+$/.test(email)
      ) {
        return fail(
          res,
          400,
          'valid email required'
        );
      }

      if (password.length < 6) {
        return fail(
          res,
          400,
          'password must be at least 6 characters'
        );
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await pool.query(
          `
          INSERT INTO users
            (
              email,
              password_hash,
              role
            )
          VALUES
            ($1,$2,'buyer')
          RETURNING
            id,
            email,
            role,
            created_at
          `,
          [
            email,
            hash
          ]
        );

      const user =
        result.rows[0];

      const token =
        jwt.sign(
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
    } catch (err) {
      if (
        err?.code === '23505'
      ) {
        return fail(
          res,
          409,
          'email already exists'
        );
      }

      console.error(
        'Register error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  '/api/auth/login',
  async (req, res) => {
    try {
      const email = String(
        req.body?.email || ''
      )
        .trim()
        .toLowerCase();

      const password = String(
        req.body?.password || ''
      );

      if (!email || !password) {
        return fail(
          res,
          400,
          'email and password required'
        );
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            email,
            password_hash,
            role,
            created_at
          FROM users
          WHERE email = $1
          LIMIT 1
          `,
          [email]
        );

      if (!result.rowCount) {
        return fail(
          res,
          401,
          'invalid credentials'
        );
      }

      const row =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          row.password_hash
        );

      if (!valid) {
        return fail(
          res,
          401,
          'invalid credentials'
        );
      }

      const user = {
        id: row.id,
        email: row.email,
        role: row.role,
        created_at: row.created_at
      };

      const token =
        jwt.sign(
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
    } catch (err) {
      console.error(
        'Login error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   PUBLIC LISTINGS
========================= */

app.get(
  '/api/listings',
  async (_req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            l.id,
            l.title,
            l.description,
            l.price,
            l.status,
            l.created_at,
            u.email AS seller_email
          FROM listings l
          JOIN users u
            ON u.id = l.seller_id
          WHERE l.status = 'active'
          ORDER BY
            l.created_at DESC
        `);

      res.json(
        result.rows
      );
    } catch (err) {
      console.error(
        'Listings error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   CREATE LISTING
========================= */

app.post(
  '/api/listings',
  auth,
  role('seller', 'admin'),
  async (req, res) => {
    try {
      const title =
        String(
          req.body?.title || ''
        ).trim();

      const description =
        String(
          req.body?.description || ''
        ).trim();

      const price =
        Number(
          req.body?.price
        );

      if (!title) {
        return fail(
          res,
          400,
          'title required'
        );
      }

      if (title.length > 200) {
        return fail(
          res,
          400,
          'title too long'
        );
      }

      if (
        !Number.isFinite(price) ||
        price <= 0
      ) {
        return fail(
          res,
          400,
          'positive price required'
        );
      }

      if (description.length > 5000) {
        return fail(
          res,
          400,
          'description too long'
        );
      }

      const result =
        await pool.query(
          `
          INSERT INTO listings
            (
              seller_id,
              title,
              description,
              price
            )
          VALUES
            ($1,$2,$3,$4)
          RETURNING
            id,
            seller_id,
            title,
            description,
            price,
            status,
            created_at
          `,
          [
            req.user.id,
            title,
            description,
            price
          ]
        );

      res.status(201).json(
        result.rows[0]
      );
    } catch (err) {
      console.error(
        'Create listing error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   MY LISTINGS
========================= */

app.get(
  '/api/my-listings',
  auth,
  role('seller', 'admin'),
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            seller_id,
            title,
            description,
            price,
            status,
            created_at
          FROM listings
          WHERE seller_id = $1
          ORDER BY
            created_at DESC
          `,
          [req.user.id]
        );

      res.json(
        result.rows
      );
    } catch (err) {
      console.error(
        'My listings error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   UPDATE LISTING
========================= */

app.patch(
  '/api/listings/:id',
  auth,
  role('seller', 'admin'),
  async (req, res) => {
    try {
      const id =
        Number(req.params.id);

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return fail(
          res,
          400,
          'valid listing id required'
        );
      }

      const current =
        await pool.query(
          `
          SELECT
            id,
            seller_id,
            status
          FROM listings
          WHERE id = $1
          LIMIT 1
          `,
          [id]
        );

      if (!current.rowCount) {
        return fail(
          res,
          404,
          'listing not found'
        );
      }

      const listing =
        current.rows[0];

      if (
        req.user.role !== 'admin' &&
        String(
          listing.seller_id
        ) !==
          String(req.user.id)
      ) {
        return fail(
          res,
          403,
          'forbidden'
        );
      }

      if (
        listing.status === 'sold'
      ) {
        return fail(
          res,
          409,
          'sold listing cannot be edited'
        );
      }

      const has = (key) =>
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          key
        );

      const title = has('title')
        ? String(
            req.body.title ?? ''
          ).trim()
        : undefined;

      const description = has(
        'description'
      )
        ? String(
            req.body.description ?? ''
          ).trim()
        : undefined;

      const price = has('price')
        ? Number(req.body.price)
        : undefined;

      const status = has('status')
        ? String(
            req.body.status ?? ''
          ).trim()
        : undefined;

      if (
        title !== undefined &&
        (!title || title.length > 200)
      ) {
        return fail(
          res,
          400,
          'invalid title'
        );
      }

      if (
        description !== undefined &&
        description.length > 5000
      ) {
        return fail(
          res,
          400,
          'description too long'
        );
      }

      if (
        price !== undefined &&
        (!Number.isFinite(price) ||
          price <= 0)
      ) {
        return fail(
          res,
          400,
          'positive price required'
        );
      }

      if (
        status !== undefined &&
        ![
          'active',
          'cancelled'
        ].includes(status)
      ) {
        return fail(
          res,
          400,
          'invalid status'
        );
      }

      const result =
        await pool.query(
          `
          UPDATE listings
          SET
            title = COALESCE($1, title),
            description = COALESCE($2, description),
            price = COALESCE($3, price),
            status = COALESCE($4, status)
          WHERE id = $5
          RETURNING
            id,
            seller_id,
            title,
            description,
            price,
            status,
            created_at
          `,
          [
            title,
            description,
            price,
            status,
            id
          ]
        );

      res.json(
        result.rows[0]
      );
    } catch (err) {
      console.error(
        'Update listing error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   CREATE ORDER
========================= */

app.post(
  '/api/orders',
  auth,
  role('buyer', 'admin'),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const listingId =
        Number(
          req.body?.listing_id
        );

      if (
        !Number.isInteger(
          listingId
        ) ||
        listingId <= 0
      ) {
        return fail(
          res,
          400,
          'valid listing_id required'
        );
      }

      await client.query(
        'BEGIN'
      );

      const listingResult =
        await client.query(
          `
          SELECT
            id,
            seller_id,
            title,
            description,
            price,
            status
          FROM listings
          WHERE id = $1
          FOR UPDATE
          `,
          [listingId]
        );

      if (!listingResult.rowCount) {
        await client.query(
          'ROLLBACK'
        );

        return fail(
          res,
          404,
          'listing not found'
        );
      }

      const listing =
        listingResult.rows[0];

      if (
        listing.status !== 'active'
      ) {
        await client.query(
          'ROLLBACK'
        );

        return fail(
          res,
          409,
          'listing not active'
        );
      }

      if (
        String(
          listing.seller_id
        ) ===
        String(
          req.user.id
        )
      ) {
        await client.query(
          'ROLLBACK'
        );

        return fail(
          res,
          403,
          'cannot buy your own listing'
        );
      }

      const open =
        await client.query(
          `
          SELECT
            id
          FROM orders
          WHERE listing_id = $1
            AND status IN (
              'pending',
              'paid'
            )
          LIMIT 1
          `,
          [listingId]
        );

      if (open.rowCount) {
        await client.query(
          'ROLLBACK'
        );

        return fail(
          res,
          409,
          'listing already has an open order'
        );
      }

      const order =
        await client.query(
          `
          INSERT INTO orders
            (
              listing_id,
              buyer_id,
              status
            )
          VALUES
            (
              $1,
              $2,
              'pending'
            )
          RETURNING
            id,
            listing_id,
            buyer_id,
            status,
            created_at
          `,
          [
            listingId,
            req.user.id
          ]
        );

      await client.query(
        'COMMIT'
      );

      res.status(201).json({
        ...order.rows[0],
        title:
          listing.title,
        description:
          listing.description,
        price:
          listing.price
      });
    } catch (err) {
      try {
        await client.query(
          'ROLLBACK'
        );
      } catch {}

      if (
        err?.code === '23505'
      ) {
        return fail(
          res,
          409,
          'listing already has an open order'
        );
      }

      console.error(
        'Create order error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    } finally {
      client.release();
    }
  }
);

/* =========================
   GET ORDERS
========================= */

app.get(
  '/api/orders',
  auth,
  async (req, res) => {
    try {
      let result;

      if (
        req.user.role === 'admin'
      ) {
        result =
          await pool.query(`
            SELECT
              o.id,
              o.listing_id,
              o.buyer_id,
              o.status,
              o.created_at,
              l.title,
              l.description,
              l.price,
              buyer.email AS buyer_email,
              seller.email AS seller_email
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
            JOIN users buyer
              ON buyer.id = o.buyer_id
            JOIN users seller
              ON seller.id = l.seller_id
            ORDER BY
              o.created_at DESC
          `);
      } else if (
        req.user.role === 'seller'
      ) {
        result =
          await pool.query(
            `
            SELECT
              o.id,
              o.listing_id,
              o.buyer_id,
              o.status,
              o.created_at,
              l.title,
              l.description,
              l.price,
              buyer.email AS buyer_email
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
            JOIN users buyer
              ON buyer.id = o.buyer_id
            WHERE l.seller_id = $1
            ORDER BY
              o.created_at DESC
            `,
            [req.user.id]
          );
      } else {
        result =
          await pool.query(
            `
            SELECT
              o.id,
              o.listing_id,
              o.buyer_id,
              o.status,
              o.created_at,
              l.title,
              l.description,
              l.price,
              seller.email AS seller_email
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
            JOIN users seller
              ON seller.id = l.seller_id
            WHERE o.buyer_id = $1
            ORDER BY
              o.created_at DESC
            `,
            [req.user.id]
          );
      }

      res.json(
        result.rows
      );
    } catch (err) {
      console.error(
        'Orders error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   GET SINGLE ORDER
========================= */

app.get(
  '/api/orders/:id',
  auth,
  async (req, res) => {
    try {
      const orderId =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(
          orderId
        ) ||
        orderId <= 0
      ) {
        return fail(
          res,
          400,
          'valid order id required'
        );
      }

      const result =
        await pool.query(
          `
          SELECT
            o.id,
            o.listing_id,
            o.buyer_id,
            o.status,
            o.created_at,
            l.title,
            l.description,
            l.price,
            l.seller_id,
            buyer.email AS buyer_email,
            seller.email AS seller_email
          FROM orders o
          JOIN listings l
            ON l.id = o.listing_id
          JOIN users buyer
            ON buyer.id = o.buyer_id
          JOIN users seller
            ON seller.id = l.seller_id
          WHERE o.id = $1
            AND (
              $2 = 'admin'
              OR o.buyer_id = $3
              OR l.seller_id = $3
            )
          LIMIT 1
          `,
          [
            orderId,
            req.user.role,
            req.user.id
          ]
        );

      if (!result.rowCount) {
        return fail(
          res,
          404,
          'order not found'
        );
      }

      res.json(
        result.rows[0]
      );
    } catch (err) {
      console.error(
        'Get order error:',
        err
      );

      fail(
        res,
        500,
        'server error'
      );
    }
  }
);

/* =========================
   UPDATE ORDER STATUS
========================= */

app.patch(
  '/api/orders/:id/status',
  auth,
  role('seller', 'admin'),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const id =
        Number(req.params.id);

      const next =
        String(
          req.body?.status || ''
       