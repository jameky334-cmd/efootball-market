import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const { Pool } = pg;
const app = express();

const VERSION = "5.1.0";
const PORT = Number(process.env.PORT || 10000);

const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET || "";
const DELIVERY_ENCRYPTION_KEY = process.env.DELIVERY_ENCRYPTION_KEY || "";
const ADMIN_BOOTSTRAP_SECRET = process.env.ADMIN_BOOTSTRAP_SECRET || "";

if (!DATABASE_URL) throw new Error("DATABASE_URL is missing");
if (!JWT_SECRET) throw new Error("JWT_SECRET is missing");

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  next();
});

const allowedOrigins = FRONTEND_ORIGIN.split(",").map(x => x.trim()).filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin) return callback(null, true);

    if (
      NODE_ENV !== "production" &&
      (
        origin.startsWith("http://localhost:") ||
        origin.startsWith("http://127.0.0.1:")
      )
    ) {
      return callback(null, true);
    }

    if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("CORS origin not allowed"));
  },
  methods: ["GET", "POST", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Webhook-Secret"
  ]
}));

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const rateLimitStore = new Map();

function rateLimit({
  windowMs = 60000,
  max = 60,
  message = "Too many requests"
} = {}) {
  return (req, res, next) => {
    const ip =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket.remoteAddress ||
      "unknown";

    const key = `${req.path}:${ip}`;
    const now = Date.now();
    const current = rateLimitStore.get(key);

    if (!current || now - current.start >= windowMs) {
      rateLimitStore.set(key, {
        start: now,
        count: 1
      });

      return next();
    }

    current.count++;

    if (current.count > max) {
      return res.status(429).json({
        error: message
      });
    }

    next();
  };
}

setInterval(() => {
  const now = Date.now();

  for (const [key, value] of rateLimitStore.entries()) {
    if (now - value.start > 10 * 60 * 1000) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

function cleanText(value, max = 500) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, max);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPrice(price) {
  const n = Number(price);

  return (
    Number.isFinite(n) &&
    n > 0 &&
    n <= 100000000
  );
}

function normalizePrice(price) {
  return Number(Number(price).toFixed(2));
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role
  };
}

function signToken(user) {
  return jwt.sign(
    { id: user.id },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function getDeliveryKey() {
  if (!/^[0-9a-fA-F]{64}$/.test(DELIVERY_ENCRYPTION_KEY)) {
    return null;
  }

  return Buffer.from(
    DELIVERY_ENCRYPTION_KEY,
    "hex"
  );
}

function encryptDelivery(value) {
  const key = getDeliveryKey();

  if (!key) {
    throw new Error(
      "DELIVERY_ENCRYPTION_KEY is not configured correctly"
    );
  }

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const ciphertext = Buffer.concat([
    cipher.update(String(value), "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64")
  ].join(".");
}

function decryptDelivery(value) {
  const key = getDeliveryKey();

  if (!key) {
    throw new Error(
      "DELIVERY_ENCRYPTION_KEY is not configured correctly"
    );
  }

  const parts = String(value || "").split(".");

  if (parts.length !== 3) {
    throw new Error(
      "Invalid encrypted delivery data"
    );
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(parts[0], "base64")
  );

  decipher.setAuthTag(
    Buffer.from(parts[1], "base64")
  );

  return Buffer.concat([
    decipher.update(
      Buffer.from(parts[2], "base64")
    ),
    decipher.final()
  ]).toString("utf8");
}

async function auth(req, res, next) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const decoded = jwt.verify(
      header.slice(7).trim(),
      JWT_SECRET
    );

    if (!decoded?.id) {
      return res.status(401).json({
        error: "Invalid token"
      });
    }

    const result = await pool.query(
      `SELECT id, email, role
       FROM users
       WHERE id = $1
       LIMIT 1`,
      [decoded.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    req.user = result.rows[0];

    next();
  } catch {
    res.status(401).json({
      error: "Invalid or expired token"
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Permission denied"
      });
    }

    next();
  };
}

async function audit(
  client,
  userId,
  action,
  entityType,
  entityId,
  details = {}
) {
  await client.query(
    `INSERT INTO audit_logs
     (user_id, action, entity_type, entity_id, details)
     VALUES ($1,$2,$3,$4,$5::jsonb)`,
    [
      userId || null,
      action,
      entityType,
      entityId || null,
      JSON.stringify(details)
    ]
  );
}

async function initializeDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'buyer'
          CHECK (role IN ('buyer','seller','admin')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id BIGSERIAL PRIMARY KEY,
        seller_id BIGINT NOT NULL
          REFERENCES users(id)
          ON DELETE CASCADE,
        title TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        price NUMERIC(12,2) NOT NULL
          CHECK (price > 0),
        account_data_encrypted TEXT,
        image_url TEXT,
        status TEXT NOT NULL DEFAULT 'active'
          CHECK (
            status IN (
              'active',
              'sold',
              'cancelled'
            )
          ),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id BIGSERIAL PRIMARY KEY,
        buyer_id BIGINT NOT NULL
          REFERENCES users(id)
          ON DELETE CASCADE,
        listing_id BIGINT NOT NULL
          REFERENCES listings(id)
          ON DELETE RESTRICT,
        price NUMERIC(12,2) NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (
            status IN (
              'pending',
              'paid',
              'completed',
              'cancelled'
            )
          ),
        payment_provider TEXT,
        payment_ref TEXT,
        payment_status TEXT NOT NULL DEFAULT 'pending'
          CHECK (
            payment_status IN (
              'pending',
              'paid',
              'failed',
              'cancelled'
            )
          ),
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS description TEXT
      NOT NULL DEFAULT ''
    `);
    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS image_url TEXT
    `);
    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS account_data_encrypted TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS price NUMERIC(12,2)
    `);

    await client.query(`
      UPDATE orders o
      SET price = l.price
      FROM listings l
      WHERE o.listing_id = l.id
        AND o.price IS NULL
    `);

    await client.query(`
      ALTER TABLE orders
      ALTER COLUMN price SET NOT NULL
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS payment_provider TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS payment_ref TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS payment_status TEXT
      NOT NULL DEFAULT 'pending'
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS paid_at TIMESTAMPTZ
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT
          REFERENCES users(id)
          ON DELETE SET NULL,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id BIGINT,
        details JSONB NOT NULL
          DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_listings_seller_id
      ON listings(seller_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_listings_status
      ON listings(status)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_orders_buyer_id
      ON orders(buyer_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_orders_listing_id
      ON orders(listing_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS
      idx_audit_logs_created_at
      ON audit_logs(created_at)
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_orders_payment_ref
      ON orders(payment_ref)
      WHERE payment_ref IS NOT NULL
    `);

    /*
      IMPORTANT:
      We intentionally do NOT create the
      "one open order per listing" unique index here.
      Older databases may already contain duplicate
      pending/paid orders, which would make startup fail.
      The order-creation transaction below prevents
      new duplicates.
    */

    await client.query("COMMIT");

    console.log(
      "Database initialized successfully"
    );
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

app.get("/", (req, res) => {
  res.json({
    name: "eFootball Market API",
    version: VERSION,
    status: "ok"
  });
});

app.get("/health", async (req, res) => {
  let database = false;

  try {
    await pool.query("SELECT 1");
    database = true;
  } catch {}

  res.json({
    ok: true,
    version: VERSION,
    database,
    webhook: Boolean(
      PAYMENT_WEBHOOK_SECRET
    ),
    secure_delivery: Boolean(
      getDeliveryKey()
    )
  });
});

app.post(
  "/api/auth/register",
  rateLimit({
    windowMs: 60000,
    max: 10,
    message: "Too many registration attempts"
  }),
  async (req, res, next) => {
    try {
      const email = cleanText(
        req.body?.email,
        200
      ).toLowerCase();

      const password =
        String(req.body?.password || "");

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error: "Invalid email"
        });
      }

      if (
        password.length < 8 ||
        password.length > 200
      ) {
        return res.status(400).json({
          error:
            "Password must be 8-200 characters"
        });
      }

      const existing = await pool.query(
        "SELECT id FROM users WHERE email = $1",
        [email]
      );

      if (existing.rowCount) {
        return res.status(409).json({
          error: "Email already registered"
        });
      }

      const passwordHash =
        await bcrypt.hash(password, 12);

      const result = await pool.query(
        `INSERT INTO users
         (email,password_hash,role)
         VALUES ($1,$2,'buyer')
         RETURNING id,email,role`,
        [email, passwordHash]
      );

      const user = result.rows[0];

      res.status(201).json({
        token: signToken(user),
        user: publicUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/auth/login",
  rateLimit({
    windowMs: 60000,
    max: 15,
    message: "Too many login attempts"
  }),
  async (req, res, next) => {
    try {
      const email = cleanText(
        req.body?.email,
        200
      ).toLowerCase();

      const password =
        String(req.body?.password || "");

      const result = await pool.query(
        `SELECT
           id,
           email,
           password_hash,
           role
         FROM users
         WHERE email = $1
         LIMIT 1`,
        [email]
      );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }

      const user = result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }

      res.json({
        token: signToken(user),
        user: publicUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get("/api/me", auth, (req, res) => {
  res.json({
    user: publicUser(req.user)
  });
});

app.get("/api/listings", async (req, res, next) => {
  try {
    const search = cleanText(
      req.query?.search,
      100
    );

    const maxPrice =
      req.query?.maxPrice
        ? Number(req.query.maxPrice)
        : null;

    const values = [];

    let where =
      "l.status = 'active'";

    if (search) {
      values.push(`%${search}%`);

      where += `
        AND (
          l.title ILIKE $${values.length}
          OR
          l.description ILIKE $${values.length}
        )
      `;
    }

    if (
      maxPrice !== null &&
      Number.isFinite(maxPrice)
    ) {
      values.push(maxPrice);

      where += `
        AND l.price <= $${values.length}
      `;
    }

    const result = await pool.query(
      `SELECT
         l.id,
         l.title,
         l.description,
         l.price,
         l.image_url,
         l.status,
         l.created_at,
         u.id AS seller_id,
         u.email AS seller_email
       FROM listings l
       JOIN users u
         ON u.id = l.seller_id
       WHERE ${where}
       ORDER BY l.created_at DESC
       LIMIT 200`,
      values
    );

    res.json({
      listings: result.rows
    });
  } catch (error) {
    next(error);
  }
});

app.get(
  "/api/my-listings",
  auth,
  requireRole("seller", "admin"),
  async (req, res, next) => {
    try {
      const result = await pool.query(
        `SELECT
           id,
           title,
           description,
           price,
           status,
           created_at
         FROM listings
         WHERE seller_id = $1
         ORDER BY created_at DESC
         LIMIT 200`,
        [req.user.id]
      );

      res.json({
        listings: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/listings",
  auth,
  requireRole("seller", "admin"),
  async (req, res, next) => {
    try {
      const title = cleanText(
        req.body?.title,
        200
      );

      const description = cleanText(
        req.body?.description,
        2000
      );

      const accountData = cleanText(
        req.body?.account_data,
        10000
      );
      
      const imageUrl = cleanText(
       req.body?.image_url,
        2000000
      );
      const price = normalizePrice(
        req.body?.price
      );

      if (!title) {
        return res.status(400).json({
          error: "Title is required"
        });
      }

      if (!isValidPrice(price)) {
        return res.status(400).json({
          error: "Invalid price"
        });
      }

      if (!accountData) {
        return res.status(400).json({
          error: "Account data is required"
        });
      }

const encrypted = encryptDelivery(accountData);
 const result = await pool.query(
  `INSERT INTO listings
  (
    seller_id,
    title,
    description,
    price,
    account_data_encrypted,
    image_url,
    status
  )
  VALUES
  ($1,$2,$3,$4,$5,$6,'active')
  RETURNING
    id,
    title,
    description,
    price,
    image_url,
    status,
    created_at`,
  [
    req.user.id,
    title,
    description,
    price,
    encrypted,
    imageUrl
  ]
);
      res.status(201).json({
        listing: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/api/listings/:id/status",
  auth,
  async (req, res, next) => {
    try {
      const listingId =
        Number(req.params.id);

      const status = cleanText(
        req.body?.status,
        30
      ).toLowerCase();

      if (!Number.isInteger(listingId)) {
        return res.status(400).json({
          error: "Invalid listing id"
        });
      }

      if (
        !["active", "cancelled"].includes(
          status
        )
      ) {
        return res.status(400).json({
          error: "Invalid listing status"
        });
      }

      const result = await pool.query(
        `UPDATE listings
         SET status = $1
         WHERE id = $2
           AND (
             seller_id = $3
             OR $4 = 'admin'
           )
         RETURNING id,title,status`,
        [
          status,
          listingId,
          req.user.id,
          req.user.role
        ]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Listing not found"
        });
      }

      res.json({
        listing: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/orders",
  auth,
  async (req, res, next) => {
    const client = await pool.connect();

    try {
      const listingId =
        Number(req.body?.listing_id);

      if (!Number.isInteger(listingId)) {
        return res.status(400).json({
          error: "Invalid listing id"
        });
      }

      await client.query("BEGIN");

      const listingResult =
        await client.query(
          `SELECT
             id,
             seller_id,
             price,
             status
           FROM listings
           WHERE id = $1
           FOR UPDATE`,
          [listingId]
        );

      if (!listingResult.rowCount) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Listing not found"
        });
      }

      const listing =
        listingResult.rows[0];

      if (
        Number(listing.seller_id) ===
        Number(req.user.id)
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "You cannot buy your own listing"
        });
      }

      if (listing.status !== "active") {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Listing is not available"
        });
      }

      const openOrder =
        await client.query(
          `SELECT id
           FROM orders
           WHERE listing_id = $1
             AND status IN ('pending','paid')
           FOR UPDATE`,
          [listingId]
        );

      if (openOrder.rowCount) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Listing already has an open order"
        });
      }

      const result =
        await client.query(
          `INSERT INTO orders
           (
             buyer_id,
             listing_id,
             price,
             status,
             payment_status
           )
           VALUES
           ($1,$2,$3,'pending','pending')
           RETURNING
             id,
             buyer_id,
             listing_id,
             price,
             status,
             payment_status,
             created_at`,
          [
            req.user.id,
            listing.id,
            listing.price
          ]
        );

      const order =
        result.rows[0];

      await audit(
        client,
        req.user.id,
        "order_created",
        "order",
        order.id,
        {
          listing_id: listing.id,
          price: listing.price
        }
      );

      await client.query("COMMIT");

      res.status(201).json({
        order
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      next(error);
    } finally {
      client.release();
    }
  }
);

app.get(
  "/api/orders",
  auth,
  async (req, res, next) => {
    try {
      const result =
        await pool.query(
          `SELECT
             o.id,
             o.listing_id,
             o.price,
             o.status,
             o.payment_provider,
             o.payment_ref,
             o.payment_status,
             o.paid_at,
             o.created_at,
             l.title,
             l.description
           FROM orders o
           JOIN listings l
             ON l.id = o.listing_id
           WHERE o.buyer_id = $1
           ORDER BY o.created_at DESC
           LIMIT 100`,
          [req.user.id]
        );

      res.json({
        orders: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/orders/:id",
  auth,
  async (req, res, next) => {
    try {
      const orderId =
        Number(req.params.id);

      const result =
        await pool.query(
          `SELECT
             o.*,
             l.title,
             l.description
           FROM orders o
           JOIN listings l
             ON l.id = o.listing_id
           WHERE o.id = $1
             AND o.buyer_id = $2
           LIMIT 1`,
          [
            orderId,
            req.user.id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      res.json({
        order: result.rows[0]
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/payments/webhook",
  rateLimit({
    windowMs: 60000,
    max: 120
  }),
  async (req, res, next) => {
    const client =
      await pool.connect();

    try {
      if (!PAYMENT_WEBHOOK_SECRET) {
        return res.status(503).json({
          error:
            "Payment webhook is not configured"
        });
      }

      const supplied =
        String(
          req.headers["x-webhook-secret"] ||
          ""
        );

      const expected =
        Buffer.from(
          PAYMENT_WEBHOOK_SECRET
        );

      const actual =
        Buffer.from(supplied);

      if (
        actual.length !==
          expected.length ||
        !crypto.timingSafeEqual(
          actual,
          expected
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid webhook secret"
        });
      }

      const orderId =
        Number(req.body?.order_id);

      const paymentRef =
        cleanText(
          req.body?.payment_ref,
          200
        );

      const provider =
        cleanText(
          req.body?.provider,
          100
        );

      const amount =
        Number(req.body?.amount);

      const status =
        cleanText(
          req.body?.status,
          50
        ).toLowerCase();

      if (
        !Number.isInteger(orderId) ||
        !paymentRef ||
        !provider ||
        !Number.isFinite(amount)
      ) {
        return res.status(400).json({
          error:
            "Invalid payment payload"
        });
      }

      if (status !== "paid") {
        return res.json({
          ok: true,
          ignored: true
        });
      }

      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT
             o.*,
             l.status AS listing_status
           FROM orders o
           JOIN listings l
             ON l.id = o.listing_id
           WHERE o.id = $1
           FOR UPDATE`,
          [orderId]
        );

      if (!result.rowCount) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Order not found"
        });
      }

      const order =
        result.rows[0];

      if (
        order.status === "cancelled" ||
        order.payment_status ===
          "cancelled"
      ) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Cancelled order cannot be paid"
        });
      }

      if (
        Math.abs(
          Number(order.price) -
          amount
        ) > 0.01
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Payment amount does not match order"
        });
      }

      if (
        order.payment_status ===
        "paid"
      ) {
        await client.query("COMMIT");

        return res.json({
          ok: true,
          already_paid: true
        });
      }

      const duplicate =
        await client.query(
          `SELECT id
           FROM orders
           WHERE payment_ref = $1
             AND id <> $2
           LIMIT 1`,
          [
            paymentRef,
            orderId
          ]
        );

      if (duplicate.rowCount) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          error:
            "Payment reference already used"
        });
      }

      await client.query(
        `UPDATE orders
         SET
           status='paid',
           payment_provider=$1,
           payment_ref=$2,
           payment_status='paid',
           paid_at=NOW()
         WHERE id=$3`,
        [
          provider,
          paymentRef,
          orderId
        ]
      );

      await audit(
        client,
        order.buyer_id,
        "payment_confirmed",
        "order",
        orderId,
        {
          provider,
          payment_ref:
            paymentRef,
          amount
        }
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        order_id: orderId,
        status: "paid"
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      next(error);
    } finally {
      client.release();
    }
  }
);

app.get(
  "/api/orders/:id/delivery",
  auth,
  async (req, res, next) => {
    try {
      const orderId =
        Number(req.params.id);

      const result =
        await pool.query(
          `SELECT
             o.id,
             o.status,
             o.payment_status,
             l.account_data_encrypted
           FROM orders o
           JOIN listings l
             ON l.id=o.listing_id
           WHERE o.id=$1
             AND o.buyer_id=$2
           LIMIT 1`,
          [
            orderId,
            req.user.id
          ]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error: "Order not found"
        });
      }

      const order =
        result.rows[0];

      if (
        !["paid", "completed"]
          .includes(order.status) ||
        order.payment_status !==
          "paid"
      ) {
        return res.status(403).json({
          error:
            "Payment is not confirmed"
        });
      }

      if (
        !order.account_data_encrypted
      ) {
        return res.status(404).json({
          error:
            "Account delivery data not found"
        });
      }

      res.json({
        order_id: orderId,
        account_data:
          decryptDelivery(
            order.account_data_encrypted
          )
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/api/orders/:id/status",
  auth,
  async (req, res, next) => {
    const client =
      await pool.connect();

    try {
      const orderId =
        Number(req.params.id);

      const nextStatus =
        cleanText(
          req.body?.status,
          50
        ).toLowerCase();

      if (!Number.isInteger(orderId)) {
        return res.status(400).json({
          error: "Invalid order id"
        });
      }

      if (
        !["completed", "cancelled"]
          .includes(nextStatus)
      ) {
        return res.status(400).json({
          error: "Invalid status"
        });
      }

      await client.query("BEGIN");

      const result =
        await client.query(
          `SELECT
             o.*,
             l.status AS listing_status
           FROM orders o
           JOIN listings l
             ON l.id=o.listing_id
           WHERE o.id=$1
           FOR UPDATE`,
          [orderId]
        );

      if (!result.rowCount) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Order not found"
        });
      }

      const order =
        result.rows[0];

      const isAdmin =
        req.user.role === "admin";

      const isBuyer =
        Number(order.buyer_id) ===
        Number(req.user.id);

      if (!isAdmin && !isBuyer) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          error: "Permission denied"
        });
      }

      if (nextStatus === "completed") {
        if (
          order.payment_status !==
          "paid"
        ) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error:
              "Order must be paid first"
          });
        }

        if (
          order.status === "cancelled"
        ) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error:
              "Cancelled order cannot be completed"
          });
        }

        await client.query(
          `UPDATE orders
           SET status='completed'
           WHERE id=$1`,
          [orderId]
        );

        await client.query(
          `UPDATE listings
           SET status='sold'
           WHERE id=$1`,
          [order.listing_id]
        );
      }

      if (nextStatus === "cancelled") {
        /*
          CRITICAL FIX:
          A paid order cannot be cancelled
          through this endpoint.
          Refund must be handled by the
          payment/refund workflow first.
        */

        if (
          order.payment_status ===
            "paid" ||
          order.status === "paid"
        ) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error:
              "Paid order cannot be cancelled; refund is required first"
          });
        }

        if (
          order.status ===
          "completed"
        ) {
          await client.query("ROLLBACK");

          return res.status(400).json({
            error:
              "Completed order cannot be cancelled"
          });
        }

        await client.query(
          `UPDATE orders
           SET
             status='cancelled',
             payment_status='cancelled'
           WHERE id=$1`,
          [orderId]
        );

        await client.query(
          `UPDATE listings
           SET status='active'
           WHERE id=$1
             AND status<>'sold'`,
          [order.listing_id]
        );
      }

      await audit(
        client,
        req.user.id,
        `order_${nextStatus}`,
        "order",
        orderId
      );

      await client.query("COMMIT");

      res.json({
        ok: true,
        status: nextStatus
      });
    } catch (error) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      next(error);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/admin/bootstrap",
  auth,
  rateLimit({
    windowMs: 60000,
    max: 5
  }),
  async (req, res, next) => {
    try {
      if (!ADMIN_BOOTSTRAP_SECRET) {
        return res.status(503).json({
          error:
            "Admin bootstrap is not configured"
        });
      }

      if (req.user.role === "admin") {
        return res.json({
          ok: true,
          user: publicUser(
            req.user
          )
        });
      }

      const existing =
        await pool.query(
          `SELECT id
           FROM users
           WHERE role='admin'
           LIMIT 1`
        );

      if (existing.rowCount) {
        return res.status(409).json({
          error:
            "An admin account already exists"
        });
      }

      const supplied =
        Buffer.from(
          String(
            req.body?.secret || ""
          )
        );

      const expected =
        Buffer.from(
          ADMIN_BOOTSTRAP_SECRET
        );

      if (
        supplied.length !==
          expected.length ||
        !crypto.timingSafeEqual(
          supplied,
          expected
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid admin bootstrap secret"
        });
      }

      const updated =
        await pool.query(
          `UPDATE users
           SET role='admin'
           WHERE id=$1
           RETURNING id,email,role`,
          [req.user.id]
        );

      res.json({
        ok: true,
        user: publicUser(
          updated.rows[0]
        )
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/admin/users",
  auth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const result =
        await pool.query(
          `SELECT
             id,
             email,
             role,
             created_at
           FROM users
           ORDER BY created_at DESC
           LIMIT 500`
        );

      res.json({
        users: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/api/admin/users/:id/role",
  auth,
  requireRole("admin"),
  async (req, res, next) => {
    let client;

    try {
      client = await pool.connect();

      const userId =
        Number(req.params.id);

      const role =
        cleanText(
          req.body?.role,
          30
        ).toLowerCase();

      if (!Number.isInteger(userId)) {
        return res.status(400).json({
          error: "Invalid user id"
        });
      }

      if (
        ![
          "buyer",
          "seller",
          "admin"
        ].includes(role)
      ) {
        return res.status(400).json({
          error: "Invalid role"
        });
      }

      await client.query("BEGIN");

      const target =
        await client.query(
          `SELECT id,email,role
           FROM users
           WHERE id=$1
           FOR UPDATE`,
          [userId]
        );

      if (!target.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          error: "User not found"
        });
      }

      if (
        Number(req.user.id) === userId &&
        role !== "admin"
      ) {
        await client.query("ROLLBACK");
        return res.status(400).json({
          error: "You cannot remove your own admin role"
        });
      }

      if (
        target.rows[0].role === "admin" &&
        role !== "admin"
      ) {
        const admins =
          await client.query(
            `SELECT id
             FROM users
             WHERE role='admin'
             FOR UPDATE`
          );

        if (admins.rowCount <= 1) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            error: "At least one admin account is required"
          });
        }
      }

      const result =
        await client.query(
          `UPDATE users
           SET role=$1
           WHERE id=$2
           RETURNING id,email,role`,
          [
            role,
            userId
          ]
        );

      await client.query(
        `INSERT INTO audit_logs
         (
           user_id,
           action,
           entity_type,
           entity_id,
           details
         )
         VALUES
         (
           $1,
           'role_changed',
           'user',
           $2,
           $3::jsonb
         )`,
        [
          req.user.id,
          userId,
          JSON.stringify({
            role
          })
        ]
      );

      await client.query("COMMIT");

      res.json({
        user: result.rows[0]
      });
    } catch (error) {
      if (client) {
        try {
          await client.query("ROLLBACK");
        } catch {}
      }

      next(error);
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);
app.get(
  "/api/admin/audit-logs",
  auth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const result =
        await pool.query(
          `SELECT
             a.id,
             a.action,
             a.entity_type,
             a.entity_id,
             a.details,
             a.created_at,
             u.email
           FROM audit_logs a
           LEFT JOIN users u
             ON u.id=a.user_id
           ORDER BY a.created_at DESC
           LIMIT 500`
        );

      res.json({
        logs: result.rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/stats",
  auth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      const users =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM users`
        );

      const listings =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM listings
           WHERE status='active'`
        );

      const orders =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM orders`
        );

      const paid =
        await pool.query(
          `SELECT COUNT(*)::int AS count
           FROM orders
           WHERE payment_status='paid'`
        );

      res.json({
        users:
          users.rows[0].count,

        active_listings:
          listings.rows[0].count,

        orders:
          orders.rows[0].count,

        paid_orders:
          paid.rows[0].count
      });
    } catch (error) {
      next(error);
    }
  }
);

app.use(
  (error, req, res, next) => {
    console.error(error);

    if (res.headersSent) {
      return next(error);
    }

    res.status(500).json({
      error:
        NODE_ENV === "production"
          ? "Internal server error"
          : error.message
    });
  }
);


process.on(
  "SIGTERM",
  async () => {
    await pool.end();
    process.exit(0);
  }
);

process.on(
  "SIGINT",
  async () => {
    await pool.end();
    process.exit(0);
  }
);
async function start() {
  try {
    await initializeDatabase();

    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(
        `eFootball Market API v${VERSION} listening on ${PORT}`
      );
    });

    server.on('error', (error) => {
      console.error('Server error:', error);
      process.exit(1);
    });
  } catch (error) {
    console.error('Startup failed:', error);
    process.exit(1);
  }
}

start();

