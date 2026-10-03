import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";

const { Pool } = pg;
const app = express();

const VERSION = "4.2.0";
const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "";
const NODE_ENV = process.env.NODE_ENV || "development";
const PAYMENT_WEBHOOK_SECRET = process.env.PAYMENT_WEBHOOK_SECRET;
const DELIVERY_ENCRYPTION_KEY = process.env.DELIVERY_ENCRYPTION_KEY;

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

/*
  v4.2 security requirements:

  PAYMENT_WEBHOOK_SECRET =
  a long random secret shared with the payment provider.

  DELIVERY_ENCRYPTION_KEY =
  64 hex characters (32 bytes) for AES-256-GCM.
*/

function getDeliveryKey() {
  if (!DELIVERY_ENCRYPTION_KEY) return null;

  if (!/^[0-9a-fA-F]{64}$/.test(DELIVERY_ENCRYPTION_KEY)) {
    return null;
  }

  return Buffer.from(DELIVERY_ENCRYPTION_KEY, "hex");
}

function encryptDelivery(value) {
  if (!value) return null;

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
    cipher.final(),
  ]);

  const tag = cipher.getAuthTag();

  return [
    iv.toString("base64"),
    tag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(".");
}

function decryptDelivery(value) {
  if (!value) return null;

  const key = getDeliveryKey();

  if (!key) {
    throw new Error(
      "DELIVERY_ENCRYPTION_KEY is not configured correctly"
    );
  }

  const parts = String(value).split(".");

  const ivB64 = parts[0];
  const tagB64 = parts[1];
  const dataB64 = parts[2];

  if (!ivB64 || !tagB64 || !dataB64) {
    throw new Error("Invalid encrypted delivery data");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64")
  );

  decipher.setAuthTag(
    Buffer.from(tagB64, "base64")
  );

  return Buffer.concat([
    decipher.update(
      Buffer.from(dataB64, "base64")
    ),
    decipher.final(),
  ]).toString("utf8");
}

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "1mb",
  })
);

app.use((req, res, next) => {
  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  res.setHeader(
    "X-Frame-Options",
    "DENY"
  );

  res.setHeader(
    "Referrer-Policy",
    "strict-origin-when-cross-origin"
  );

  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  next();
});

const allowedOrigins = FRONTEND_ORIGIN
  .split(",")
  .map((x) => x.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (
        NODE_ENV !== "production" &&
        (
          origin.startsWith("http://localhost:") ||
          origin.startsWith("http://127.0.0.1:")
        )
      ) {
        return callback(null, true);
      }

      if (
        allowedOrigins.includes("*") ||
        allowedOrigins.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS origin not allowed")
      );
    },

    methods: [
      "GET",
      "POST",
      "PATCH",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Webhook-Secret",
    ],
  })
);

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000,
});

const rateLimitStore = new Map();

function rateLimit({
  windowMs = 60000,
  max = 60,
  message = "Too many requests",
} = {}) {
  return (req, res, next) => {
    const ip =
      req.headers["x-forwarded-for"]
        ?.split(",")[0]
        ?.trim() ||
      req.socket.remoteAddress ||
      "unknown";

    const key = `${req.path}:${ip}`;

    const now = Date.now();

    const current = rateLimitStore.get(key);

    if (
      !current ||
      now - current.start >= windowMs
    ) {
      rateLimitStore.set(key, {
        start: now,
        count: 1,
      });

      return next();
    }

    current.count++;

    if (current.count > max) {
      return res.status(429).json({
        error: message,
      });
    }

    next();
  };
}

setInterval(() => {
  const now = Date.now();

  for (
    const [key, value]
    of rateLimitStore.entries()
  ) {
    if (
      now - value.start >
      10 * 60 * 1000
    ) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

function cleanText(
  value,
  maxLength = 500
) {
  if (
    value === undefined ||
    value === null
  ) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, maxLength);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
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
  return Number(
    Number(price).toFixed(2)
  );
}

function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function publicUser(user) {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
  };
}

async function auth(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    const decoded = jwt.verify(
      header.slice(7).trim(),
      JWT_SECRET
    );

    if (!decoded?.id) {
      return res.status(401).json({
        error: "Invalid token",
      });
    }

    const result = await pool.query(
      `
      SELECT id, email, role
      FROM users
      WHERE id = $1
      LIMIT 1
      `,
      [decoded.id]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "User not found",
      });
    }

    req.user = result.rows[0];

    next();
  } catch {
    res.status(401).json({
      error:
        "Invalid or expired token",
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error:
          "Authentication required",
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: "Permission denied",
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
    `
    INSERT INTO audit_logs
      (
        user_id,
        action,
        entity_type,
        entity_id,
        details
      )
    VALUES
      ($1, $2, $3, $4, $5::jsonb)
    `,
    [
      userId || null,
      action,
      entityType,
      entityId || null,
      JSON.stringify(details),
    ]
  );
}

async function initializeDatabase() {
  const client =
    await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'buyer'
          CHECK (
            role IN (
              'buyer',
              'seller',
              'admin'
            )
          ),
        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS listings (
        id BIGSERIAL PRIMARY KEY,
        seller_id BIGINT NOT NULL
          REFERENCES users(id)
          ON DELETE CASCADE,

        title TEXT NOT NULL,

        description TEXT
          NOT NULL DEFAULT '',

        price NUMERIC(12,2)
          NOT NULL
          CHECK (price > 0),

        status TEXT NOT NULL
          DEFAULT 'active'
          CHECK (
            status IN (
              'active',
              'sold',
              'cancelled'
            )
          ),

        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
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

        price NUMERIC(12,2)
          NOT NULL,

        status TEXT NOT NULL
          DEFAULT 'pending'
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

        payment_status TEXT NOT NULL
          DEFAULT 'pending'
          CHECK (
            payment_status IN (
              'pending',
              'paid',
              'failed',
              'cancelled'
            )
          ),

        paid_at TIMESTAMPTZ,

        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS
      description TEXT
      NOT NULL DEFAULT ''
    `);

    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS
      account_data_encrypted TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS
      price NUMERIC(12,2)
    `);

    await client.query(`
      UPDATE orders o
      SET price = l.price
      FROM listings l
      WHERE
        o.listing_id = l.id
        AND o.price IS NULL
    `);

    await client.query(`
      ALTER TABLE orders
      ALTER COLUMN price SET NOT NULL
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS
      payment_provider TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS
      payment_ref TEXT
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS
      payment_status TEXT
      NOT NULL DEFAULT 'pending'
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS
      paid_at TIMESTAMPTZ
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

        created_at TIMESTAMPTZ
          NOT NULL DEFAULT NOW()
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
      idx_one_open_order_per_listing
      ON orders(listing_id)
      WHERE status IN (
        'pending',
        'paid'
      )
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_orders_payment_ref
      ON orders(payment_ref)
      WHERE payment_ref IS NOT NULL
    `);

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
    status: "ok",
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: VERSION,
    database: Boolean(DATABASE_URL),
    webhook: Boolean(
      PAYMENT_WEBHOOK_SECRET
    ),
    secure_delivery: Boolean(
      getDeliveryKey()
    ),
  });
});

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      version: VERSION,
      service:
        "eFootball Market API",
    });
  }
);

app.post(
  "/api/auth/register",
  rateLimit({
    windowMs: 60 * 1000,
    max: 10,
  }),
  async (req, res, next) => {
    try {
      const email =
        cleanText(
          req.body?.email,
          200
        ).toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error:
            "Invalid email address",
        });
      }

      if (
        password.length < 8 ||
        password.length > 128
      ) {
        return res.status(400).json({
          error:
            "Password must be 8-128 characters",
        });
      }

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email = $1
          LIMIT 1
          `,
          [email]
        );

      if (existing.rowCount) {
        return res.status(409).json({
          error:
            "Email already registered",
        });
      }

      const passwordHash =
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
            ($1, $2, 'buyer')
          RETURNING
            id,
            email,
            role
          `,
          [
            email,
            passwordHash,
          ]
        );

      const user =
        result.rows[0];

      res.status(201).json({
        user: publicUser(user),
        token: signToken(user),
      });
    } catch (error) {
      if (error?.code === "23505") {
        return res.status(409).json({
          error:
            "Email already registered",
        });
      }

      next(error);
    }
  }
);

app.post(
  "/api/auth/login",
  rateLimit({
    windowMs: 60 * 1000,
    max: 10,
  }),
  async (req, res, next) => {
    try {
      const email =
        cleanText(
          req.body?.email,
          200
        ).toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      const result =
        await pool.query(
          `
          SELECT
            id,
            email,
            password_hash,
            role
          FROM users
          WHERE email = $1
          LIMIT 1
          `,
          [email]
        );

      if (!result.rowCount) {
        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const user =
        result.rows[0];

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      res.json({
        user: publicUser(user),
        token: signToken(user),
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    res.json({
      user: publicUser(
        req.user
      ),
    });
  }
);

app.get(
  "/api/listings",
  async (req, res, next) => {
    try {
      let limit =
        Number(
          req.query.limit || 100
        );

      let offset =
        Number(
          req.query.offset || 0
        );

      if (
        !Number.isInteger(limit) ||
        limit < 1
      ) {
        limit = 100;
      }

      if (limit > 100) {
        limit = 100;
      }

      if (
        !Number.isInteger(offset) ||
        offset < 0
      ) {
        offset = 0;
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            title,
            description,
            price,
            status,
            created_at,
            seller_id
          FROM listings
          WHERE status = 'active'
          ORDER BY created_at DESC
          LIMIT $1
          OFFSET $2
          `,
          [
            limit,
            offset,
          ]
        );

      res.json({
        listings:
          result.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/api/listings",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    try {
      const title =
        cleanText(
          req.body?.title,
          150
        );

      const description =
        cleanText(
          req.body?.description,
          3000
        );

      const price =
        Number(
          req.body?.price
        );

      const accountData =
        cleanText(
          req.body?.account_data,
          10000
        );

      if (!title) {
        return res.status(400).json({
          error:
            "Title is required",
        });
      }

      if (!isValidPrice(price)) {
        return res.status(400).json({
          error:
            "Invalid price",
        });
      }

      if (
        accountData &&
        !getDeliveryKey()
      ) {
        return res.status(503).json({
          error:
            "Secure delivery is not configured",
        });
      }

      const encrypted =
        accountData
          ? encryptDelivery(
              accountData
            )
          : null;

      const result =
        await pool.query(
          `
          INSERT INTO listings
            (
              seller_id,
              title,
              description,
              price,
              account_data_encrypted
            )
          VALUES
            ($1, $2, $3, $4, $5)
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
            normalizePrice(price),
            encrypted,
          ]
        );

      res.status(201).json({
        listing:
          result.rows[0],
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/my-listings",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
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
          ORDER BY created_at DESC
          `,
          [req.user.id]
        );

      res.json({
        listings:
          result.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/api/listings/:id",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    const client =
      await pool.connect();

    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid listing id",
        });
      }

      await client.query(
        "BEGIN"
      );

      const result =
        await client.query(
          `
          SELECT *
          FROM listings
          WHERE id = $1
          FOR UPDATE
          `,
          [id]
        );

      if (!result.rowCount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Listing not found",
        });
      }

      const listing =
        result.rows[0];

      if (
        req.user.role !== "admin" &&
        String(
          listing.seller_id
        ) !==
          String(req.user.id)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(403).json({
          error:
            "Permission denied",
        });
      }

      const openOrder =
        await client.query(
          `
          SELECT id
          FROM orders
          WHERE
            listing_id = $1
            AND status IN (
              'pending',
              'paid'
            )
          LIMIT 1
          `,
          [id]
        );

      const hasOpenOrder =
        openOrder.rowCount > 0;

      const body =
        req.body || {};

      const hasTitle =
        Object.prototype.hasOwnProperty.call(
          body,
          "title"
        );

      const hasDescription =
        Object.prototype.hasOwnProperty.call(
          body,
          "description"
        );

      const hasPrice =
        Object.prototype.hasOwnProperty.call(
          body,
          "price"
        );

      const hasStatus =
        Object.prototype.hasOwnProperty.call(
          body,
          "status"
        );

      const hasAccountData =
        Object.prototype.hasOwnProperty.call(
          body,
          "account_data"
        );

      if (
        hasOpenOrder &&
        (
          hasTitle ||
          hasDescription ||
          hasPrice ||
          hasStatus
        )
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            "Listing cannot be changed while an order is open",
        });
      }

      const title =
        hasTitle
          ? cleanText(
              body.title,
              150
            )
          : listing.title;

      const description =
        hasDescription
          ? cleanText(
              body.description,
              3000
            )
          : listing.description;

      const price =
        hasPrice
          ? Number(body.price)
          : Number(
              listing.price
            );

      let status =
        hasStatus
          ? cleanText(
              body.status,
              30
            )
          : listing.status;

      if (
        !["active", "cancelled", "sold"]
          .includes(status)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          error:
            "Invalid listing status",
        });
      }

      if (!title) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          error:
            "Title is required",
        });
      }

      if (!isValidPrice(price)) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          error:
            "Invalid price",
        });
      }

      let encrypted =
        listing.account_data_encrypted;

      if (hasAccountData) {
        const accountData =
          cleanText(
            body.account_data,
            10000
          );

        if (
          accountData &&
          !getDeliveryKey()
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(503).json({
            error:
              "Secure delivery is not configured",
          });
        }

        encrypted =
          accountData
            ? encryptDelivery(
                accountData
              )
            : null;
      }

      const updated =
        await client.query(
          `
          UPDATE listings
          SET
            title = $1,
            description = $2,
            price = $3,
            status = $4,
            account_data_encrypted = $5
          WHERE id = $6
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
            normalizePrice(
              price
            ),
            status,
            encrypted,
            id,
          ]
        );

      await audit(
        client,
        req.user.id,
        "listing.updated",
        "listing",
        id,
        {
          status,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        listing:
          updated.rows[0],
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(error);
    } finally {
      client.release();
    }
  }
);

app.post(
  "/api/orders",
  auth,
  requireRole(
    "buyer",
    "admin"
  ),
  async (req, res, next) => {
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
        return res.status(400).json({
          error:
            "Invalid listing id",
        });
      }

      await client.query(
        "BEGIN"
      );

      const listingResult =
        await client.query(
          `
          SELECT *
          FROM listings
          WHERE id = $1
          FOR UPDATE
          `,
          [listingId]
        );

      if (!listingResult.rowCount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Listing not found",
        });
      }

      const listing =
        listingResult.rows[0];

      if (
        listing.status !== "active"
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            "Listing is not available",
        });
      }

      if (
        req.user.role !== "admin" &&
        String(
          listing.seller_id
        ) ===
          String(req.user.id)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(403).json({
          error:
            "Seller cannot buy own listing",
        });
      }

      const existing =
        await client.query(
          `
          SELECT id
          FROM orders
          WHERE
            listing_id = $1
            AND status IN (
              'pending',
              'paid'
            )
          LIMIT 1
          `,
          [listingId]
        );

      if (existing.rowCount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            "Listing already has an open order",
        });
      }

      const price =
        normalizePrice(
          listing.price
        );

      const inserted =
        await client.query(
          `
          INSERT INTO orders
            (
              buyer_id,
              listing_id,
              price,
              status,
              payment_status
            )
          VALUES
            (
              $1,
              $2,
              $3,
              'pending',
              'pending'
            )
          RETURNING *
          `,
          [
            req.user.id,
            listingId,
            price,
          ]
        );

      const order =
        inserted.rows[0];

      await audit(
        client,
        req.user.id,
        "order.created",
        "order",
        order.id,
        {
          listing_id:
            listingId,
          price,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.status(201).json({
        order,
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      if (
        error?.code ===
        "23505"
      ) {
        return res.status(409).json({
          error:
            "Listing already has an open order",
        });
      }

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
      let result;

      if (
        req.user.role ===
        "admin"
      ) {
        result =
          await pool.query(`
            SELECT
              o.id,
              o.buyer_id,
              o.listing_id,
              o.price,
              o.status,
              o.payment_provider,
              o.payment_ref,
              o.payment_status,
              o.paid_at,
              o.created_at,
              l.title,
              l.seller_id
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
            ORDER BY
              o.created_at DESC
          `);
      } else if (
        req.user.role ===
        "seller"
      ) {
        result =
          await pool.query(
            `
            SELECT
              o.id,
              o.buyer_id,
              o.listing_id,
              o.price,
              o.status,
              o.payment_provider,
              o.payment_ref,
              o.payment_status,
              o.paid_at,
              o.created_at,
              l.title,
              l.seller_id
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
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
              o.buyer_id,
              o.listing_id,
              o.price,
              o.status,
              o.payment_provider,
              o.payment_ref,
              o.payment_status,
              o.paid_at,
              o.created_at,
              l.title,
              l.seller_id
            FROM orders o
            JOIN listings l
              ON l.id = o.listing_id
            WHERE o.buyer_id = $1
            ORDER BY
              o.created_at DESC
            `,
            [req.user.id]
          );
      }

      res.json({
        orders:
          result.rows,
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
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid order id",
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            o.id,
            o.buyer_id,
            o.listing_id,
            o.price,
            o.status,
            o.payment_provider,
            o.payment_ref,
            o.payment_status,
            o.paid_at,
            o.created_at,
            l.title,
            l.description,
            l.seller_id
          FROM orders o
          JOIN listings l
            ON l.id = o.listing_id
          WHERE o.id = $1
          LIMIT 1
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const order =
        result.rows[0];

      const allowed =
        req.user.role === "admin" ||
        String(
          order.buyer_id
        ) ===
          String(req.user.id) ||
        (
          req.user.role ===
            "seller" &&
          String(
            order.seller_id
          ) ===
            String(req.user.id)
        );

      if (!allowed) {
        return res.status(403).json({
          error:
            "Permission denied",
        });
      }

      res.json({
        order,
      });
    } catch (error) {
      next(error);
    }
  }
);

async function markOrderPaid({
  paymentProvider,
  paymentRef,
  orderId,
  paidAmount,
}) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const r =
      await client.query(
        `
        SELECT *
        FROM orders
        WHERE id = $1
        FOR UPDATE
        `,
        [orderId]
      );

    if (!r.rowCount) {
      throw new Error(
        "Order not found"
      );
    }

    const order =
      r.rows[0];

    if (
      normalizePrice(
        paidAmount
      ) !==
      normalizePrice(
        order.price
      )
    ) {
      throw new Error(
        "Payment amount does not match order price"
      );
    }

    if (
      order.payment_status ===
      "paid"
    ) {
      await client.query(
        "COMMIT"
      );

      return order;
    }

    if (
      order.status !==
        "pending" ||
      order.payment_status !==
        "pending"
    ) {
      throw new Error(
        "Order is not payable"
      );
    }

    const updated =
      await client.query(
        `
        UPDATE orders
        SET
          payment_provider = $1,
          payment_ref = $2,
          payment_status = 'paid',
          paid_at = NOW(),
          status = 'paid'
        WHERE
          id = $3
          AND status = 'pending'
          AND payment_status = 'pending'
        RETURNING *
        `,
        [
          paymentProvider,
          paymentRef,
          orderId,
        ]
      );

    if (!updated.rowCount) {
      throw new Error(
        "Payment confirmation failed"
      );
    }

    await audit(
      client,
      null,
      "payment.confirmed",
      "order",
      orderId,
      {
        provider:
          paymentProvider,
        ref:
          paymentRef,
      }
    );

    await client.query(
      "COMMIT"
    );

    return updated.rows[0];
  } catch (error) {
    try {
      await client.query(
        "ROLLBACK"
      );
    } catch {}

    throw error;
  } finally {
    client.release();
  }
}

/*
  Generic webhook endpoint.

  Configure your payment provider/gateway to send:

    X-Webhook-Secret:
    PAYMENT_WEBHOOK_SECRET

  JSON:

    {
      "order_id": 123,
      "payment_ref": "...",
      "amount": 1234.50,
      "provider": "truemoney"
    }

  IMPORTANT:
  This endpoint is a secure integration point,
  not a TrueMoney implementation by itself.
*/

app.post(
  "/api/payments/webhook",
  rateLimit({
    windowMs:
      60 * 1000,
    max: 120,
  }),
  async (req, res, next) => {
    try {
      if (
        !PAYMENT_WEBHOOK_SECRET
      ) {
        return res.status(503).json({
          error:
            "Payment webhook is not configured",
        });
      }

      const supplied =
        String(
          req.headers[
            "x-webhook-secret"
          ] || ""
        );

      const a =
        Buffer.from(
          supplied
        );

      const b =
        Buffer.from(
          PAYMENT_WEBHOOK_SECRET
        );

      if (
        a.length !== b.length ||
        !crypto.timingSafeEqual(
          a,
          b
        )
      ) {
        return res.status(401).json({
          error:
            "Invalid webhook secret",
        });
      }

      const orderId =
        Number(
          req.body?.order_id
        );

      const paymentRef =
        cleanText(
          req.body?.payment_ref,
          200
        );

      const amount =
        Number(
          req.body?.amount
        );

      const provider =
        cleanText(
          req.body?.provider ||
            "payment_gateway",
          50
        );

      if (
        !Number.isInteger(
          orderId
        ) ||
        orderId <= 0 ||
        !paymentRef ||
        !isValidPrice(amount)
      ) {
        return res.status(400).json({
          error:
            "Invalid payment webhook payload",
        });
      }

      const order =
        await markOrderPaid({
          paymentProvider:
            provider,
          paymentRef,
          orderId,
          paidAmount:
            amount,
        });

      res.json({
        ok: true,
        order_id:
          order.id,
        status:
          order.status,
        payment_status:
          order.payment_status,
      });
    } catch (error) {
      if (
        error?.code ===
        "23505"
      ) {
        return res.status(409).json({
          error:
            "Payment reference already used",
        });
      }

      if (
        [
          "Order not found",
          "Payment amount does not match order price",
          "Order is not payable",
          "Payment confirmation failed",
        ].includes(
          error?.message
        )
      ) {
        return res.status(409).json({
          error:
            error.message,
        });
      }

      next(error);
    }
  }
);

app.get(
  "/api/orders/:id/delivery",
  auth,
  async (req, res, next) => {
    try {
      const id =
        Number(
          req.params.id
        );

      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid order id",
        });
      }

      const result =
        await pool.query(
          `
          SELECT
            o.id,
            o.buyer_id,
            o.listing_id,
            o.status,
            o.payment_status,
            l.seller_id,
            l.account_data_encrypted
          FROM orders o
          JOIN listings l
            ON l.id = o.listing_id
          WHERE o.id = $1
          LIMIT 1
          `,
          [id]
        );

      if (!result.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const row =
        result.rows[0];

      if (
        req.user.role !==
          "admin" &&
        String(
          row.buyer_id
        ) !==
          String(req.user.id)
      ) {
        return res.status(403).json({
          error:
            "Only the buyer can receive delivery",
        });
      }

      if (
        row.payment_status !==
          "paid" ||
        ![
          "paid",
          "completed",
        ].includes(
          row.status
        )
      ) {
        return res.status(409).json({
          error:
            "Payment must be confirmed before delivery",
        });
      }

      if (
        !row.account_data_encrypted
      ) {
        return res.status(404).json({
          error:
            "Secure account delivery data is not available",
        });
      }

      if (!getDeliveryKey()) {
        return res.status(503).json({
          error:
            "Secure delivery is not configured on the server",
        });
      }

      res.json({
        order_id:
          row.id,

        listing_id:
          row.listing_id,

        account_data:
          decryptDelivery(
            row.account_data_encrypted
          ),
      });
    } catch (error) {
      next(error);
    }
  }
);

app.patch(
  "/api/orders/:id/status",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    const client =
      await pool.connect();

    try {
      const orderId =
        Number(
          req.params.id
        );

      const newStatus =
        cleanText(
          req.body?.status,
          30
        );

      if (
        !Number.isInteger(
          orderId
        ) ||
        orderId <= 0
      ) {
        return res.status(400).json({
          error:
            "Invalid order id",
        });
      }

      if (
        ![
          "completed",
          "cancelled",
        ].includes(
          newStatus
        )
      ) {
        return res.status(400).json({
          error:
            "Only completed or cancelled can be set manually",
        });
      }

      await client.query(
        "BEGIN"
      );

      const r =
        await client.query(
          `
          SELECT
            o.*,
            l.seller_id,
            l.status AS listing_status
          FROM orders o
          JOIN listings l
            ON l.id = o.listing_id
          WHERE o.id = $1
          FOR UPDATE
          `,
          [orderId]
        );

      if (!r.rowCount) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const order =
        r.rows[0];

      if (
        req.user.role !==
          "admin" &&
        String(
          order.seller_id
        ) !==
          String(req.user.id)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(403).json({
          error:
            "Permission denied",
        });
      }

      if (
        newStatus ===
        "completed"
      ) {
        if (
          order.status !==
            "paid" ||
          order.payment_status !==
            "paid"
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Only a confirmed paid order can be completed",
          });
        }

        const sold =
          await client.query(
            `
            UPDATE listings
            SET status = 'sold'
            WHERE
              id = $1
              AND status = 'active'
            RETURNING id
            `,
            [
              order.listing_id,
            ]
          );

        if (!sold.rowCount) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Listing is no longer available for completion",
          });
        }
      } else {
        if (
          ![
            "pending",
            "paid",
          ].includes(
            order.status
          )
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Order cannot be cancelled in its current state",
          });
        }

        await client.query(
          `
          UPDATE listings
          SET status = 'active'
          WHERE
            id = $1
            AND status <> 'sold'
          `,
          [
            order.listing_id,
          ]
        );

        if (
          order.payment_status !==
          "paid"
        ) {
          await client.query(
            `
            UPDATE orders
            SET payment_status =
              'cancelled'
            WHERE id = $1
            `,
            [orderId]
          );
        }
      }

      const updated =
        await client.query(
          `
          UPDATE orders
          SET status = $1
          WHERE id = $2
          RETURNING *
          `,
          [
            newStatus,
            orderId,
          ]
        );

      await audit(
        client,
        req.user.id,
        `order.${newStatus}`,
        "order",
        orderId,
        {
          listing_id:
            order.listing_id,
        }
      );

      await client.query(
        "COMMIT"
      );

      res.json({
        order:
          updated.rows[0],
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      next(error);
    } finally {
      client.release();
    }
  }
);

app.get(
  "/api/admin/audit-logs",
  auth,
  requireRole("admin"),
  async (req, res, next) => {
    try {
      let limit =
        Number(
          req.query.limit || 100
        );

      if (
        !Number.isInteger(
          limit
        ) ||
        limit < 1
      ) {
        limit = 100;
      }

      if (limit > 500) {
        limit = 500;
      }

      const result =
        await pool.query(
          `
          SELECT
            id,
            user_id,
            action,
            entity_type,
            entity_id,
            details,
            created_at
          FROM audit_logs
          ORDER BY
            created_at DESC
          LIMIT $1
          `,
          [limit]
        );

      res.json({
        logs:
          result.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  "/api/stats",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    try {
      let result;

      if (
        req.user.role ===
        "admin"
      ) {
        result =
          await pool.query(`
            SELECT
              (
                SELECT COUNT(*)
                FROM users
              ) AS users,

              (
                SELECT COUNT(*)
                FROM listings
              ) AS listings,

              (
                SELECT COUNT(*)
                FROM listings
                WHERE status = 'active'
              ) AS active_listings,

              (
                SELECT COUNT(*)
                FROM orders
              ) AS orders,

              (
                SELECT COUNT(*)
                FROM orders
                WHERE status = 'completed'
              ) AS completed_orders,

              (
                SELECT
                  COALESCE(
                    SUM(price),
                    0
                  )
                FROM orders
                WHERE status = 'completed'
              ) AS completed_revenue
          `);
      } else {
        result =
          await pool.query(
            `
            SELECT
              (
                SELECT COUNT(*)
                FROM listings
                WHERE seller_id = $1
              ) AS listings,

              (
                SELECT COUNT(*)
                FROM listings
                WHERE
                  seller_id = $1
                  AND status = 'active'
              ) AS active_listings,

              (
                SELECT COUNT(*)
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE
                  l.seller_id = $1
              ) AS orders,

              (
                SELECT COUNT(*)
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE
                  l.seller_id = $1
                  AND o.status = 'completed'
              ) AS completed_orders,

              (
                SELECT
                  COALESCE(
                    SUM(o.price),
                    0
                  )
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE
                  l.seller_id = $1
                  AND o.status = 'completed'
              ) AS completed_revenue
            `,
            [req.user.id]
          );
      }

      res.json({
        stats:
          result.rows[0],
      });
    } catch (error) {
      next(error);
    }
  }
);

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "Route not found",
    });
  }
);

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(error);

    if (
      error?.message ===
      "CORS origin not allowed"
    ) {
      return res.status(403).json({
        error:
          "CORS origin not allowed",
      });
    }

    if (
      error?.code ===
      "23505"
    ) {
      return res.status(409).json({
        error:
          "Duplicate record",
      });
    }

    if (
      error?.code ===
      "23503"
    ) {
      return res.status(400).json({
        error:
          "Referenced record does not exist",
      });
    }

    res.status(500).json({
      error:
        "Internal server error",
    });
  }
);

async function start() {
  try {
    await initializeDatabase();

    const server =
      app.listen(
        PORT,
        () => {
          console.log(
            `eFootball Market API v${VERSION} running on port ${PORT}`
          );
        }
      );

    const shutdown =
      async (signal) => {
        console.log(
          `${signal} received`
        );

        server.close(
          async () => {
            try {
              await pool.end();
              process.exit(0);
            } catch {
              process.exit(1);
            }
          }
        );
      };

    process.on(
      "SIGTERM",
      () =>
        shutdown("SIGTERM")
    );

    process.on(
      "SIGINT",
      () =>
        shutdown("SIGINT")
    );
  } catch (error) {
    console.error(
      "Server startup failed:",
      error
    );

    await pool.end();

    process.exit(1);
  }
}

start();