import express from "express";
import cors from "cors";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pg;

const app = express();

const PORT = Number(process.env.PORT || 10000);
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
const NODE_ENV = process.env.NODE_ENV || "development";

if (!DATABASE_URL) {
  console.error("DATABASE_URL is missing");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
  process.exit(1);
}

/* =======================================================
   BASIC CONFIG
======================================================= */

app.disable("x-powered-by");

app.use(
  express.json({
    limit: "1mb",
  })
);

/* =======================================================
   SECURITY HEADERS
======================================================= */

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()"
  );

  next();
});

/* =======================================================
   CORS
======================================================= */

const allowedOrigins = FRONTEND_ORIGIN
  ? FRONTEND_ORIGIN
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean)
  : [];

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (
        NODE_ENV !== "production" &&
        (origin.startsWith("http://localhost:") ||
          origin.startsWith("http://127.0.0.1:"))
      ) {
        return callback(null, true);
      }

      if (allowedOrigins.includes("*")) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error("CORS origin not allowed"));
    },

    methods: ["GET", "POST", "PATCH", "OPTIONS"],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
    ],
  })
);

/* =======================================================
   DATABASE
======================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    NODE_ENV === "production"
      ? {
          rejectUnauthorized: false,
        }
      : false,

  max: 10,

  idleTimeoutMillis: 30000,

  connectionTimeoutMillis: 10000,
});

/* =======================================================
   RATE LIMITER
======================================================= */

const rateLimitStore = new Map();

function rateLimit({
  windowMs = 60 * 1000,
  max = 60,
  message = "Too many requests",
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
        count: 1,
      });

      return next();
    }

    current.count += 1;

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

  for (const [key, value] of rateLimitStore.entries()) {
    if (now - value.start > 10 * 60 * 1000) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

/* =======================================================
   HELPERS
======================================================= */

function cleanText(value, maxLength = 500) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value).trim().slice(0, maxLength);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPrice(price) {
  const number = Number(price);

  return (
    Number.isFinite(number) &&
    number > 0 &&
    number <= 100000000
  );
}

function normalizePrice(price) {
  return Number(Number(price).toFixed(2));
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

/* =======================================================
   AUTH
======================================================= */

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const token = header.slice(7).trim();

    if (!token) {
      return res.status(401).json({
        error: "Authentication required",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);

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

    if (result.rowCount === 0) {
      return res.status(401).json({
        error: "User not found",
      });
    }

    req.user = result.rows[0];

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "Authentication required",
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

/* =======================================================
   DATABASE INITIALIZATION
======================================================= */

async function initializeDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    /* USERS */

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

        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    /* LISTINGS */

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

    /* ORDERS */

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

    /* ===================================================
       MIGRATIONS
    =================================================== */

    await client.query(`
      ALTER TABLE listings
      ADD COLUMN IF NOT EXISTS description
      TEXT NOT NULL DEFAULT ''
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS price
      NUMERIC(12,2)
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
      ADD COLUMN IF NOT EXISTS payment_status
      TEXT NOT NULL DEFAULT 'pending'
    `);

    await client.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS paid_at
      TIMESTAMPTZ
    `);

    /* INDEXES */

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
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_one_open_order_per_listing
      ON orders(listing_id)
      WHERE status IN ('pending', 'paid')
    `);

    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS
      idx_orders_payment_ref
      ON orders(payment_ref)
      WHERE payment_ref IS NOT NULL
    `);

    await client.query("COMMIT");

    console.log("Database initialized");
  } catch (error) {
    await client.query("ROLLBACK");

    console.error(
      "Database initialization failed:",
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

/* =======================================================
   ROOT
======================================================= */

app.get("/", (req, res) => {
  res.json({
    name: "eFootball Market API",
    version: "4.1.0",
    status: "running",
  });
});

/* =======================================================
   HEALTH
======================================================= */

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      version: "4.1.0",
    });
  } catch {
    res.status(503).json({
      status: "error",
      database: "disconnected",
    });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "ok",
      database: "connected",
      version: "4.1.0",
    });
  } catch {
    res.status(503).json({
      status: "error",
      database: "disconnected",
    });
  }
});

/* =======================================================
   REGISTER
======================================================= */

app.post(
  "/api/auth/register",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many registration attempts",
  }),
  async (req, res, next) => {
    try {
      const email = cleanText(
        req.body?.email,
        255
      ).toLowerCase();

      const password = String(
        req.body?.password || ""
      );

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error: "Invalid email",
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

      const existing = await pool.query(
        `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [email]
      );

      if (existing.rowCount > 0) {
        return res.status(409).json({
          error: "Email already registered",
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        12
      );

      const result = await pool.query(
        `
        INSERT INTO users (
          email,
          password_hash,
          role
        )
        VALUES (
          $1,
          $2,
          'buyer'
        )
        RETURNING id, email, role
        `,
        [
          email,
          passwordHash,
        ]
      );

      const user = result.rows[0];

      const token = signToken(user);

      return res.status(201).json({
        user: publicUser(user),
        token,
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   LOGIN
======================================================= */

app.post(
  "/api/auth/login",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: "Too many login attempts",
  }),
  async (req, res, next) => {
    try {
      const email = cleanText(
        req.body?.email,
        255
      ).toLowerCase();

      const password = String(
        req.body?.password || ""
      );

      if (
        !isValidEmail(email) ||
        !password
      ) {
        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const result = await pool.query(
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

      if (result.rowCount === 0) {
        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const user = result.rows[0];

      const validPassword =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!validPassword) {
        return res.status(401).json({
          error:
            "Invalid email or password",
        });
      }

      const token = signToken(user);

      return res.json({
        user: publicUser(user),
        token,
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   PUBLIC LISTINGS
======================================================= */

app.get(
  "/api/listings",
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
  }),
  async (req, res, next) => {
    try {
      let limit = Number(
        req.query.limit || 30
      );

      let offset = Number(
        req.query.offset || 0
      );

      if (
        !Number.isInteger(limit) ||
        limit < 1
      ) {
        limit = 30;
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

      const result = await pool.query(
        `
        SELECT
          l.id,
          l.title,
          l.description,
          l.price,
          l.status,
          l.created_at,
          l.seller_id
        FROM listings l
        WHERE l.status = 'active'
        ORDER BY l.created_at DESC
        LIMIT $1
        OFFSET $2
        `,
        [
          limit,
          offset,
        ]
      );

      res.json({
        listings: result.rows,
        limit,
        offset,
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   CREATE LISTING
======================================================= */

app.post(
  "/api/listings",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    try {
      const title = cleanText(
        req.body?.title,
        150
      );

      const description = cleanText(
        req.body?.description,
        3000
      );

      const price = normalizePrice(
        req.body?.price
      );

      if (!title) {
        return res.status(400).json({
          error: "Title is required",
        });
      }

      if (!isValidPrice(price)) {
        return res.status(400).json({
          error: "Invalid price",
        });
      }

      const result = await pool.query(
        `
        INSERT INTO listings (
          seller_id,
          title,
          description,
          price,
          status
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          'active'
        )
        RETURNING *
        `,
        [
          req.user.id,
          title,
          description,
          price,
        ]
      );

      res.status(201).json({
        listing: result.rows[0],
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   MY LISTINGS
======================================================= */

app.get(
  "/api/my-listings",
  auth,
  requireRole(
    "seller",
    "admin"
  ),
  async (req, res, next) => {
    try {
      const result = await pool.query(
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
        listings: result.rows,
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   UPDATE LISTING
======================================================= */

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
      const listingId = Number(
        req.params.id
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

      await client.query("BEGIN");

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

      if (
        listingResult.rowCount === 0
      ) {
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
            "You do not own this listing",
        });
      }

      if (
        listing.status === "sold"
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            "Sold listing cannot be edited",
        });
      }

      const openOrder =
        await client.query(
          `
          SELECT id
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

      const hasOpenOrder =
        openOrder.rowCount > 0;

      let title =
        listing.title;

      let description =
        listing.description;

      let price =
        Number(listing.price);

      let status =
        listing.status;

      if (
        req.body?.title !== undefined
      ) {
        title = cleanText(
          req.body.title,
          150
        );
      }

      if (
        req.body?.description !==
        undefined
      ) {
        description =
          cleanText(
            req.body.description,
            3000
          );
      }

      if (
        req.body?.price !==
        undefined
      ) {
        price =
          normalizePrice(
            req.body.price
          );
      }

      if (
        req.body?.status !==
        undefined
      ) {
        status = cleanText(
          req.body.status,
          20
        );
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

      if (
        ![
          "active",
          "cancelled",
        ].includes(status)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          error:
            "Invalid listing status",
        });
      }

      if (hasOpenOrder) {
        const priceChanged =
          Number(listing.price) !==
          Number(price);

        const titleChanged =
          listing.title !== title;

        const descriptionChanged =
          listing.description !==
          description;

        if (
          priceChanged ||
          titleChanged ||
          descriptionChanged
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Listing cannot be edited while an order is active",
          });
        }

        if (
          status === "cancelled"
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Listing cannot be cancelled while an order is active",
          });
        }
      }

      const result =
        await client.query(
          `
          UPDATE listings
          SET
            title = $1,
            description = $2,
            price = $3,
            status = $4
          WHERE id = $5
          RETURNING *
          `,
          [
            title,
            description,
            price,
            status,
            listingId,
          ]
        );

      await client.query(
        "COMMIT"
      );

      res.json({
        listing:
          result.rows[0],
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

/* =======================================================
   CREATE ORDER
======================================================= */

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
            "Invalid listing_id",
        });
      }

      await client.query(
        "BEGIN"
      );

      const listingResult =
        await client.query(
          `
          SELECT
            id,
            seller_id,
            title,
            price,
            status
          FROM listings
          WHERE id = $1
          FOR UPDATE
          `,
          [listingId]
        );

      if (
        listingResult.rowCount ===
        0
      ) {
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
        listing.status !==
        "active"
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
        req.user.role !==
          "admin" &&
        String(
          listing.seller_id
        ) ===
          String(req.user.id)
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(400).json({
          error:
            "You cannot buy your own listing",
        });
      }

      const existing =
        await client.query(
          `
          SELECT
            id,
            status
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

      if (
        existing.rowCount > 0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            "Listing already has an active order",
          order_id:
            existing.rows[0].id,
        });
      }

      const orderPrice =
        normalizePrice(
          listing.price
        );

      const orderResult =
        await client.query(
          `
          INSERT INTO orders (
            buyer_id,
            listing_id,
            price,
            status,
            payment_status
          )
          VALUES (
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
            orderPrice,
          ]
        );

      await client.query(
        "COMMIT"
      );

      res.status(201).json({
        order:
          orderResult.rows[0],
      });
    } catch (error) {
      try {
        await client.query(
          "ROLLBACK"
        );
      } catch {}

      if (
        error?.code === "23505"
      ) {
        return res.status(409).json({
          error:
            "Listing already has an active order",
        });
      }

      next(error);
    } finally {
      client.release();
    }
  }
);

/* =======================================================
   GET ORDERS
======================================================= */

app.get(
  "/api/orders",
  auth,
  async (req, res, next) => {
    try {
      let limit = Number(
        req.query.limit || 30
      );

      let offset = Number(
        req.query.offset || 0
      );

      if (
        !Number.isInteger(limit) ||
        limit < 1
      ) {
        limit = 30;
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

      let result;

      if (
        req.user.role ===
        "admin"
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
            ORDER BY o.created_at DESC
            LIMIT $1
            OFFSET $2
            `,
            [
              limit,
              offset,
            ]
          );
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
            WHERE l.seller_id = $3
            ORDER BY o.created_at DESC
            LIMIT $1
            OFFSET $2
            `,
            [
              limit,
              offset,
              req.user.id,
            ]
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
            WHERE o.buyer_id = $3
            ORDER BY o.created_at DESC
            LIMIT $1
            OFFSET $2
            `,
            [
              limit,
              offset,
              req.user.id,
            ]
          );
      }

      res.json({
        orders:
          result.rows,
        limit,
        offset,
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =======================================================
   GET SINGLE ORDER
======================================================= */

app.get(
  "/api/orders/:id",
  auth,
  async (req, res, next) => {
    try {
      const orderId =
        Number(req.params.id);

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
          [orderId]
        );

      if (
        result.rowCount ===
        0
      ) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const order =
        result.rows[0];

      const allowed =
        req.user.role ===
          "admin" ||
        String(
          order.buyer_id
        ) ===
          String(req.user.id) ||
        String(
          order.seller_id
        ) ===
          String(req.user.id);

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

/* =======================================================
   PAYMENT CONFIRMATION
======================================================= */

/*
  IMPORTANT

  This endpoint is intentionally NOT exposed
  to normal sellers/buyers.

  A real payment provider webhook must eventually
  call internal payment-confirmation logic after
  verifying the provider signature/server response.

  Never trust:
    POST /api/orders/:id/payment-confirmed
  from the browser.
*/

/* =======================================================
   UPDATE ORDER STATUS
======================================================= */

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
        Number(req.params.id);

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
          "paid",
          "completed",
          "cancelled",
        ].includes(newStatus)
      ) {
        return res.status(400).json({
          error:
            "Invalid status",
        });
      }

      await client.query(
        "BEGIN"
      );

      const result =
        await client.query(
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

      if (
        result.rowCount ===
        0
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const order =
        result.rows[0];

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

      /*
        IMPORTANT SECURITY RULE

        Seller cannot manually change:

        pending -> paid

        Only a verified payment webhook
        should make payment_status = paid
        and status = paid.
      */

      const validTransitions = {
        pending: [
          "cancelled",
        ],

        paid: [
          "completed",
        ],

        completed: [],

        cancelled: [],
      };

      if (
        !validTransitions[
          order.status
        ]?.includes(
          newStatus
        )
      ) {
        await client.query(
          "ROLLBACK"
        );

        return res.status(409).json({
          error:
            `Cannot change order from ${order.status} to ${newStatus}`,
        });
      }

      /*
        COMPLETION REQUIRES
        CONFIRMED PAYMENT
      */

      if (
        newStatus ===
        "completed"
      ) {
        if (
          order.payment_status !==
          "paid"
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Payment has not been confirmed",
          });
        }

        /*
          Listing becomes sold only after
          payment has been confirmed.
        */

        const listingUpdate =
          await client.query(
            `
            UPDATE listings
            SET status = 'sold'
            WHERE id = $1
              AND status = 'active'
            RETURNING id
            `,
            [
              order.listing_id,
            ]
          );

        if (
          listingUpdate.rowCount ===
          0
        ) {
          await client.query(
            "ROLLBACK"
          );

          return res.status(409).json({
            error:
              "Listing is no longer available for completion",
          });
        }
      }

      /*
        CANCEL PENDING ORDER

        Listing returns to active
        unless it has already been sold.
      */

      if (
        newStatus ===
        "cancelled"
      ) {
        await client.query(
          `
          UPDATE listings
          SET status = 'active'
          WHERE id = $1
            AND status <> 'sold'
          `,
          [
            order.listing_id,
          ]
        );

        await client.query(
          `
          UPDATE orders
          SET payment_status =
            CASE
              WHEN payment_status = 'paid'
              THEN payment_status
              ELSE 'cancelled'
            END
          WHERE id = $1
          `,
          [orderId]
        );
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

/* =======================================================
   ADMIN / PAYMENT INTERNAL HELPER
======================================================= */

/*
  This function is prepared for the future
  TrueMoney/payment provider webhook.

  It MUST only be called after the provider's
  signature/server-side verification succeeds.
*/

async function markOrderPaid({
  paymentProvider,
  paymentRef,
  orderId,
}) {
  const client =
    await pool.connect();

  try {
    await client.query(
      "BEGIN"
    );

    const result =
      await client.query(
        `
        SELECT
          id,
          listing_id,
          price,
          status,
          payment_status
        FROM orders
        WHERE id = $1
        FOR UPDATE
        `,
        [orderId]
      );

    if (
      result.rowCount ===
      0
    ) {
      throw new Error(
        "Order not found"
      );
    }

    const order =
      result.rows[0];

    /*
      Idempotency:
      already paid = do not charge/update twice.
    */

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
      "pending"
    ) {
      throw new Error(
        "Order is not pending"
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
        WHERE id = $3
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

    if (
      updated.rowCount ===
      0
    ) {
      throw new Error(
        "Payment confirmation failed"
      );
    }

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

/* =======================================================
   STATS
======================================================= */

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
                SELECT COALESCE(
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
                WHERE seller_id = $1
                  AND status = 'active'
              ) AS active_listings,

              (
                SELECT COUNT(*)
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE l.seller_id = $1
              ) AS orders,

              (
                SELECT COUNT(*)
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE l.seller_id = $1
                  AND o.status = 'completed'
              ) AS completed_orders,

              (
                SELECT COALESCE(
                  SUM(o.price),
                  0
                )
                FROM orders o
                JOIN listings l
                  ON l.id = o.listing_id
                WHERE l.seller_id = $1
                  AND o.status = 'completed'
              ) AS completed_revenue
            `,
            [
              req.user.id,
            ]
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

/* =======================================================
   404
======================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "Route not found",
    });
  }
);

/* =======================================================
   ERROR HANDLER
======================================================= */

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

    return res.status(500).json({
      error:
        "Internal server error",
    });
  }
);

/* =======================================================
   START SERVER
======================================================= */

async function start() {
  try {
    await initializeDatabase();

    const server =
      app.listen(
        PORT,
        () => {
          console.log(
            `eFootball Market API v4.1.0 running on port ${PORT}`
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