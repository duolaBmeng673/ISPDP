const crypto = require("crypto");
const path = require("path");

require("dotenv").config();

const argon2 = require("argon2");
const express = require("express");
const rateLimit = require("express-rate-limit");
const session = require("express-session");
const helmet = require("helmet");
const mysql = require("mysql2/promise");
const nodemailer = require("nodemailer");
const { z } = require("zod");

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-only-session-secret-change-me";
const isProduction = process.env.NODE_ENV === "production";
const publicDir = path.join(__dirname, "public");
const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const EMAIL_CODE_TTL_MS = 10 * 60 * 1000;

const dbConfig = {
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "ispdp",
};

const smtpConfig = {
  host: process.env.SMTP_HOST || "",
  port: Number(process.env.SMTP_PORT) || 587,
  user: process.env.SMTP_USER || "",
  pass: process.env.SMTP_PASS || "",
  from: process.env.MAIL_FROM || process.env.SMTP_USER || "no-reply@example.com",
};

let pool;

const pemRegex = /^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----\s*$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const registerSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "用户名至少需要 3 个字符。")
    .max(24, "用户名最多 24 个字符。")
    .regex(/^[a-zA-Z0-9_]+$/, "用户名只能包含字母、数字和下划线。"),
  email: z
    .string()
    .trim()
    .toLowerCase()
    .min(6, "请输入有效邮箱。")
    .max(120, "邮箱长度不正确。")
    .regex(emailRegex, "请输入有效邮箱。"),
  password: z
    .string()
    .min(10, "密码至少需要 10 个字符。")
    .max(72, "密码长度不能超过 72 个字符。")
    .regex(/[a-z]/, "密码至少需要一个小写字母。")
    .regex(/[A-Z]/, "密码至少需要一个大写字母。")
    .regex(/\d/, "密码至少需要一个数字。")
    .regex(/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/, "密码至少需要一个特殊字符。"),
  publicKey: z
    .string()
    .trim()
    .min(100, "RSA 公钥格式不正确。")
    .max(5000, "RSA 公钥长度异常。")
    .regex(pemRegex, "RSA 公钥必须是 PEM 格式。"),
});

const loginSchema = z.object({
  username: z.string().trim().min(1, "请输入用户名。").max(24, "用户名格式不正确。"),
  password: z.string().min(1, "请输入密码。").max(72, "密码格式不正确。"),
});

const verifySchema = z.object({
  username: z.string().trim().min(1, "请输入用户名。").max(24, "用户名格式不正确。"),
  challengeId: z.coerce.number().int().positive("挑战编号不正确。"),
  challenge: z.string().trim().min(32, "挑战内容不正确。").max(512, "挑战内容不正确。"),
  signature: z.string().trim().min(32, "签名不能为空。").max(4096, "签名长度异常。"),
});

const emailCodeRequestSchema = z.object({
  username: z.string().trim().min(1, "请输入用户名。").max(24, "用户名格式不正确。"),
  password: z.string().min(1, "请输入密码。").max(72, "密码格式不正确。"),
});

const emailCodeVerifySchema = z.object({
  username: z.string().trim().min(1, "请输入用户名。").max(24, "用户名格式不正确。"),
  code: z.string().trim().regex(/^\d{6}$/, "邮箱验证码必须为 6 位数字。"),
  newPublicKey: z
    .string()
    .trim()
    .min(100, "RSA 公钥格式不正确。")
    .max(5000, "RSA 公钥长度异常。")
    .regex(pemRegex, "RSA 公钥必须是 PEM 格式。"),
});

const createOrderSchema = z.object({
  shippingName: z.string().trim().min(2, "请输入收货人姓名。").max(30, "收货人姓名过长。"),
  shippingPhone: z.string().trim().min(6, "请输入联系电话。").max(20, "联系电话格式不正确。"),
  shippingAddress: z.string().trim().min(8, "请输入详细收货地址。").max(200, "收货地址过长。"),
  note: z.string().trim().max(200, "订单备注过长。").optional().default(""),
  items: z.array(z.object({
    productId: z.coerce.number().int().positive("商品编号不正确。"),
    quantity: z.coerce.number().int().min(1, "购买数量至少为 1。").max(99, "单件商品数量过大。"),
  })).min(1, "购物车不能为空。"),
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: "请求过于频繁，请 15 分钟后再试。" },
});

app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: isProduction ? [] : null,
      },
    },
  })
);
app.use(express.json({ limit: "10kb" }));
app.use(
  session({
    name: "sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: isProduction,
      maxAge: 1000 * 60 * 60,
    },
  })
);

app.use("/api/auth", authLimiter);
app.use(express.static(publicDir));

function createChallengeValue() {
  return crypto.randomBytes(32).toString("base64url");
}

function createEmailCode() {
  return String(crypto.randomInt(100000, 1000000));
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function toExpirationDate(ttlMs) {
  return new Date(Date.now() + ttlMs);
}

function verifySignature(publicKeyPem, challenge, signatureBase64) {
  try {
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(challenge);
    verifier.end();
    return verifier.verify(publicKeyPem, Buffer.from(signatureBase64, "base64"));
  } catch (error) {
    console.error("RSA verify error:", error);
    return false;
  }
}

function hasSmtpConfig() {
  return Boolean(smtpConfig.host && smtpConfig.user && smtpConfig.pass);
}

function createMailTransport() {
  if (hasSmtpConfig()) {
    return nodemailer.createTransport({
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.port === 465,
      auth: {
        user: smtpConfig.user,
        pass: smtpConfig.pass,
      },
    });
  }

  return nodemailer.createTransport({
    streamTransport: true,
    newline: "unix",
    buffer: true,
  });
}

async function sendRecoveryEmail(email, username, code) {
  const transporter = createMailTransport();
  const mail = await transporter.sendMail({
    from: smtpConfig.from,
    to: email,
    subject: "设备恢复验证码",
    text: `用户 ${username} 正在执行新设备 RSA 密钥重绑操作。\n验证码：${code}\n有效期：10 分钟。\n如果不是你本人操作，请忽略此邮件。`,
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.6;">
        <h2>设备恢复验证码</h2>
        <p>用户 <strong>${username}</strong> 正在执行新设备 RSA 密钥重绑操作。</p>
        <p>本次验证码为：</p>
        <p style="font-size: 28px; letter-spacing: 6px; font-weight: bold;">${code}</p>
        <p>验证码有效期 10 分钟。如果不是你本人操作，请忽略此邮件。</p>
      </div>
    `,
  });

  if (!hasSmtpConfig()) {
    console.log("Mail preview:", mail.message.toString());
  }
}

async function ensureColumn(tableName, columnName, definition) {
  const [rows] = await pool.query(
    `
      SELECT COUNT(*) AS count
      FROM information_schema.COLUMNS
      WHERE TABLE_SCHEMA = ?
        AND TABLE_NAME = ?
        AND COLUMN_NAME = ?
    `,
    [dbConfig.database, tableName, columnName]
  );

  if (!rows[0].count) {
    await pool.query(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  }
}

async function initDatabase() {
  const serverPool = mysql.createPool({
    host: dbConfig.host,
    port: dbConfig.port,
    user: dbConfig.user,
    password: dbConfig.password,
    waitForConnections: true,
    connectionLimit: 10,
  });

  await serverPool.query(
    `CREATE DATABASE IF NOT EXISTS \`${dbConfig.database}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci`
  );
  await serverPool.end();

  pool = mysql.createPool({
    ...dbConfig,
    waitForConnections: true,
    connectionLimit: 10,
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(24) NOT NULL UNIQUE,
      password_hash VARCHAR(255) NOT NULL,
      public_key TEXT NULL,
      email VARCHAR(120) NULL UNIQUE,
      email_verified TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  await ensureColumn("users", "public_key", "TEXT NULL");
  await ensureColumn("users", "email", "VARCHAR(120) NULL UNIQUE");
  await ensureColumn("users", "email_verified", "TINYINT(1) NOT NULL DEFAULT 0");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS login_challenges (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id BIGINT NOT NULL,
      challenge_hash CHAR(64) NOT NULL,
      expires_at DATETIME NOT NULL,
      used TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_login_challenges_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,
      INDEX idx_login_challenges_user (user_id),
      INDEX idx_login_challenges_expires (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS email_verification_codes (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id BIGINT NOT NULL,
      code_hash CHAR(64) NOT NULL,
      purpose VARCHAR(32) NOT NULL,
      expires_at DATETIME NOT NULL,
      used TINYINT(1) NOT NULL DEFAULT 0,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_email_codes_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,
      INDEX idx_email_codes_user (user_id),
      INDEX idx_email_codes_expires (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      name VARCHAR(80) NOT NULL,
      category VARCHAR(40) NOT NULL,
      price DECIMAL(10,2) NOT NULL,
      stock INT NOT NULL DEFAULT 0,
      description TEXT NOT NULL,
      badge VARCHAR(40) NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS orders (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      user_id BIGINT NOT NULL,
      order_no VARCHAR(32) NOT NULL UNIQUE,
      total_amount DECIMAL(10,2) NOT NULL,
      status VARCHAR(30) NOT NULL DEFAULT '待付款确认',
      shipping_name VARCHAR(30) NOT NULL,
      shipping_phone VARCHAR(20) NOT NULL,
      shipping_address VARCHAR(200) NOT NULL,
      note VARCHAR(200) NOT NULL DEFAULT '',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      CONSTRAINT fk_orders_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,
      INDEX idx_orders_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS order_items (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      order_id BIGINT NOT NULL,
      product_id BIGINT NOT NULL,
      product_name VARCHAR(80) NOT NULL,
      unit_price DECIMAL(10,2) NOT NULL,
      quantity INT NOT NULL,
      subtotal DECIMAL(10,2) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_order_items_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
        ON DELETE CASCADE,
      CONSTRAINT fk_order_items_product
        FOREIGN KEY (product_id) REFERENCES products(id)
        ON DELETE RESTRICT,
      INDEX idx_order_items_order (order_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci
  `);

  const [productCountRows] = await pool.query("SELECT COUNT(*) AS count FROM products");
  if (!productCountRows[0].count) {
    await pool.query(
      `
        INSERT INTO products (name, category, price, stock, description, badge)
        VALUES
        (?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?),
        (?, ?, ?, ?, ?, ?)
      `,
      [
        "安全支付U盾 Pro", "认证设备", 299.0, 32, "面向高安全场景的 USB 认证设备，支持私钥隔离存储与双因子登录演示。", "热销",
        "企业加密网关 Lite", "网络安全", 899.0, 15, "适用于中小型系统的加密接入网关，可用于 HTTPS 接入与传输层策略控制。", "新品",
        "签名密钥备份盒", "密钥管理", 459.0, 24, "离线备份 RSA 私钥与恢复材料的教学演示设备，适合课程展示。", "恢复方案",
        "认证日志审计屏", "审计监控", 699.0, 18, "对登录、验签、支付确认等关键行为进行可视化审计的教学面板。", "推荐",
        "虚拟银行接口沙箱包", "支付接口", 1299.0, 10, "用于模拟电子商务平台与虚拟银行交互的接口套件，便于后续联调。", "接口预留",
        "课程实验商城模板", "教学资源", 199.0, 50, "集成商品列表、购物车、订单确认与模拟付款确认的课程展示模板。", "演示版",
      ]
    );
  }
}

async function getUserByUsername(username) {
  const [rows] = await pool.query(
    "SELECT id, username, password_hash, public_key, email, email_verified, created_at FROM users WHERE username = ? LIMIT 1",
    [username]
  );
  return rows[0] || null;
}

async function getUserById(id) {
  const [rows] = await pool.query(
    "SELECT id, username, public_key, email, email_verified, created_at FROM users WHERE id = ? LIMIT 1",
    [id]
  );
  return rows[0] || null;
}

async function getAllProducts() {
  const [rows] = await pool.query(
    "SELECT id, name, category, price, stock, description, badge FROM products ORDER BY created_at DESC, id DESC"
  );
  return rows.map((row) => ({
    ...row,
    price: Number(row.price),
    stock: Number(row.stock),
  }));
}

async function getProductsByIds(productIds) {
  if (!productIds.length) return [];
  const placeholders = productIds.map(() => "?").join(", ");
  const [rows] = await pool.query(
    `SELECT id, name, category, price, stock, description, badge FROM products WHERE id IN (${placeholders})`,
    productIds
  );
  return rows.map((row) => ({
    ...row,
    price: Number(row.price),
    stock: Number(row.stock),
  }));
}

async function getOrdersByUserId(userId) {
  const [orders] = await pool.query(
    `
      SELECT id, order_no, total_amount, status, shipping_name, shipping_phone, shipping_address, note, created_at, updated_at
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC, id DESC
    `,
    [userId]
  );

  if (!orders.length) {
    return [];
  }

  const orderIds = orders.map((order) => order.id);
  const placeholders = orderIds.map(() => "?").join(", ");
  const [items] = await pool.query(
    `
      SELECT order_id, product_name, unit_price, quantity, subtotal
      FROM order_items
      WHERE order_id IN (${placeholders})
      ORDER BY id ASC
    `,
    orderIds
  );

  return orders.map((order) => ({
    id: Number(order.id),
    orderNo: order.order_no,
    totalAmount: Number(order.total_amount),
    status: order.status,
    shippingName: order.shipping_name,
    shippingPhone: order.shipping_phone,
    shippingAddress: order.shipping_address,
    note: order.note,
    createdAt: order.created_at,
    updatedAt: order.updated_at,
    items: items
      .filter((item) => Number(item.order_id) === Number(order.id))
      .map((item) => ({
        productName: item.product_name,
        unitPrice: Number(item.unit_price),
        quantity: Number(item.quantity),
        subtotal: Number(item.subtotal),
      })),
  }));
}

function buildOrderNumber() {
  return `ORD${Date.now()}${crypto.randomInt(100, 999)}`;
}

async function getChallengeForVerification(challengeId, username) {
  const [rows] = await pool.query(
    `
      SELECT lc.id, lc.user_id, lc.challenge_hash, lc.expires_at, lc.used, u.username, u.public_key
      FROM login_challenges lc
      INNER JOIN users u ON u.id = lc.user_id
      WHERE lc.id = ? AND u.username = ?
      LIMIT 1
    `,
    [challengeId, username]
  );
  return rows[0] || null;
}

async function getEmailCodeForVerification(username, code, purpose) {
  const [rows] = await pool.query(
    `
      SELECT evc.id, evc.user_id, evc.code_hash, evc.expires_at, evc.used, evc.purpose, u.username, u.email
      FROM email_verification_codes evc
      INNER JOIN users u ON u.id = evc.user_id
      WHERE u.username = ?
        AND evc.purpose = ?
        AND evc.used = 0
      ORDER BY evc.id DESC
      LIMIT 1
    `,
    [username, purpose]
  );

  const record = rows[0] || null;
  if (!record) {
    return null;
  }

  if (sha256Hex(code) !== record.code_hash) {
    return { ...record, matched: false };
  }

  return { ...record, matched: true };
}

async function createLoginChallenge(userId) {
  const challenge = createChallengeValue();
  const challengeHash = sha256Hex(challenge);
  const expiresAt = toExpirationDate(CHALLENGE_TTL_MS);

  await pool.query("DELETE FROM login_challenges WHERE expires_at < NOW() OR used = 1");
  const [result] = await pool.query(
    "INSERT INTO login_challenges (user_id, challenge_hash, expires_at) VALUES (?, ?, ?)",
    [userId, challengeHash, expiresAt]
  );

  return {
    challengeId: Number(result.insertId),
    challenge,
    expiresAt,
  };
}

async function createEmailVerificationCode(userId, purpose) {
  const code = createEmailCode();
  const codeHash = sha256Hex(code);
  const expiresAt = toExpirationDate(EMAIL_CODE_TTL_MS);

  await pool.query("DELETE FROM email_verification_codes WHERE expires_at < NOW() OR used = 1");
  const [result] = await pool.query(
    "INSERT INTO email_verification_codes (user_id, code_hash, purpose, expires_at) VALUES (?, ?, ?, ?)",
    [userId, codeHash, purpose, expiresAt]
  );

  return {
    id: Number(result.insertId),
    code,
    expiresAt,
  };
}

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "请先登录。" });
  }
  next();
}

function sendValidationError(res, error) {
  const firstIssue = error.issues?.[0];
  return res.status(400).json({
    success: false,
    message: firstIssue?.message || "提交的数据格式不正确。",
  });
}

app.post("/api/auth/register", async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { username, email, password, publicKey } = parsed.data;

  try {
    const existingUser = await getUserByUsername(username);
    if (existingUser) {
      return res.status(409).json({ success: false, message: "用户名已存在，请更换一个。" });
    }

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 19456,
      timeCost: 2,
      parallelism: 1,
    });

    const [result] = await pool.query(
      "INSERT INTO users (username, email, email_verified, password_hash, public_key) VALUES (?, ?, 1, ?, ?)",
      [username, email, passwordHash, publicKey]
    );

    req.session.user = {
      id: Number(result.insertId),
      username,
    };

    return res.status(201).json({
      success: true,
      message: "注册成功，邮箱已绑定，RSA 密钥已绑定，已自动登录。",
      user: { username, rsaEnabled: true, email },
    });
  } catch (error) {
    if (error && error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({ success: false, message: "用户名或邮箱已存在，请更换后重试。" });
    }

    console.error("Register error:", error);
    return res.status(500).json({ success: false, message: "服务器繁忙，请稍后重试。" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { username, password } = parsed.data;

  try {
    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ success: false, message: "用户名或密码错误。" });
    }

    const isValid = await argon2.verify(user.password_hash, password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: "用户名或密码错误。" });
    }

    if (!user.public_key) {
      return res.status(403).json({ success: false, message: "该账号未绑定 RSA 公钥，可通过邮箱恢复后重新绑定。" });
    }

    const pendingChallenge = await createLoginChallenge(user.id);
    return res.json({
      success: true,
      requiresSignature: true,
      message: "密码校验通过，请完成 RSA 私钥签名。",
      challengeId: pendingChallenge.challengeId,
      challenge: pendingChallenge.challenge,
      expiresAt: pendingChallenge.expiresAt,
    });
  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ success: false, message: "服务器繁忙，请稍后重试。" });
  }
});

app.post("/api/auth/verify-signature", async (req, res) => {
  const parsed = verifySchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { username, challengeId, challenge, signature } = parsed.data;

  try {
    const challengeRecord = await getChallengeForVerification(challengeId, username);
    if (!challengeRecord) {
      return res.status(404).json({ success: false, message: "未找到待验证的挑战记录。" });
    }

    if (challengeRecord.used) {
      return res.status(400).json({ success: false, message: "该挑战码已被使用，请重新登录。" });
    }

    if (new Date(challengeRecord.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ success: false, message: "挑战码已过期，请重新登录。" });
    }

    if (sha256Hex(challenge) !== challengeRecord.challenge_hash) {
      return res.status(401).json({ success: false, message: "挑战内容不匹配，请重新登录。" });
    }

    const verified = verifySignature(challengeRecord.public_key, challenge, signature);
    if (!verified) {
      return res.status(401).json({ success: false, message: "RSA 签名验证失败，请确认本地私钥正确。" });
    }

    await pool.query("UPDATE login_challenges SET used = 1 WHERE id = ?", [challengeId]);

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regenerate error:", err);
        return res.status(500).json({ success: false, message: "登录失败，请稍后重试。" });
      }

      req.session.user = {
        id: Number(challengeRecord.user_id),
        username: challengeRecord.username,
      };

      return res.json({
        success: true,
        message: "双因子认证成功，已安全登录。",
      });
    });
  } catch (error) {
    console.error("Signature verify error:", error);
    return res.status(500).json({ success: false, message: "验签失败，请稍后再试。" });
  }
});

app.post("/api/auth/request-email-recovery", async (req, res) => {
  const parsed = emailCodeRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { username, password } = parsed.data;

  try {
    const user = await getUserByUsername(username);
    if (!user) {
      return res.status(401).json({ success: false, message: "用户名或密码错误。" });
    }

    const isValid = await argon2.verify(user.password_hash, password);
    if (!isValid) {
      return res.status(401).json({ success: false, message: "用户名或密码错误。" });
    }

    if (!user.email || !user.email_verified) {
      return res.status(403).json({ success: false, message: "该账号未绑定已验证邮箱，无法进行跨设备恢复。" });
    }

    const verification = await createEmailVerificationCode(user.id, "device_rebind");
    await sendRecoveryEmail(user.email, user.username, verification.code);

    return res.json({
      success: true,
      message: hasSmtpConfig()
        ? "邮箱验证码已发送，请查收后完成新设备绑定。"
        : "验证码已生成。当前未配置真实 SMTP，验证码内容已输出到服务器日志用于本地演示。",
      expiresAt: verification.expiresAt,
    });
  } catch (error) {
    console.error("Email recovery request error:", error);
    return res.status(500).json({ success: false, message: "发送邮箱验证码失败，请稍后再试。" });
  }
});

app.post("/api/auth/verify-email-recovery", async (req, res) => {
  const parsed = emailCodeVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { username, code, newPublicKey } = parsed.data;

  try {
    const codeRecord = await getEmailCodeForVerification(username, code, "device_rebind");
    if (!codeRecord) {
      return res.status(404).json({ success: false, message: "未找到有效的邮箱验证码，请重新申请。" });
    }

    if (codeRecord.used) {
      return res.status(400).json({ success: false, message: "该验证码已使用，请重新申请。" });
    }

    if (new Date(codeRecord.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ success: false, message: "邮箱验证码已过期，请重新申请。" });
    }

    if (!codeRecord.matched) {
      return res.status(401).json({ success: false, message: "邮箱验证码错误。" });
    }

    await pool.query("UPDATE email_verification_codes SET used = 1 WHERE id = ?", [codeRecord.id]);
    await pool.query("UPDATE users SET public_key = ? WHERE id = ?", [newPublicKey, codeRecord.user_id]);

    req.session.regenerate((err) => {
      if (err) {
        console.error("Session regenerate error:", err);
        return res.status(500).json({ success: false, message: "恢复成功，但登录失败，请重新尝试。" });
      }

      req.session.user = {
        id: Number(codeRecord.user_id),
        username: codeRecord.username,
      };

      return res.json({
        success: true,
        message: "邮箱验证成功，当前设备已绑定新的 RSA 公钥，并已登录。",
      });
    });
  } catch (error) {
    console.error("Email recovery verify error:", error);
    return res.status(500).json({ success: false, message: "邮箱恢复失败，请稍后再试。" });
  }
});

app.get("/api/shop/products", requireAuth, async (req, res) => {
  try {
    const products = await getAllProducts();
    return res.json({ success: true, products });
  } catch (error) {
    console.error("Load products error:", error);
    return res.status(500).json({ success: false, message: "加载商品失败，请稍后重试。" });
  }
});

app.get("/api/shop/orders", requireAuth, async (req, res) => {
  try {
    const orders = await getOrdersByUserId(req.session.user.id);
    return res.json({ success: true, orders });
  } catch (error) {
    console.error("Load orders error:", error);
    return res.status(500).json({ success: false, message: "加载订单失败，请稍后重试。" });
  }
});

app.post("/api/shop/orders", requireAuth, async (req, res) => {
  const parsed = createOrderSchema.safeParse(req.body);
  if (!parsed.success) {
    return sendValidationError(res, parsed.error);
  }

  const { shippingName, shippingPhone, shippingAddress, note, items } = parsed.data;

  try {
    const requestedIds = items.map((item) => item.productId);
    const products = await getProductsByIds(requestedIds);
    if (products.length !== requestedIds.length) {
      return res.status(400).json({ success: false, message: "购物车中包含不存在的商品。" });
    }

    const productMap = new Map(products.map((product) => [Number(product.id), product]));
    let totalAmount = 0;
    const normalizedItems = [];

    for (const item of items) {
      const product = productMap.get(Number(item.productId));
      if (!product) {
        return res.status(400).json({ success: false, message: "购物车中包含不存在的商品。" });
      }
      if (product.stock < item.quantity) {
        return res.status(400).json({ success: false, message: `${product.name} 库存不足。` });
      }

      const subtotal = Number((product.price * item.quantity).toFixed(2));
      totalAmount += subtotal;
      normalizedItems.push({
        productId: Number(product.id),
        productName: product.name,
        unitPrice: product.price,
        quantity: item.quantity,
        subtotal,
      });
    }

    totalAmount = Number(totalAmount.toFixed(2));
    const orderNo = buildOrderNumber();
    const connection = await pool.getConnection();

    try {
      await connection.beginTransaction();
      const [orderResult] = await connection.query(
        `
          INSERT INTO orders (user_id, order_no, total_amount, status, shipping_name, shipping_phone, shipping_address, note)
          VALUES (?, ?, ?, '待付款确认', ?, ?, ?, ?)
        `,
        [req.session.user.id, orderNo, totalAmount, shippingName, shippingPhone, shippingAddress, note]
      );

      const orderId = Number(orderResult.insertId);
      for (const item of normalizedItems) {
        await connection.query(
          `
            INSERT INTO order_items (order_id, product_id, product_name, unit_price, quantity, subtotal)
            VALUES (?, ?, ?, ?, ?, ?)
          `,
          [orderId, item.productId, item.productName, item.unitPrice, item.quantity, item.subtotal]
        );
        await connection.query(
          "UPDATE products SET stock = stock - ? WHERE id = ?",
          [item.quantity, item.productId]
        );
      }

      await connection.commit();
      return res.status(201).json({
        success: true,
        message: "订单已创建，当前为待付款确认状态。",
        orderNo,
      });
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error("Create order error:", error);
    return res.status(500).json({ success: false, message: "创建订单失败，请稍后重试。" });
  }
});

app.post("/api/shop/orders/:orderId/pay", requireAuth, async (req, res) => {
  const orderId = Number(req.params.orderId);
  if (!Number.isInteger(orderId) || orderId <= 0) {
    return res.status(400).json({ success: false, message: "订单编号不正确。" });
  }

  try {
    const [rows] = await pool.query(
      "SELECT id, status FROM orders WHERE id = ? AND user_id = ? LIMIT 1",
      [orderId, req.session.user.id]
    );
    const order = rows[0];
    if (!order) {
      return res.status(404).json({ success: false, message: "未找到该订单。" });
    }
    if (order.status !== "待付款确认") {
      return res.status(400).json({ success: false, message: "当前订单状态不允许重复付款确认。" });
    }

    await pool.query(
      "UPDATE orders SET status = '交易成功-待发货' WHERE id = ?",
      [orderId]
    );
    return res.json({
      success: true,
      message: "模拟付款确认成功。后续可对接虚拟银行接口返回结果。",
    });
  } catch (error) {
    console.error("Pay order error:", error);
    return res.status(500).json({ success: false, message: "付款确认失败，请稍后重试。" });
  }
});

app.get("/api/auth/session", async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: "未登录。" });
  }

  try {
    const user = await getUserById(req.session.user.id);
    if (!user) {
      req.session.destroy(() => {});
      return res.status(401).json({ success: false, message: "登录状态已失效。" });
    }

    return res.json({
      success: true,
      user: {
        id: Number(user.id),
        username: user.username,
        email: user.email,
        emailVerified: Boolean(user.email_verified),
        createdAt: user.created_at,
        rsaEnabled: Boolean(user.public_key),
      },
    });
  } catch (error) {
    console.error("Session error:", error);
    return res.status(500).json({ success: false, message: "读取会话失败，请稍后重试。" });
  }
});

app.post("/api/auth/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ success: false, message: "退出失败，请稍后重试。" });
    }

    res.clearCookie("sid");
    return res.json({ success: true, message: "已安全退出登录。" });
  });
});

app.get("/dashboard.html", (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/index.html");
  }
  return next();
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: "请求的资源不存在。" });
});

async function start() {
  try {
    await initDatabase();
    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
      console.log(`MySQL schema: ${dbConfig.database}`);
    });
  } catch (error) {
    console.error("Failed to initialize MySQL:", error);
    process.exit(1);
  }
}

start();
