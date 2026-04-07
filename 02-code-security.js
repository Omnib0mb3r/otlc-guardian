/**
 * ============================================================
 * OTLC GUARDIAN — Code Security Standards
 * // security · onthelevelconcepts.com
 * Version: 1.0.0
 * ============================================================
 *
 * Production security utilities for Node.js/Express projects.
 * Covers: secure headers, rate limiting, env validation,
 * request ID threading, structured logging, error responses.
 *
 * Usage:
 *   import { applySecureHeaders, rateLimitMiddleware,
 *            validateEnv, requestIdMiddleware,
 *            errorHandler } from './security/02-code-security.js';
 *
 * ============================================================
 */

import crypto from "crypto";

// ---------------------------------------------------------------------------
// ENVIRONMENT VALIDATION
// Call at app startup. Fails fast before any server starts.
// ---------------------------------------------------------------------------

/**
 * Validates required environment variables exist.
 * Fails loudly — never silently start with missing config.
 *
 * @param {string[]} required - env var names that must exist
 * @param {string[]} recommended - env var names that should exist (warn only)
 */
export function validateEnv(required = [], recommended = []) {
  const missing = required.filter((key) => !process.env[key]);

  if (missing.length > 0) {
    console.error(`\n🚨 [OTLC GUARDIAN] MISSING REQUIRED ENVIRONMENT VARIABLES`);
    missing.forEach((key) => console.error(`    → ${key}`));
    console.error(`\n    Copy .env.example to .env and fill in all required values.`);
    console.error(`    On Windows: set ${missing[0]}=your_value_here\n`);
    process.exit(1);
  }

  const missingRecommended = recommended.filter((key) => !process.env[key]);
  if (missingRecommended.length > 0) {
    console.warn(`\n⚠️  [OTLC GUARDIAN] RECOMMENDED ENV VARS NOT SET`);
    missingRecommended.forEach((key) => console.warn(`    → ${key}`));
    console.warn("");
  }

  console.info(`✅ [OTLC GUARDIAN] Environment validated — all required vars present.\n`);
}

// ---------------------------------------------------------------------------
// SECURE HEADERS
// Industry-standard HTTP security headers.
// ---------------------------------------------------------------------------

export const SECURE_HEADERS = {
  "X-Content-Type-Options":           "nosniff",
  "X-Frame-Options":                  "DENY",
  "X-XSS-Protection":                 "1; mode=block",
  "Referrer-Policy":                  "strict-origin-when-cross-origin",
  "Permissions-Policy":               "camera=(), microphone=(), geolocation=()",
  "Strict-Transport-Security":        "max-age=31536000; includeSubDomains",
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self';",
};

/**
 * Express middleware — applies all secure headers.
 * Usage: app.use(applySecureHeaders)
 */
export function applySecureHeaders(req, res, next) {
  Object.entries(SECURE_HEADERS).forEach(([key, val]) => res.setHeader(key, val));
  // Remove fingerprinting headers
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");
  next();
}

// ---------------------------------------------------------------------------
// REQUEST ID MIDDLEWARE
// Threads a UUID through every request for log correlation.
// ---------------------------------------------------------------------------

/**
 * Attaches a unique requestId to every request and response.
 * All logs, errors, and responses should include this ID.
 *
 * Usage: app.use(requestIdMiddleware)
 */
export function requestIdMiddleware(req, res, next) {
  const requestId = req.headers["x-request-id"] ?? crypto.randomUUID();
  req.requestId   = requestId;
  res.setHeader("X-Request-ID", requestId);
  next();
}

// ---------------------------------------------------------------------------
// STRUCTURED LOGGER
// Never use console.log() in production paths — use this.
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
const CURRENT_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL ?? "info"] ?? 1;

function structuredLog(level, message, meta = {}) {
  if ((LOG_LEVELS[level] ?? 0) < CURRENT_LEVEL) return;

  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...meta,
  };

  const output = JSON.stringify(entry);

  if (level === "error")  console.error(output);
  else if (level === "warn") console.warn(output);
  else console.log(output);
}

export const logger = {
  debug: (message, meta) => structuredLog("debug", message, meta),
  info:  (message, meta) => structuredLog("info",  message, meta),
  warn:  (message, meta) => structuredLog("warn",  message, meta),
  error: (message, meta) => structuredLog("error", message, meta),
};

// ---------------------------------------------------------------------------
// RATE LIMITER
// In-memory token bucket. For multi-server: swap Map for Redis.
// ---------------------------------------------------------------------------

const rateLimitStore = new Map();

/**
 * Checks rate limit for a given key.
 * @param {string} key       - e.g. user IP, userId
 * @param {number} limit     - max requests per window
 * @param {number} windowMs  - rolling window in ms
 * @returns {{ allowed: boolean, remaining: number, resetAt: number }}
 */
export function checkRateLimit(key, limit = 20, windowMs = 60_000) {
  const now    = Date.now();
  const record = rateLimitStore.get(key) ?? { count: 0, resetAt: now + windowMs };

  if (now > record.resetAt) {
    record.count  = 0;
    record.resetAt = now + windowMs;
  }

  record.count += 1;
  rateLimitStore.set(key, record);

  return {
    allowed:   record.count <= limit,
    remaining: Math.max(0, limit - record.count),
    resetAt:   record.resetAt,
  };
}

/**
 * Express rate limit middleware factory.
 * Usage: app.use('/api/chat', rateLimitMiddleware({ limit: 10, windowMs: 60000 }))
 */
export function rateLimitMiddleware({ limit = 20, windowMs = 60_000, keyFn } = {}) {
  return (req, res, next) => {
    const key    = keyFn ? keyFn(req) : (req.ip ?? req.headers["x-forwarded-for"] ?? "unknown");
    const result = checkRateLimit(key, limit, windowMs);

    res.setHeader("X-RateLimit-Limit",     limit);
    res.setHeader("X-RateLimit-Remaining", result.remaining);
    res.setHeader("X-RateLimit-Reset",     result.resetAt);

    if (!result.allowed) {
      logger.warn("Rate limit exceeded", { key, requestId: req.requestId });
      return res.status(429).json({
        success: false,
        error: {
          code:    "ERR_RATE_LIMITED",
          message: "Too many requests. Please wait before trying again.",
        },
        requestId: req.requestId,
      });
    }

    next();
  };
}

// ---------------------------------------------------------------------------
// CONSISTENT ERROR RESPONSE
// All API errors must use this shape. No exceptions.
// ---------------------------------------------------------------------------

/**
 * Sends a standardized error response.
 * Never send raw error messages or stack traces to clients.
 *
 * @param {Response} res
 * @param {number} status
 * @param {string} code     - machine-readable error code e.g. "ERR_NOT_FOUND"
 * @param {string} message  - human-readable, safe to show to users
 * @param {string} requestId
 */
export function sendError(res, status, code, message, requestId) {
  return res.status(status).json({
    success: false,
    error: { code, message },
    requestId: requestId ?? crypto.randomUUID(),
  });
}

/**
 * Sends a standardized success response.
 */
export function sendSuccess(res, data, requestId, status = 200) {
  return res.status(status).json({
    success: true,
    data,
    requestId: requestId ?? crypto.randomUUID(),
  });
}

// ---------------------------------------------------------------------------
// GLOBAL ERROR HANDLER (Express)
// Must be registered LAST in your Express app.
// Catches all unhandled errors — never leaks stack traces.
// ---------------------------------------------------------------------------

/**
 * Usage: app.use(errorHandler)   ← must be last app.use()
 */
export function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const requestId = req.requestId ?? crypto.randomUUID();

  // Log full error internally with structured logger
  logger.error("Unhandled error", {
    requestId,
    error:   err.message,
    stack:   err.stack,
    path:    req.path,
    method:  req.method,
  });

  // Never expose internal error details to the client
  const status  = err.status ?? err.statusCode ?? 500;
  const message = status < 500 ? err.message : "An unexpected error occurred.";

  return sendError(res, status, "ERR_SERVER", message, requestId);
}

// ---------------------------------------------------------------------------
// HEALTH CHECK HANDLER
// Every service must have /health. Wire this up at app startup.
// ---------------------------------------------------------------------------

/**
 * Usage: app.get('/health', healthCheck)
 */
export function healthCheck(req, res) {
  return res.status(200).json({
    status:    "ok",
    timestamp: new Date().toISOString(),
    uptime:    process.uptime(),
    version:   process.env.npm_package_version ?? "unknown",
  });
}

// ---------------------------------------------------------------------------
// WINDOWS ENV VAR SETUP HELPER
// Prints the correct commands for Windows users to register env vars.
// ---------------------------------------------------------------------------

/**
 * Prints Windows setup instructions for required env vars.
 * Call during first-run / setup scripts.
 * @param {string[]} keys - required env var names
 */
export function printWindowsEnvSetup(keys = []) {
  console.info(`\n📋 [OTLC GUARDIAN] WINDOWS ENVIRONMENT VARIABLE SETUP`);
  console.info(`\n   PowerShell (current session only):`);
  keys.forEach((key) => console.info(`   $env:${key} = "your_value_here"`));

  console.info(`\n   PowerShell (permanent — system level):`);
  keys.forEach((key) =>
    console.info(`   [System.Environment]::SetEnvironmentVariable("${key}", "your_value_here", "User")`)
  );

  console.info(`\n   Or use: Settings → System → Advanced → Environment Variables\n`);
}
