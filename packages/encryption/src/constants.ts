/**
 * Encryption constants and configuration
 */

export const ENCRYPTION_ALGORITHMS = {
  AES_GCM: 'AES-GCM',
  AES_CBC: 'AES-CBC',
  RSA_OAEP: 'RSA-OAEP',
} as const;

export const KEY_SIZES = {
  AES_128: 128,
  AES_192: 192,
  AES_256: 256,
  RSA_2048: 2048,
  RSA_4096: 4096,
} as const;

export const PBKDF2_CONFIG = {
  ITERATIONS: 100000,
  HASH: 'SHA-256',
} as const;

export const ARGON2_CONFIG = {
  MEMORY: 64 * 1024, // 64MB
  ITERATIONS: 3,
  PARALLELISM: 4,
  HASH_LENGTH: 32,
  TYPE: 'argon2id',
} as const;

export const STORAGE_KEYS = {
  MASTER_KEY: 'zero:master_key',
  USER_KEYS: 'zero:user_keys',
  PGP_KEYS: 'zero:pgp_keys',
  KEY_METADATA: 'zero:key_metadata',
} as const;

export const ENCRYPTION_ERRORS = {
  INVALID_KEY: 'INVALID_KEY',
  DECRYPTION_FAILED: 'DECRYPTION_FAILED',
  KEY_NOT_FOUND: 'KEY_NOT_FOUND',
  ENCRYPTION_FAILED: 'ENCRYPTION_FAILED',
  INVALID_DATA: 'INVALID_DATA',
} as const;

export const SECURITY_HEADERS = {
  CSP: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' wss: https:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';",
  HSTS: 'max-age=31536000; includeSubDomains; preload',
  X_CONTENT_TYPE: 'nosniff',
  X_FRAME_OPTIONS: 'DENY',
  X_XSS_PROTECTION: '1; mode=block',
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
  PERMISSIONS_POLICY: 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
} as const;

export const RATE_LIMIT_CONFIG = {
  LOGIN: {
    WINDOW_MS: 15 * 60 * 1000, // 15 minutes
    MAX_ATTEMPTS: 5,
  },
  API: {
    WINDOW_MS: 60 * 1000, // 1 minute
    MAX_REQUESTS: 100,
  },
  EMAIL_SEND: {
    WINDOW_MS: 60 * 1000, // 1 minute
    MAX_EMAILS: 10,
  },
} as const;