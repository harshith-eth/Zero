import { z } from 'zod';

/**
 * Zod schemas for encryption data validation
 */

export const encryptionKeySchema = z.object({
  id: z.string().uuid(),
  type: z.enum(['master', 'derived', 'pgp']),
  algorithm: z.string(),
  key: z.union([z.any(), z.string()]), // CryptoKey or string
  createdAt: z.date(),
  expiresAt: z.date().optional(),
});

export const encryptedDataSchema = z.object({
  ciphertext: z.string(),
  iv: z.string(),
  salt: z.string().optional(),
  algorithm: z.string(),
  keyId: z.string().uuid().optional(),
});

export const pgpKeyPairSchema = z.object({
  publicKey: z.string(),
  privateKey: z.string(),
  fingerprint: z.string(),
  userId: z.string().email(),
  createdAt: z.date(),
});

export const encryptionOptionsSchema = z.object({
  algorithm: z.enum(['AES-GCM', 'AES-CBC', 'RSA-OAEP']).optional(),
  keySize: z.enum([128, 192, 256]).optional(),
  iterations: z.number().positive().optional(),
  format: z.enum(['base64', 'hex', 'binary']).optional(),
});

export const keyDerivationOptionsSchema = z.object({
  algorithm: z.enum(['PBKDF2', 'Argon2id']),
  salt: z.instanceof(Uint8Array),
  iterations: z.number().positive(),
  keyLength: z.number().positive(),
  memory: z.number().positive().optional(),
  parallelism: z.number().positive().optional(),
});

export const secureStorageOptionsSchema = z.object({
  encryption: z.boolean(),
  compression: z.boolean(),
  ttl: z.number().positive().optional(),
});

// Email encryption schemas
export const encryptedEmailSchema = z.object({
  id: z.string(),
  encryptedSubject: encryptedDataSchema,
  encryptedBody: encryptedDataSchema,
  encryptedAttachments: z.array(z.object({
    filename: z.string(),
    encryptedData: encryptedDataSchema,
    mimeType: z.string(),
  })).optional(),
  recipientKeys: z.array(z.object({
    email: z.string().email(),
    encryptedSessionKey: z.string(),
  })),
  metadata: z.object({
    timestamp: z.date(),
    version: z.string(),
    algorithm: z.string(),
  }),
});

// Security configuration schemas
export const securityConfigSchema = z.object({
  encryption: z.object({
    enabled: z.boolean(),
    defaultAlgorithm: z.enum(['AES-GCM', 'AES-CBC', 'RSA-OAEP']),
    keyRotationDays: z.number().positive(),
  }),
  authentication: z.object({
    mfaEnabled: z.boolean(),
    sessionTimeout: z.number().positive(),
    maxLoginAttempts: z.number().positive(),
  }),
  privacy: z.object({
    dataRetentionDays: z.number().positive(),
    anonymousAnalytics: z.boolean(),
    metadataCollection: z.enum(['none', 'minimal', 'full']),
  }),
});