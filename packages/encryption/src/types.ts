/**
 * Core encryption types for Zero email
 */

export interface EncryptionKey {
  id: string;
  type: 'master' | 'derived' | 'pgp';
  algorithm: string;
  key: CryptoKey | string;
  createdAt: Date;
  expiresAt?: Date;
}

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt?: string;
  algorithm: string;
  keyId?: string;
}

export interface PGPKeyPair {
  publicKey: string;
  privateKey: string;
  fingerprint: string;
  userId: string;
  createdAt: Date;
}

export interface EncryptionOptions {
  algorithm?: 'AES-GCM' | 'AES-CBC' | 'RSA-OAEP';
  keySize?: 128 | 192 | 256;
  iterations?: number;
  format?: 'base64' | 'hex' | 'binary';
}

export interface KeyDerivationOptions {
  algorithm: 'PBKDF2' | 'Argon2id';
  salt: Uint8Array;
  iterations: number;
  keyLength: number;
  memory?: number; // For Argon2
  parallelism?: number; // For Argon2
}

export interface SecureStorageOptions {
  encryption: boolean;
  compression: boolean;
  ttl?: number; // Time to live in milliseconds
}

export interface EncryptionMetrics {
  encryptionTime: number;
  decryptionTime: number;
  keyDerivationTime: number;
  dataSize: number;
  compressedSize?: number;
}

export interface EncryptionError extends Error {
  code: 'INVALID_KEY' | 'DECRYPTION_FAILED' | 'KEY_NOT_FOUND' | 'ENCRYPTION_FAILED' | 'INVALID_DATA';
  details?: unknown;
}

export type EncryptionProvider = 'webcrypto' | 'openpgp' | 'native';