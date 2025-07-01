import { WebCryptoProvider } from './web-crypto';
import { KeyDerivation } from './key-derivation';
import { OpenPGPProvider } from './openpgp';
import { SecureStorage } from '../storage/secure-storage';
import { STORAGE_KEYS, ENCRYPTION_ERRORS } from '../constants';
import type { EncryptionKey, PGPKeyPair, EncryptionError } from '../types';
import { encryptionKeySchema } from '../schemas';
import { getRandomBase64 } from '../utils/encoding';

/**
 * Comprehensive key management system
 */
export class KeyManager {
  private storage: SecureStorage;
  private masterKey?: CryptoKey;
  private keyCache: Map<string, EncryptionKey>;

  constructor(storage: SecureStorage) {
    this.storage = storage;
    this.keyCache = new Map();
  }

  /**
   * Initialize the key manager with a master password
   */
  async initialize(masterPassword: string): Promise<void> {
    // Check if we have a stored salt, if not create one
    let salt = await this.storage.get<string>('master_salt');
    if (!salt) {
      salt = getRandomBase64(16);
      await this.storage.set('master_salt', salt);
    }

    // Derive master key from password
    const saltBuffer = new Uint8Array(atob(salt).split('').map(c => c.charCodeAt(0)));
    this.masterKey = await KeyDerivation.deriveKeyPBKDF2(
      masterPassword,
      saltBuffer,
      100000,
      32
    );

    // Load existing keys into cache
    await this.loadKeysFromStorage();
  }

  /**
   * Change the master password
   */
  async changeMasterPassword(
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    // Verify current password
    await this.initialize(currentPassword);

    // Get all keys
    const allKeys = await this.getAllKeys();

    // Generate new salt and derive new master key
    const newSalt = getRandomBase64(16);
    const newSaltBuffer = new Uint8Array(atob(newSalt).split('').map(c => c.charCodeAt(0)));
    const newMasterKey = await KeyDerivation.deriveKeyPBKDF2(
      newPassword,
      newSaltBuffer,
      100000,
      32
    );

    // Re-encrypt all keys with new master key
    const crypto = new WebCryptoProvider();
    for (const key of allKeys) {
      if (key.key instanceof CryptoKey) {
        // Export the key
        const exportedKey = await crypto.exportKey(key.key);
        
        // Encrypt with new master key
        const encrypted = await crypto.encrypt(exportedKey, newMasterKey);
        
        // Store encrypted key
        await this.storage.set(`key:${key.id}`, {
          ...key,
          key: encrypted,
        });
      }
    }

    // Update salt and master key
    await this.storage.set('master_salt', newSalt);
    this.masterKey = newMasterKey;
  }

  /**
   * Generate and store a new encryption key
   */
  async generateKey(
    type: 'master' | 'derived' | 'pgp',
    metadata?: Record<string, any>
  ): Promise<EncryptionKey> {
    if (!this.masterKey) {
      throw this.createError('INVALID_KEY', 'Key manager not initialized');
    }

    const crypto = new WebCryptoProvider();
    const keyId = WebCryptoProvider.generateRandomString(16);
    
    let key: CryptoKey | string;
    let algorithm: string;

    if (type === 'pgp') {
      // Generate PGP key pair
      const email = metadata?.email || 'user@example.com';
      const name = metadata?.name || 'Zero User';
      const pgpKeys = await OpenPGPProvider.generateKeyPair(name, email);
      
      // Store PGP keys encrypted
      const encryptedPrivate = await crypto.encrypt(
        pgpKeys.privateKey,
        this.masterKey
      );
      const encryptedPublic = await crypto.encrypt(
        pgpKeys.publicKey,
        this.masterKey
      );

      await this.storage.set(`pgp:${keyId}`, {
        private: encryptedPrivate,
        public: encryptedPublic,
        fingerprint: pgpKeys.fingerprint,
        userId: pgpKeys.userId,
      });

      key = pgpKeys.publicKey; // Store public key reference
      algorithm = 'PGP';
    } else {
      // Generate AES key
      key = await crypto.generateKey();
      algorithm = 'AES-GCM';

      // Export and encrypt the key for storage
      const exportedKey = await crypto.exportKey(key);
      const encryptedKey = await crypto.encrypt(exportedKey, this.masterKey);
      
      await this.storage.set(`key:${keyId}`, encryptedKey);
    }

    const encryptionKey: EncryptionKey = {
      id: keyId,
      type,
      algorithm,
      key,
      createdAt: new Date(),
      ...metadata,
    };

    // Validate and cache
    const validated = encryptionKeySchema.parse(encryptionKey);
    this.keyCache.set(keyId, validated);

    return validated;
  }

  /**
   * Get a key by ID
   */
  async getKey(keyId: string): Promise<EncryptionKey | null> {
    // Check cache first
    if (this.keyCache.has(keyId)) {
      return this.keyCache.get(keyId)!;
    }

    if (!this.masterKey) {
      throw this.createError('INVALID_KEY', 'Key manager not initialized');
    }

    // Load from storage
    const encryptedKey = await this.storage.get<any>(`key:${keyId}`);
    if (!encryptedKey) {
      return null;
    }

    const crypto = new WebCryptoProvider();
    
    // Decrypt the key
    const decryptedKeyData = await crypto.decrypt(encryptedKey, this.masterKey);
    const key = await crypto.importKey(decryptedKeyData);

    const encryptionKey: EncryptionKey = {
      id: keyId,
      type: encryptedKey.type || 'derived',
      algorithm: encryptedKey.algorithm || 'AES-GCM',
      key,
      createdAt: new Date(encryptedKey.createdAt),
      expiresAt: encryptedKey.expiresAt ? new Date(encryptedKey.expiresAt) : undefined,
    };

    // Cache and return
    this.keyCache.set(keyId, encryptionKey);
    return encryptionKey;
  }

  /**
   * Get PGP keys
   */
  async getPGPKeys(keyId: string): Promise<PGPKeyPair | null> {
    if (!this.masterKey) {
      throw this.createError('INVALID_KEY', 'Key manager not initialized');
    }

    const encryptedKeys = await this.storage.get<any>(`pgp:${keyId}`);
    if (!encryptedKeys) {
      return null;
    }

    const crypto = new WebCryptoProvider();
    
    // Decrypt both keys
    const privateKey = await crypto.decryptString(
      encryptedKeys.private,
      this.masterKey
    );
    const publicKey = await crypto.decryptString(
      encryptedKeys.public,
      this.masterKey
    );

    return {
      privateKey,
      publicKey,
      fingerprint: encryptedKeys.fingerprint,
      userId: encryptedKeys.userId,
      createdAt: new Date(),
    };
  }

  /**
   * Delete a key
   */
  async deleteKey(keyId: string): Promise<boolean> {
    this.keyCache.delete(keyId);
    
    const deleted1 = await this.storage.delete(`key:${keyId}`);
    const deleted2 = await this.storage.delete(`pgp:${keyId}`);
    
    return deleted1 || deleted2;
  }

  /**
   * Get all keys
   */
  async getAllKeys(): Promise<EncryptionKey[]> {
    const keys: EncryptionKey[] = [];
    
    // Get all key IDs from storage
    const allItems = await this.storage.getAllKeys();
    const keyIds = allItems
      .filter(k => k.startsWith('key:'))
      .map(k => k.substring(4));

    for (const keyId of keyIds) {
      const key = await this.getKey(keyId);
      if (key) {
        keys.push(key);
      }
    }

    return keys;
  }

  /**
   * Rotate old keys
   */
  async rotateKeys(daysOld: number = 90): Promise<number> {
    const keys = await this.getAllKeys();
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    let rotatedCount = 0;

    for (const key of keys) {
      if (key.createdAt < cutoffDate && !key.expiresAt) {
        // Mark key as expired
        key.expiresAt = new Date();
        
        // Generate replacement key
        await this.generateKey(key.type, {
          replacesKeyId: key.id,
        });

        rotatedCount++;
      }
    }

    return rotatedCount;
  }

  /**
   * Export keys for backup
   */
  async exportKeys(password: string): Promise<string> {
    if (!this.masterKey) {
      throw this.createError('INVALID_KEY', 'Key manager not initialized');
    }

    const keys = await this.getAllKeys();
    const pgpKeys: Record<string, any> = {};

    // Get all PGP keys
    for (const key of keys) {
      if (key.type === 'pgp') {
        const pgp = await this.getPGPKeys(key.id);
        if (pgp) {
          pgpKeys[key.id] = pgp;
        }
      }
    }

    const backup = {
      version: '1.0',
      created: new Date().toISOString(),
      keys: keys.map(k => ({
        ...k,
        key: k.key instanceof CryptoKey ? 'CryptoKey' : k.key,
      })),
      pgpKeys,
    };

    // Encrypt backup with password
    const salt = KeyDerivation.generateSalt();
    const backupKey = await KeyDerivation.deriveKeyPBKDF2(password, salt, 100000, 32);
    
    const crypto = new WebCryptoProvider();
    const encrypted = await crypto.encrypt(
      JSON.stringify(backup),
      backupKey
    );

    return JSON.stringify({
      encrypted,
      salt: btoa(String.fromCharCode.apply(null, Array.from(salt))),
    });
  }

  /**
   * Import keys from backup
   */
  async importKeys(backupData: string, password: string): Promise<number> {
    const { encrypted, salt } = JSON.parse(backupData);
    const saltBuffer = new Uint8Array(atob(salt).split('').map(c => c.charCodeAt(0)));
    
    const backupKey = await KeyDerivation.deriveKeyPBKDF2(
      password,
      saltBuffer,
      100000,
      32
    );

    const crypto = new WebCryptoProvider();
    const decrypted = await crypto.decryptString(encrypted, backupKey);
    const backup = JSON.parse(decrypted);

    // Import keys
    let importedCount = 0;
    for (const keyData of backup.keys) {
      // Skip if key already exists
      if (await this.getKey(keyData.id)) {
        continue;
      }

      await this.storage.set(`key:${keyData.id}`, keyData);
      importedCount++;
    }

    // Import PGP keys
    for (const [keyId, pgpData] of Object.entries(backup.pgpKeys)) {
      await this.storage.set(`pgp:${keyId}`, pgpData);
    }

    return importedCount;
  }

  /**
   * Load keys from storage into cache
   */
  private async loadKeysFromStorage(): Promise<void> {
    const keys = await this.getAllKeys();
    for (const key of keys) {
      this.keyCache.set(key.id, key);
    }
  }

  /**
   * Create a typed error
   */
  private createError(code: keyof typeof ENCRYPTION_ERRORS, message: string): EncryptionError {
    const error = new Error(message) as EncryptionError;
    error.code = code;
    return error;
  }

  /**
   * Clear all keys (use with caution!)
   */
  async clearAllKeys(): Promise<void> {
    const allKeys = await this.storage.getAllKeys();
    for (const key of allKeys) {
      if (key.startsWith('key:') || key.startsWith('pgp:')) {
        await this.storage.delete(key);
      }
    }
    this.keyCache.clear();
  }
}