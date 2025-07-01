import { SecureStorage } from './secure-storage';
import type { EncryptionKey, PGPKeyPair } from '../types';

/**
 * Specialized key store for managing encryption keys
 */
export class KeyStore {
  private storage: SecureStorage;
  private keyPrefix = 'key:';
  private pgpPrefix = 'pgp:';

  constructor(storage: SecureStorage) {
    this.storage = storage;
  }

  /**
   * Store an encryption key
   */
  async storeKey(key: EncryptionKey): Promise<void> {
    await this.storage.set(`${this.keyPrefix}${key.id}`, key, {
      encryption: true,
      compression: false,
    });
  }

  /**
   * Retrieve an encryption key
   */
  async getKey(keyId: string): Promise<EncryptionKey | null> {
    return await this.storage.get<EncryptionKey>(`${this.keyPrefix}${keyId}`);
  }

  /**
   * Store PGP keys
   */
  async storePGPKeys(keyId: string, keys: PGPKeyPair): Promise<void> {
    await this.storage.set(`${this.pgpPrefix}${keyId}`, keys, {
      encryption: true,
      compression: true,
    });
  }

  /**
   * Retrieve PGP keys
   */
  async getPGPKeys(keyId: string): Promise<PGPKeyPair | null> {
    return await this.storage.get<PGPKeyPair>(`${this.pgpPrefix}${keyId}`);
  }

  /**
   * List all key IDs
   */
  async listKeyIds(): Promise<string[]> {
    const allKeys = await this.storage.getAllKeys();
    return allKeys
      .filter(k => k.startsWith(this.keyPrefix))
      .map(k => k.substring(this.keyPrefix.length));
  }

  /**
   * List all PGP key IDs
   */
  async listPGPKeyIds(): Promise<string[]> {
    const allKeys = await this.storage.getAllKeys();
    return allKeys
      .filter(k => k.startsWith(this.pgpPrefix))
      .map(k => k.substring(this.pgpPrefix.length));
  }

  /**
   * Delete a key
   */
  async deleteKey(keyId: string): Promise<boolean> {
    const deleted1 = await this.storage.delete(`${this.keyPrefix}${keyId}`);
    const deleted2 = await this.storage.delete(`${this.pgpPrefix}${keyId}`);
    return deleted1 || deleted2;
  }

  /**
   * Check if a key exists
   */
  async hasKey(keyId: string): Promise<boolean> {
    const hasRegular = await this.storage.has(`${this.keyPrefix}${keyId}`);
    const hasPGP = await this.storage.has(`${this.pgpPrefix}${keyId}`);
    return hasRegular || hasPGP;
  }

  /**
   * Get keys by type
   */
  async getKeysByType(type: 'master' | 'derived' | 'pgp'): Promise<EncryptionKey[]> {
    const allKeyIds = await this.listKeyIds();
    const keys: EncryptionKey[] = [];

    for (const keyId of allKeyIds) {
      const key = await this.getKey(keyId);
      if (key && key.type === type) {
        keys.push(key);
      }
    }

    return keys;
  }

  /**
   * Find keys by metadata
   */
  async findKeysByMetadata(
    predicate: (key: EncryptionKey) => boolean
  ): Promise<EncryptionKey[]> {
    const allKeyIds = await this.listKeyIds();
    const matchingKeys: EncryptionKey[] = [];

    for (const keyId of allKeyIds) {
      const key = await this.getKey(keyId);
      if (key && predicate(key)) {
        matchingKeys.push(key);
      }
    }

    return matchingKeys;
  }

  /**
   * Clear all keys
   */
  async clearAll(): Promise<void> {
    const allKeys = await this.storage.getAllKeys();
    const keysToDelete = allKeys.filter(
      k => k.startsWith(this.keyPrefix) || k.startsWith(this.pgpPrefix)
    );

    for (const key of keysToDelete) {
      await this.storage.delete(key);
    }
  }

  /**
   * Get storage statistics
   */
  async getStats(): Promise<{
    totalKeys: number;
    pgpKeys: number;
    regularKeys: number;
    storageSize: number;
  }> {
    const regularKeys = await this.listKeyIds();
    const pgpKeys = await this.listPGPKeyIds();
    const { estimatedSize } = await this.storage.getSize();

    return {
      totalKeys: regularKeys.length + pgpKeys.length,
      pgpKeys: pgpKeys.length,
      regularKeys: regularKeys.length,
      storageSize: estimatedSize,
    };
  }
}