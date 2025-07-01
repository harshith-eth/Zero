import Dexie, { type Table } from 'dexie';
import type { SecureStorageOptions } from '../types';

interface StorageItem {
  key: string;
  value: any;
  encrypted: boolean;
  compressed: boolean;
  createdAt: Date;
  expiresAt?: Date;
}

/**
 * Secure storage implementation using IndexedDB
 */
export class SecureStorage extends Dexie {
  items!: Table<StorageItem, string>;

  constructor(dbName: string = 'ZeroSecureStorage') {
    super(dbName);
    
    this.version(1).stores({
      items: 'key, createdAt, expiresAt',
    });
  }

  /**
   * Set a value in secure storage
   */
  async set<T>(
    key: string,
    value: T,
    options: Partial<SecureStorageOptions> = {}
  ): Promise<void> {
    const item: StorageItem = {
      key,
      value,
      encrypted: options.encryption || false,
      compressed: options.compression || false,
      createdAt: new Date(),
      expiresAt: options.ttl ? new Date(Date.now() + options.ttl) : undefined,
    };

    await this.items.put(item);
  }

  /**
   * Get a value from secure storage
   */
  async get<T>(key: string): Promise<T | null> {
    const item = await this.items.get(key);
    
    if (!item) {
      return null;
    }

    // Check if expired
    if (item.expiresAt && item.expiresAt < new Date()) {
      await this.delete(key);
      return null;
    }

    return item.value as T;
  }

  /**
   * Delete a value from secure storage
   */
  async delete(key: string): Promise<boolean> {
    const count = await this.items.where('key').equals(key).delete();
    return count > 0;
  }

  /**
   * Check if a key exists
   */
  async has(key: string): Promise<boolean> {
    const count = await this.items.where('key').equals(key).count();
    return count > 0;
  }

  /**
   * Clear all expired items
   */
  async clearExpired(): Promise<number> {
    const now = new Date();
    return await this.items
      .where('expiresAt')
      .below(now)
      .delete();
  }

  /**
   * Get all keys
   */
  async getAllKeys(): Promise<string[]> {
    const items = await this.items.toArray();
    return items.map(item => item.key);
  }

  /**
   * Clear all items
   */
  async clear(): Promise<void> {
    await this.items.clear();
  }

  /**
   * Get storage size
   */
  async getSize(): Promise<{
    itemCount: number;
    estimatedSize: number;
  }> {
    const itemCount = await this.items.count();
    
    // Estimate size (rough calculation)
    const items = await this.items.toArray();
    const estimatedSize = items.reduce((total, item) => {
      const itemSize = JSON.stringify(item).length * 2; // UTF-16 encoding
      return total + itemSize;
    }, 0);

    return { itemCount, estimatedSize };
  }

  /**
   * Export all data
   */
  async exportData(): Promise<StorageItem[]> {
    return await this.items.toArray();
  }

  /**
   * Import data
   */
  async importData(data: StorageItem[]): Promise<void> {
    await this.items.bulkPut(data);
  }

  /**
   * Search for items by prefix
   */
  async getByPrefix(prefix: string): Promise<StorageItem[]> {
    return await this.items
      .where('key')
      .startsWith(prefix)
      .toArray();
  }

  /**
   * Update TTL for a key
   */
  async updateTTL(key: string, ttl: number): Promise<boolean> {
    const item = await this.items.get(key);
    if (!item) {
      return false;
    }

    item.expiresAt = new Date(Date.now() + ttl);
    await this.items.put(item);
    return true;
  }
}