import { ENCRYPTION_ALGORITHMS, KEY_SIZES, ENCRYPTION_ERRORS } from '../constants';
import type { EncryptedData, EncryptionOptions, EncryptionError } from '../types';
import { encryptedDataSchema } from '../schemas';
import { base64ToArrayBuffer, arrayBufferToBase64, stringToArrayBuffer, arrayBufferToString } from '../utils/encoding';

/**
 * Web Crypto API wrapper for browser-native encryption
 */
export class WebCryptoProvider {
  private crypto: SubtleCrypto;

  constructor() {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Web Crypto API not available');
    }
    this.crypto = window.crypto.subtle;
  }

  /**
   * Generate a new AES encryption key
   */
  async generateKey(keySize: number = KEY_SIZES.AES_256): Promise<CryptoKey> {
    return await this.crypto.generateKey(
      {
        name: ENCRYPTION_ALGORITHMS.AES_GCM,
        length: keySize,
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Generate a new RSA key pair
   */
  async generateKeyPair(keySize: number = KEY_SIZES.RSA_4096): Promise<CryptoKeyPair> {
    return await this.crypto.generateKey(
      {
        name: ENCRYPTION_ALGORITHMS.RSA_OAEP,
        modulusLength: keySize,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Import a key from raw bytes
   */
  async importKey(
    keyData: ArrayBuffer | Uint8Array,
    algorithm: string = ENCRYPTION_ALGORITHMS.AES_GCM
  ): Promise<CryptoKey> {
    return await this.crypto.importKey(
      'raw',
      keyData,
      algorithm,
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Export a key to raw bytes
   */
  async exportKey(key: CryptoKey): Promise<ArrayBuffer> {
    return await this.crypto.exportKey('raw', key);
  }

  /**
   * Encrypt data using AES-GCM
   */
  async encrypt(
    data: string | ArrayBuffer,
    key: CryptoKey,
    options: EncryptionOptions = {}
  ): Promise<EncryptedData> {
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM
      const dataBuffer = typeof data === 'string' ? stringToArrayBuffer(data) : data;

      const encrypted = await this.crypto.encrypt(
        {
          name: ENCRYPTION_ALGORITHMS.AES_GCM,
          iv: iv,
        },
        key,
        dataBuffer
      );

      return {
        ciphertext: arrayBufferToBase64(encrypted),
        iv: arrayBufferToBase64(iv),
        algorithm: ENCRYPTION_ALGORITHMS.AES_GCM,
      };
    } catch (error) {
      throw this.createEncryptionError('ENCRYPTION_FAILED', error);
    }
  }

  /**
   * Decrypt data using AES-GCM
   */
  async decrypt(
    encryptedData: EncryptedData,
    key: CryptoKey
  ): Promise<ArrayBuffer> {
    try {
      // Validate encrypted data
      const validated = encryptedDataSchema.parse(encryptedData);

      const decrypted = await this.crypto.decrypt(
        {
          name: validated.algorithm,
          iv: base64ToArrayBuffer(validated.iv),
        },
        key,
        base64ToArrayBuffer(validated.ciphertext)
      );

      return decrypted;
    } catch (error) {
      throw this.createEncryptionError('DECRYPTION_FAILED', error);
    }
  }

  /**
   * Decrypt data and return as string
   */
  async decryptString(
    encryptedData: EncryptedData,
    key: CryptoKey
  ): Promise<string> {
    const decrypted = await this.decrypt(encryptedData, key);
    return arrayBufferToString(decrypted);
  }

  /**
   * Encrypt data with RSA public key
   */
  async encryptWithPublicKey(
    data: string | ArrayBuffer,
    publicKey: CryptoKey
  ): Promise<EncryptedData> {
    try {
      const dataBuffer = typeof data === 'string' ? stringToArrayBuffer(data) : data;

      const encrypted = await this.crypto.encrypt(
        {
          name: ENCRYPTION_ALGORITHMS.RSA_OAEP,
        },
        publicKey,
        dataBuffer
      );

      return {
        ciphertext: arrayBufferToBase64(encrypted),
        iv: '', // RSA doesn't use IV
        algorithm: ENCRYPTION_ALGORITHMS.RSA_OAEP,
      };
    } catch (error) {
      throw this.createEncryptionError('ENCRYPTION_FAILED', error);
    }
  }

  /**
   * Decrypt data with RSA private key
   */
  async decryptWithPrivateKey(
    encryptedData: EncryptedData,
    privateKey: CryptoKey
  ): Promise<ArrayBuffer> {
    try {
      const decrypted = await this.crypto.decrypt(
        {
          name: ENCRYPTION_ALGORITHMS.RSA_OAEP,
        },
        privateKey,
        base64ToArrayBuffer(encryptedData.ciphertext)
      );

      return decrypted;
    } catch (error) {
      throw this.createEncryptionError('DECRYPTION_FAILED', error);
    }
  }

  /**
   * Generate a random encryption key and encrypt it with multiple public keys
   * Used for encrypting emails for multiple recipients
   */
  async encryptForMultipleRecipients(
    data: string | ArrayBuffer,
    recipientPublicKeys: Map<string, CryptoKey>
  ): Promise<{
    encryptedData: EncryptedData;
    encryptedKeys: Map<string, string>;
  }> {
    // Generate a random session key
    const sessionKey = await this.generateKey();
    
    // Encrypt the data with the session key
    const encryptedData = await this.encrypt(data, sessionKey);

    // Encrypt the session key for each recipient
    const encryptedKeys = new Map<string, string>();
    const sessionKeyData = await this.exportKey(sessionKey);

    for (const [email, publicKey] of recipientPublicKeys) {
      const encryptedKey = await this.encryptWithPublicKey(sessionKeyData, publicKey);
      encryptedKeys.set(email, encryptedKey.ciphertext);
    }

    return { encryptedData, encryptedKeys };
  }

  /**
   * Create a properly typed encryption error
   */
  private createEncryptionError(
    code: keyof typeof ENCRYPTION_ERRORS,
    details?: unknown
  ): EncryptionError {
    const error = new Error(`Encryption error: ${code}`) as EncryptionError;
    error.code = code;
    error.details = details;
    return error;
  }

  /**
   * Check if Web Crypto API is available
   */
  static isAvailable(): boolean {
    return !!(window.crypto && window.crypto.subtle);
  }

  /**
   * Generate a cryptographically secure random string
   */
  static generateRandomString(length: number = 32): string {
    const array = new Uint8Array(length);
    window.crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }
}