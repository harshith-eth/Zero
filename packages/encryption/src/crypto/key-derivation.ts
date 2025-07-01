import argon2 from 'argon2-browser';
import { PBKDF2_CONFIG, ARGON2_CONFIG } from '../constants';
import type { KeyDerivationOptions } from '../types';
import { arrayBufferToHex, hexToArrayBuffer, getRandomBytes } from '../utils/encoding';

/**
 * Key derivation functions for secure password-based encryption
 */
export class KeyDerivation {
  /**
   * Derive a key from password using PBKDF2
   */
  static async deriveKeyPBKDF2(
    password: string,
    salt: Uint8Array,
    iterations: number = PBKDF2_CONFIG.ITERATIONS,
    keyLength: number = 32
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      passwordBuffer,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    // Derive AES key from password
    return await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: PBKDF2_CONFIG.HASH,
      },
      keyMaterial,
      { name: 'AES-GCM', length: keyLength * 8 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Derive a key from password using Argon2id
   */
  static async deriveKeyArgon2(
    password: string,
    salt: Uint8Array,
    options: Partial<KeyDerivationOptions> = {}
  ): Promise<ArrayBuffer> {
    const config = {
      pass: password,
      salt: salt,
      time: options.iterations || ARGON2_CONFIG.ITERATIONS,
      mem: options.memory || ARGON2_CONFIG.MEMORY,
      hashLen: options.keyLength || ARGON2_CONFIG.HASH_LENGTH,
      parallelism: options.parallelism || ARGON2_CONFIG.PARALLELISM,
      type: argon2.ArgonType.Argon2id,
    };

    const result = await argon2.hash(config);
    return result.hash;
  }

  /**
   * Generate a random salt
   */
  static generateSalt(length: number = 16): Uint8Array {
    return getRandomBytes(length);
  }

  /**
   * Derive encryption key with automatic algorithm selection
   */
  static async deriveKey(
    password: string,
    options: KeyDerivationOptions
  ): Promise<CryptoKey | ArrayBuffer> {
    if (options.algorithm === 'PBKDF2') {
      return await this.deriveKeyPBKDF2(
        password,
        options.salt,
        options.iterations,
        options.keyLength
      );
    } else if (options.algorithm === 'Argon2id') {
      return await this.deriveKeyArgon2(password, options.salt, options);
    } else {
      throw new Error(`Unsupported key derivation algorithm: ${options.algorithm}`);
    }
  }

  /**
   * Create a deterministic key ID from password and salt
   */
  static async createKeyId(password: string, salt: Uint8Array): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + arrayBufferToHex(salt.buffer));
    
    const hash = await crypto.subtle.digest('SHA-256', data);
    return arrayBufferToHex(hash).substring(0, 16); // Use first 16 chars as ID
  }

  /**
   * Stretch a key to a specific length using HKDF
   */
  static async stretchKey(
    key: ArrayBuffer,
    salt: Uint8Array,
    info: string,
    length: number
  ): Promise<ArrayBuffer> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      key,
      'HKDF',
      false,
      ['deriveBits']
    );

    const encoder = new TextEncoder();
    const infoBuffer = encoder.encode(info);

    return await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: infoBuffer,
      },
      keyMaterial,
      length * 8
    );
  }

  /**
   * Verify a password against a stored hash
   */
  static async verifyPassword(
    password: string,
    storedHash: string,
    salt: Uint8Array,
    options: KeyDerivationOptions
  ): Promise<boolean> {
    const derivedKey = await this.deriveKey(password, options);
    
    let derivedHash: string;
    if (derivedKey instanceof ArrayBuffer) {
      derivedHash = arrayBufferToHex(derivedKey);
    } else {
      const exported = await crypto.subtle.exportKey('raw', derivedKey);
      derivedHash = arrayBufferToHex(exported);
    }

    return derivedHash === storedHash;
  }
}