/**
 * Validation utilities for encryption operations
 */

/**
 * Check if a string is valid base64
 */
export function isValidBase64(str: string): boolean {
  try {
    return btoa(atob(str)) === str;
  } catch {
    return false;
  }
}

/**
 * Check if a string is valid hex
 */
export function isValidHex(str: string): boolean {
  return /^[0-9a-fA-F]+$/.test(str) && str.length % 2 === 0;
}

/**
 * Validate key size
 */
export function isValidKeySize(size: number, validSizes: readonly number[]): boolean {
  return validSizes.includes(size);
}

/**
 * Check if a value is a CryptoKey
 */
export function isCryptoKey(value: unknown): value is CryptoKey {
  return value !== null && 
         typeof value === 'object' && 
         'type' in value && 
         'algorithm' in value &&
         'extractable' in value &&
         'usages' in value;
}

/**
 * Check if browser supports required crypto operations
 */
export function checkCryptoSupport(): {
  supported: boolean;
  missingFeatures: string[];
} {
  const missingFeatures: string[] = [];

  if (!window.crypto) {
    missingFeatures.push('window.crypto');
  }

  if (!window.crypto?.subtle) {
    missingFeatures.push('crypto.subtle');
  }

  if (typeof TextEncoder === 'undefined') {
    missingFeatures.push('TextEncoder');
  }

  if (typeof TextDecoder === 'undefined') {
    missingFeatures.push('TextDecoder');
  }

  return {
    supported: missingFeatures.length === 0,
    missingFeatures,
  };
}

/**
 * Validate email address
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Sanitize filename for secure storage
 */
export function sanitizeFilename(filename: string): string {
  // Remove any path traversal attempts
  return filename
    .replace(/[\/\\]/g, '_')
    .replace(/\.\./g, '_')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .substring(0, 255); // Limit length
}