import { Ratelimit } from '@upstash/ratelimit';
import { Context } from 'hono';
import { redis } from '../services';
import { z } from 'zod';
import { getConnInfo } from 'hono/cloudflare-workers';
import type { HonoContext } from '../../ctx';

// Security constants
export const SECURITY_HEADERS = {
  // Content Security Policy
  CSP_DEVELOPMENT: [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' ws: wss: https:",
    "media-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join('; '),
  
  CSP_PRODUCTION: [
    "default-src 'self'",
    "script-src 'self' 'nonce-{nonce}'",
    "style-src 'self' 'nonce-{nonce}' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' wss: https:",
    "media-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests"
  ].join('; '),
  
  // Security headers
  HSTS: 'max-age=31536000; includeSubDomains; preload',
  FRAME_OPTIONS: 'DENY',
  CONTENT_TYPE_OPTIONS: 'nosniff',
  REFERRER_POLICY: 'strict-origin-when-cross-origin',
  PERMISSIONS_POLICY: [
    'camera=()',
    'microphone=()',
    'geolocation=()',
    'payment=()',
    'usb=()',
    'magnetometer=()',
    'gyroscope=()',
    'accelerometer=()',
  ].join(', ')
};

// Rate limiting configurations
export const RATE_LIMITS = {
  // Authentication endpoints
  AUTH: {
    LOGIN: Ratelimit.slidingWindow(5, '15m'), // 5 attempts per 15 minutes
    SIGNUP: Ratelimit.slidingWindow(3, '1h'), // 3 signups per hour
    PASSWORD_RESET: Ratelimit.slidingWindow(3, '1h'), // 3 password resets per hour
    EMAIL_VERIFICATION: Ratelimit.slidingWindow(5, '1h'), // 5 verification emails per hour
  },
  
  // API endpoints
  API: {
    GENERAL: Ratelimit.slidingWindow(100, '1m'), // 100 requests per minute
    MAIL_SEND: Ratelimit.slidingWindow(50, '1h'), // 50 emails per hour
    SEARCH: Ratelimit.slidingWindow(30, '1m'), // 30 searches per minute
    UPLOAD: Ratelimit.slidingWindow(10, '1m'), // 10 uploads per minute
  },
  
  // Security sensitive endpoints
  SECURITY: {
    SETTINGS_CHANGE: Ratelimit.slidingWindow(10, '1h'), // 10 settings changes per hour
    CONNECTION_CHANGE: Ratelimit.slidingWindow(5, '1h'), // 5 connection changes per hour
    ACCOUNT_DELETE: Ratelimit.slidingWindow(1, '24h'), // 1 account deletion per day
  }
};

// Input validation schemas
export const INPUT_SCHEMAS = {
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
  name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9\s\-_.]+$/, 'Invalid characters in name'),
  subject: z.string().max(998), // RFC 5322 limit
  messageBody: z.string().max(1000000), // 1MB limit for message body
  searchQuery: z.string().min(1).max(500),
  fileName: z.string().min(1).max(255).regex(/^[^<>:"/\\|?*]+$/, 'Invalid file name'),
  phoneNumber: z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format'),
  url: z.string().url().max(2048),
  uuid: z.string().uuid(),
  connectionId: z.string().uuid(),
  threadId: z.string().max(100),
  labelId: z.string().max(100),
  noteContent: z.string().max(50000), // 50KB limit for notes
};

// Security utility functions
export class SecurityUtils {
  // Generate cryptographically secure nonce
  static generateNonce(): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const binaryString = Array.prototype.map.call(bytes, function(byte: number) { 
      return String.fromCharCode(byte); 
    }).join('');
    return btoa(binaryString);
  }
  
  // Sanitize HTML content
  static sanitizeHTML(html: string): string {
    // Remove potentially dangerous tags and attributes
    return html
      .replace(/<script[^>]*>.*?<\/script>/gi, '')
      .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
      .replace(/<object[^>]*>.*?<\/object>/gi, '')
      .replace(/<embed[^>]*>/gi, '')
      .replace(/<form[^>]*>.*?<\/form>/gi, '')
      .replace(/on\w+="[^"]*"/gi, '')
      .replace(/on\w+='[^']*'/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/vbscript:/gi, '')
      .replace(/data:text\/html/gi, '');
  }
  
  // Validate email address against common security threats
  static validateEmailSecurity(email: string): boolean {
    // Check for common email injection patterns
    const dangerousPatterns = [
      /[\r\n]/,
      /\bcc:/i,
      /\bbcc:/i,
      /\bsubject:/i,
      /\bcontent-type:/i,
      /\bmime-version:/i,
      /%0a/i,
      /%0d/i,
    ];
    
    return !dangerousPatterns.some(function(pattern) { return pattern.test(email); });
  }
  
  // Generate secure session token
  static generateSecureToken(length: number = 32): string {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      const hex = bytes[i].toString(16);
      result += hex.length === 1 ? '0' + hex : hex;
    }
    return result;
  }
  
  // Simple hash function for sensitive data (non-async version)
  static hashSensitiveData(data: string): string {
    // Simple hash implementation for compatibility
    let hash = 0;
    if (data.length === 0) return hash.toString();
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }
  
  // Validate file upload
  static validateFileUpload(file: { name: string; size: number; type: string }): {
    isValid: boolean;
    error?: string;
  } {
    const MAX_FILE_SIZE = 25 * 1024 * 1024; // 25MB
    const ALLOWED_TYPES = [
      'image/jpeg',
      'image/png',
      'image/gif',
      'image/webp',
      'application/pdf',
      'text/plain',
      'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    ];
    
    if (file.size > MAX_FILE_SIZE) {
      return { isValid: false, error: 'File size exceeds 25MB limit' };
    }
    
    if (ALLOWED_TYPES.indexOf(file.type) === -1) {
      return { isValid: false, error: 'File type not allowed' };
    }
    
    // Check file extension matches MIME type
    const fileExtension = file.name.split('.').pop();
    const fileExtLower = fileExtension ? fileExtension.toLowerCase() : '';
    
    const mimeToExtension: Record<string, string[]> = {
      'image/jpeg': ['jpg', 'jpeg'],
      'image/png': ['png'],
      'image/gif': ['gif'],
      'image/webp': ['webp'],
      'application/pdf': ['pdf'],
      'text/plain': ['txt'],
      'application/msword': ['doc'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['docx'],
      'application/vnd.ms-excel': ['xls'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['xlsx'],
    };
    
    const allowedExtensions = mimeToExtension[file.type];
    if (!allowedExtensions || !fileExtLower || allowedExtensions.indexOf(fileExtLower) === -1) {
      return { isValid: false, error: 'File extension does not match MIME type' };
    }
    
    return { isValid: true };
  }
  
  // Detect suspicious activity patterns
  static detectSuspiciousActivity(userAgent: string, ip: string): {
    isSuspicious: boolean;
    reasons: string[];
  } {
    const reasons: string[] = [];
    let isSuspicious = false;
    
    // Check for automation tools
    const automationPatterns = [
      /bot/i,
      /crawler/i,
      /spider/i,
      /scraper/i,
      /curl/i,
      /wget/i,
      /python/i,
      /php/i,
    ];
    
    if (automationPatterns.some(function(pattern) { return pattern.test(userAgent); })) {
      reasons.push('Automated tool detected');
      isSuspicious = true;
    }
    
    // Check for suspicious IP patterns (basic checks)
    if (ip === '127.0.0.1' || ip === '::1') {
      // Localhost - might be suspicious in production
      reasons.push('Localhost access');
    }
    
    // Check for empty or suspicious user agent
    if (!userAgent || userAgent.length < 10) {
      reasons.push('Suspicious user agent');
      isSuspicious = true;
    }
    
    return { isSuspicious: isSuspicious, reasons: reasons };
  }
}

// Security middleware factory
export function createSecurityMiddleware(options: {
  enableCSP?: boolean;
  enableHSTS?: boolean;
  enableFrameOptions?: boolean;
  enableContentTypeOptions?: boolean;
  enableReferrerPolicy?: boolean;
  enablePermissionsPolicy?: boolean;
  isDevelopment?: boolean;
}) {
  return function(c: Context<HonoContext>, next: () => Promise<void>) {
    const nonce = SecurityUtils.generateNonce();
    c.set('securityNonce', nonce);
    
    // Set security headers
    if (options.enableCSP) {
      const csp = options.isDevelopment 
        ? SECURITY_HEADERS.CSP_DEVELOPMENT
        : SECURITY_HEADERS.CSP_PRODUCTION.replace('{nonce}', nonce);
      c.header('Content-Security-Policy', csp);
      c.header('Content-Security-Policy-Report-Only', csp);
    }
    
    if (options.enableHSTS && !options.isDevelopment) {
      c.header('Strict-Transport-Security', SECURITY_HEADERS.HSTS);
    }
    
    if (options.enableFrameOptions) {
      c.header('X-Frame-Options', SECURITY_HEADERS.FRAME_OPTIONS);
    }
    
    if (options.enableContentTypeOptions) {
      c.header('X-Content-Type-Options', SECURITY_HEADERS.CONTENT_TYPE_OPTIONS);
    }
    
    if (options.enableReferrerPolicy) {
      c.header('Referrer-Policy', SECURITY_HEADERS.REFERRER_POLICY);
    }
    
    if (options.enablePermissionsPolicy) {
      c.header('Permissions-Policy', SECURITY_HEADERS.PERMISSIONS_POLICY);
    }
    
    // Remove server identifying headers
    c.header('Server', '');
    c.header('X-Powered-By', '');
    
    return next();
  };
}

// Rate limiting middleware factory
export function createRateLimitMiddleware(
  limiter: Ratelimit,
  keyGenerator: (c: Context<HonoContext>) => string
) {
  return function(c: Context<HonoContext>, next: () => Promise<void>) {
    const key = keyGenerator(c);
    const connInfo = getConnInfo(c);
    const ip = connInfo.remote.address || 'unknown';
    
    return limiter.limit(key + ':' + ip).then(function(result) {
      const success = result.success;
      const limit = result.limit;
      const reset = result.reset;
      const remaining = result.remaining;
      
      // Set rate limit headers
      c.header('X-RateLimit-Limit', limit.toString());
      c.header('X-RateLimit-Remaining', remaining.toString());
      c.header('X-RateLimit-Reset', reset.toString());
      
      if (!success) {
        const userAgent = c.req.header('User-Agent') || '';
        const suspiciousActivity = SecurityUtils.detectSuspiciousActivity(userAgent, ip);
        
        // Log suspicious activity
        console.warn('Rate limit exceeded for IP ' + ip, {
          userAgent: userAgent,
          suspicious: suspiciousActivity.isSuspicious,
          reasons: suspiciousActivity.reasons,
          endpoint: c.req.url,
        });
        
        return c.json(
          {
            error: 'Too Many Requests',
            message: 'Rate limit exceeded. Please try again later.',
            retryAfter: Math.ceil((reset - Date.now()) / 1000),
          },
          429
        );
      }
      
      return next();
    });
  };
}

// Input validation middleware factory
export function createInputValidationMiddleware<T>(
  schema: z.ZodSchema<T>,
  source: 'body' | 'query' | 'params' = 'body'
) {
  return function(c: Context<HonoContext>, next: () => Promise<void>) {
    return Promise.resolve().then(function() {
      let dataPromise: Promise<any>;
      
      switch (source) {
        case 'body':
          dataPromise = c.req.json();
          break;
        case 'query':
          const queries = c.req.queries();
          const data: Record<string, any> = {};
          for (const key in queries) {
            if (queries.hasOwnProperty(key)) {
              data[key] = queries[key];
            }
          }
          dataPromise = Promise.resolve(data);
          break;
        case 'params':
          dataPromise = Promise.resolve(c.req.param());
          break;
        default:
          dataPromise = Promise.resolve({});
      }
      
      return dataPromise.then(function(data) {
        const validatedData = schema.parse(data);
        c.set('validatedData', validatedData);
        return next();
      });
    }).catch(function(error) {
      if (error instanceof z.ZodError) {
        return c.json(
          {
            error: 'Validation Error',
            message: 'Invalid input data',
            details: error.errors.map(function(e) {
              return {
                field: e.path.join('.'),
                message: e.message,
              };
            }),
          },
          400
        );
      }
      
      return c.json(
        {
          error: 'Internal Server Error',
          message: 'Failed to validate input',
        },
        500
      );
    });
  };
}

// CSP violation reporting endpoint
export function handleCSPViolation(c: Context<HonoContext>) {
  return c.req.json().then(function(report) {
    // Log CSP violation
    console.warn('CSP violation detected:', {
      report: report,
      userAgent: c.req.header('User-Agent'),
      ip: getConnInfo(c).remote.address,
      timestamp: new Date().toISOString(),
    });
    
    // In production, you might want to send alerts for critical violations
    if (report['violated-directive'] && report['violated-directive'].indexOf('script-src') !== -1) {
      console.warn('Critical CSP violation detected:', report);
    }
    
    return c.json({ status: 'ok' }, 204);
  }).catch(function(error) {
    console.error('Error handling CSP violation report:', error);
    return c.json({ error: 'Internal Server Error' }, 500);
  });
}