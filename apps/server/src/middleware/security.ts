import { Context, Next } from 'hono';
import { z } from 'zod';
import { SECURITY_HEADERS, RATE_LIMIT_CONFIG } from '@zero/encryption';

/**
 * Security middleware for Zero email server
 */

// Rate limiter storage (in production, use Redis)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

/**
 * Add security headers to responses
 */
export async function securityHeaders(c: Context, next: Next) {
  // Add security headers
  c.header('Content-Security-Policy', SECURITY_HEADERS.CSP);
  c.header('Strict-Transport-Security', SECURITY_HEADERS.HSTS);
  c.header('X-Content-Type-Options', SECURITY_HEADERS.X_CONTENT_TYPE);
  c.header('X-Frame-Options', SECURITY_HEADERS.X_FRAME_OPTIONS);
  c.header('X-XSS-Protection', SECURITY_HEADERS.X_XSS_PROTECTION);
  c.header('Referrer-Policy', SECURITY_HEADERS.REFERRER_POLICY);
  c.header('Permissions-Policy', SECURITY_HEADERS.PERMISSIONS_POLICY);

  await next();
}

/**
 * Rate limiting middleware
 */
export function createRateLimiter(config: {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (c: Context) => string;
}) {
  return async function rateLimiter(c: Context, next: Next) {
    const key = config.keyGenerator ? config.keyGenerator(c) : c.req.header('cf-connecting-ip') || 'anonymous';
    const now = Date.now();

    // Clean up expired entries
    for (const [k, v] of rateLimitStore.entries()) {
      if (v.resetTime < now) {
        rateLimitStore.delete(k);
      }
    }

    // Get or create rate limit entry
    let entry = rateLimitStore.get(key);
    if (!entry || entry.resetTime < now) {
      entry = {
        count: 0,
        resetTime: now + config.windowMs,
      };
      rateLimitStore.set(key, entry);
    }

    // Increment count
    entry.count++;

    // Check if limit exceeded
    if (entry.count > config.maxRequests) {
      const retryAfter = Math.ceil((entry.resetTime - now) / 1000);
      c.header('Retry-After', retryAfter.toString());
      c.header('X-RateLimit-Limit', config.maxRequests.toString());
      c.header('X-RateLimit-Remaining', '0');
      c.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString());

      return c.json(
        {
          error: 'Too many requests',
          message: `Rate limit exceeded. Please try again in ${retryAfter} seconds.`,
        },
        429
      );
    }

    // Add rate limit headers
    c.header('X-RateLimit-Limit', config.maxRequests.toString());
    c.header('X-RateLimit-Remaining', (config.maxRequests - entry.count).toString());
    c.header('X-RateLimit-Reset', new Date(entry.resetTime).toISOString());

    await next();
  };
}

/**
 * Input validation middleware factory
 */
export function validateInput<T extends z.ZodType>(schema: T) {
  return async function validator(c: Context, next: Next) {
    try {
      const contentType = c.req.header('content-type');
      let data;

      if (contentType?.includes('application/json')) {
        data = await c.req.json();
      } else if (contentType?.includes('multipart/form-data')) {
        data = await c.req.parseBody();
      } else {
        data = c.req.query();
      }

      const validated = schema.parse(data);
      c.set('validatedInput', validated);
      
      await next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        return c.json(
          {
            error: 'Validation error',
            details: error.errors,
          },
          400
        );
      }
      throw error;
    }
  };
}

/**
 * CSRF protection middleware
 */
export async function csrfProtection(c: Context, next: Next) {
  const method = c.req.method;
  
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    await next();
    return;
  }

  const token = c.req.header('X-CSRF-Token');
  const sessionToken = c.get('session')?.csrfToken;

  if (!token || token !== sessionToken) {
    return c.json(
      {
        error: 'CSRF token validation failed',
        message: 'Invalid or missing CSRF token',
      },
      403
    );
  }

  await next();
}

/**
 * XSS protection - sanitize user input
 */
export function sanitizeInput(input: any): any {
  if (typeof input === 'string') {
    // Basic XSS prevention - in production use a proper library like DOMPurify
    return input
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }
  
  if (Array.isArray(input)) {
    return input.map(sanitizeInput);
  }
  
  if (input && typeof input === 'object') {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(input)) {
      sanitized[key] = sanitizeInput(value);
    }
    return sanitized;
  }
  
  return input;
}

/**
 * SQL injection prevention helper
 */
export function escapeSqlIdentifier(identifier: string): string {
  // Remove any characters that aren't alphanumeric or underscore
  return identifier.replace(/[^a-zA-Z0-9_]/g, '');
}

/**
 * Create rate limiters for different endpoints
 */
export const loginRateLimiter = createRateLimiter({
  windowMs: RATE_LIMIT_CONFIG.LOGIN.WINDOW_MS,
  maxRequests: RATE_LIMIT_CONFIG.LOGIN.MAX_ATTEMPTS,
  keyGenerator: (c) => {
    const email = c.req.query('email') || c.req.header('x-user-email');
    return email || c.req.header('cf-connecting-ip') || 'anonymous';
  },
});

export const apiRateLimiter = createRateLimiter({
  windowMs: RATE_LIMIT_CONFIG.API.WINDOW_MS,
  maxRequests: RATE_LIMIT_CONFIG.API.MAX_REQUESTS,
});

export const emailSendRateLimiter = createRateLimiter({
  windowMs: RATE_LIMIT_CONFIG.EMAIL_SEND.WINDOW_MS,
  maxRequests: RATE_LIMIT_CONFIG.EMAIL_SEND.MAX_EMAILS,
  keyGenerator: (c) => {
    const userId = c.get('session')?.userId;
    return userId || c.req.header('cf-connecting-ip') || 'anonymous';
  },
});

/**
 * Audit logging middleware
 */
export async function auditLog(c: Context, next: Next) {
  const startTime = Date.now();
  const method = c.req.method;
  const path = c.req.path;
  const userId = c.get('session')?.userId;
  const ip = c.req.header('cf-connecting-ip') || c.req.header('x-forwarded-for');

  await next();

  const duration = Date.now() - startTime;
  const status = c.res.status;

  // Log security-relevant events
  if (shouldAuditLog(method, path, status)) {
    console.log(JSON.stringify({
      type: 'audit',
      timestamp: new Date().toISOString(),
      userId,
      ip,
      method,
      path,
      status,
      duration,
      userAgent: c.req.header('user-agent'),
    }));
  }
}

function shouldAuditLog(method: string, path: string, status: number): boolean {
  // Always log authentication attempts
  if (path.includes('/auth/') || path.includes('/login')) return true;
  
  // Log failed requests
  if (status >= 400) return true;
  
  // Log sensitive operations
  if (method !== 'GET' && (
    path.includes('/keys') ||
    path.includes('/encrypt') ||
    path.includes('/decrypt') ||
    path.includes('/settings')
  )) return true;
  
  return false;
}