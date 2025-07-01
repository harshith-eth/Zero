import { getConnInfo } from 'hono/cloudflare-workers';
import type { HonoContext } from '../../ctx';
import { SecurityUtils } from './index';
import { redis } from '../services';
import { Context } from 'hono';

// Authentication security configuration
export const AUTH_SECURITY_CONFIG = {
  // Session configuration
  SESSION_TIMEOUT: 30 * 60 * 1000, // 30 minutes
  MAX_CONCURRENT_SESSIONS: 5,

  // Account lockout configuration
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60, // 15 minutes in seconds
  LOCKOUT_ESCALATION: [
    { attempts: 3, duration: 5 * 60 }, // 5 minutes
    { attempts: 5, duration: 15 * 60 }, // 15 minutes
    { attempts: 10, duration: 60 * 60 }, // 1 hour
    { attempts: 15, duration: 24 * 60 * 60 }, // 24 hours
  ],

  // Password security
  MIN_PASSWORD_LENGTH: 8,
  MAX_PASSWORD_LENGTH: 128,
  REQUIRE_SPECIAL_CHARS: true,
  REQUIRE_NUMBERS: true,
  REQUIRE_UPPERCASE: true,
  REQUIRE_LOWERCASE: true,
  PASSWORD_HISTORY_COUNT: 5,

  // MFA configuration
  MFA_CODE_LENGTH: 6,
  MFA_CODE_EXPIRY: 5 * 60, // 5 minutes
  MFA_MAX_ATTEMPTS: 3,

  // Suspicious activity thresholds
  SUSPICIOUS_LOGIN_THRESHOLD: 3,
  GEOLOCATION_CHANGE_THRESHOLD: 500, // km
  DEVICE_CHANGE_THRESHOLD: 3, // different devices in 24h
};

export interface LoginAttempt {
  ip: string;
  userAgent: string;
  timestamp: number;
  success: boolean;
  location?: {
    country?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };
  deviceFingerprint?: string;
}

export interface UserSession {
  sessionId: string;
  userId: string;
  ip: string;
  userAgent: string;
  createdAt: number;
  lastActivity: number;
  isActive: boolean;
  deviceFingerprint?: string;
  location?: {
    country?: string;
    city?: string;
  };
}

export interface AuthSecurityResult {
  allowed: boolean;
  reason?: string;
  warnings: string[];
  requiresMFA?: boolean;
  lockoutExpiry?: number;
  riskScore: number;
}

export class AuthSecurityService {
  private static readonly REDIS_KEYS = {
    LOGIN_ATTEMPTS: 'auth:login_attempts',
    ACCOUNT_LOCKOUT: 'auth:lockout',
    ACTIVE_SESSIONS: 'auth:sessions',
    MFA_CODES: 'auth:mfa_codes',
    PASSWORD_HISTORY: 'auth:password_history',
    SUSPICIOUS_ACTIVITY: 'auth:suspicious',
    DEVICE_FINGERPRINTS: 'auth:devices',
  };

  /**
   * Validate password strength
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean;
    score: number;
    violations: string[];
    suggestions: string[];
  } {
    const violations: string[] = [];
    const suggestions: string[] = [];
    let score = 0;

    // Length check
    if (password.length < AUTH_SECURITY_CONFIG.MIN_PASSWORD_LENGTH) {
      violations.push(
        `Password must be at least ${AUTH_SECURITY_CONFIG.MIN_PASSWORD_LENGTH} characters`,
      );
      suggestions.push('Use a longer password');
    } else {
      score += 20;
    }

    if (password.length > AUTH_SECURITY_CONFIG.MAX_PASSWORD_LENGTH) {
      violations.push(
        `Password must be no more than ${AUTH_SECURITY_CONFIG.MAX_PASSWORD_LENGTH} characters`,
      );
    }

    // Character type requirements
    if (AUTH_SECURITY_CONFIG.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
      violations.push('Password must contain lowercase letters');
      suggestions.push('Add lowercase letters');
    } else {
      score += 15;
    }

    if (AUTH_SECURITY_CONFIG.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
      violations.push('Password must contain uppercase letters');
      suggestions.push('Add uppercase letters');
    } else {
      score += 15;
    }

    if (AUTH_SECURITY_CONFIG.REQUIRE_NUMBERS && !/\d/.test(password)) {
      violations.push('Password must contain numbers');
      suggestions.push('Add numbers');
    } else {
      score += 15;
    }

    if (
      AUTH_SECURITY_CONFIG.REQUIRE_SPECIAL_CHARS &&
      !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    ) {
      violations.push('Password must contain special characters');
      suggestions.push('Add special characters (!@#$%^&* etc.)');
    } else {
      score += 15;
    }

    // Additional scoring
    const uniqueChars = new Set(password).size;
    score += Math.min(uniqueChars * 2, 20); // Bonus for character diversity

    // Common password patterns
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /abc123/i,
      /admin/i,
      /letmein/i,
      /welcome/i,
      /monkey/i,
      /dragon/i,
    ];

    if (commonPatterns.some((pattern) => pattern.test(password))) {
      violations.push('Password contains common patterns');
      suggestions.push('Avoid common words and patterns');
      score -= 30;
    }

    // Sequential characters
    if (/(.)\1{2,}/.test(password)) {
      violations.push('Password contains repeated characters');
      suggestions.push('Avoid repeating characters');
      score -= 10;
    }

    score = Math.max(0, Math.min(100, score));

    return {
      isValid: violations.length === 0 && score >= 60,
      score,
      violations,
      suggestions,
    };
  }

  /**
   * Record login attempt
   */
  static async recordLoginAttempt(
    email: string,
    ip: string,
    userAgent: string,
    success: boolean,
    additionalData?: {
      location?: LoginAttempt['location'];
      deviceFingerprint?: string;
    },
  ): Promise<void> {
    const cache = redis();
    const key = `${this.REDIS_KEYS.LOGIN_ATTEMPTS}:${email}`;
    const attemptKey = `${key}:${Date.now()}`;

    const attempt: LoginAttempt = {
      ip,
      userAgent,
      timestamp: Date.now(),
      success,
      location: additionalData?.location,
      deviceFingerprint: additionalData?.deviceFingerprint,
    };

    // Store individual attempt
    await cache.setex(attemptKey, 24 * 60 * 60, JSON.stringify(attempt)); // 24 hours

    // Update attempt counter
    if (!success) {
      await cache.incr(`${key}:failed`);
      await cache.expire(`${key}:failed`, AUTH_SECURITY_CONFIG.LOCKOUT_DURATION);
    } else {
      // Clear failed attempts on successful login
      await cache.del(`${key}:failed`);
    }
  }

  /**
   * Check if account is locked out
   */
  static async isAccountLockedOut(email: string): Promise<{
    isLocked: boolean;
    expiresAt?: number;
    reason?: string;
  }> {
    const cache = redis();
    const lockoutKey = `${this.REDIS_KEYS.ACCOUNT_LOCKOUT}:${email}`;

    const lockoutData = await cache.get(lockoutKey);
    if (lockoutData) {
      const lockout = JSON.parse(lockoutData as string);
      const now = Date.now();

      if (lockout.expiresAt > now) {
        return {
          isLocked: true,
          expiresAt: lockout.expiresAt,
          reason: lockout.reason,
        };
      } else {
        // Lockout expired, clean up
        await cache.del(lockoutKey);
      }
    }

    return { isLocked: false };
  }

  /**
   * Implement account lockout
   */
  static async lockAccount(email: string, reason: string, duration?: number): Promise<void> {
    const cache = redis();
    const lockoutKey = `${this.REDIS_KEYS.ACCOUNT_LOCKOUT}:${email}`;

    // Get current failed attempts to determine lockout duration
    const failedKey = `${this.REDIS_KEYS.LOGIN_ATTEMPTS}:${email}:failed`;
    const failedAttempts = parseInt(((await cache.get(failedKey)) as string) || '0');

    // Determine lockout duration based on escalation policy
    let lockoutDuration = duration || AUTH_SECURITY_CONFIG.LOCKOUT_DURATION;

    for (const escalation of AUTH_SECURITY_CONFIG.LOCKOUT_ESCALATION) {
      if (failedAttempts >= escalation.attempts) {
        lockoutDuration = escalation.duration;
      }
    }

    const lockoutData = {
      reason,
      expiresAt: Date.now() + lockoutDuration * 1000,
      attempts: failedAttempts,
      lockedAt: Date.now(),
    };

    await cache.setex(lockoutKey, lockoutDuration, JSON.stringify(lockoutData));

    console.warn(`Account locked: ${email}, reason: ${reason}, duration: ${lockoutDuration}s`);
  }

  /**
   * Evaluate login attempt security
   */
  static async evaluateLoginSecurity(
    email: string,
    ip: string,
    userAgent: string,
    additionalData?: {
      location?: LoginAttempt['location'];
      deviceFingerprint?: string;
    },
  ): Promise<AuthSecurityResult> {
    const warnings: string[] = [];
    let riskScore = 0;
    let requiresMFA = false;

    // Check if account is locked
    const lockoutCheck = await this.isAccountLockedOut(email);
    if (lockoutCheck.isLocked) {
      return {
        allowed: false,
        reason: lockoutCheck.reason || 'Account temporarily locked',
        warnings,
        lockoutExpiry: lockoutCheck.expiresAt,
        riskScore: 100,
      };
    }

    // Check recent failed attempts
    const cache = redis();
    const failedKey = `${this.REDIS_KEYS.LOGIN_ATTEMPTS}:${email}:failed`;
    const failedAttempts = parseInt(((await cache.get(failedKey)) as string) || '0');

    if (failedAttempts >= 3) {
      warnings.push('Multiple recent failed login attempts detected');
      riskScore += 30;
      requiresMFA = true;
    }

    // Check for suspicious IP patterns
    const suspiciousActivity = SecurityUtils.detectSuspiciousActivity(userAgent, ip);
    if (suspiciousActivity.isSuspicious) {
      warnings.push('Suspicious user agent or IP detected');
      riskScore += suspiciousActivity.reasons.length * 10;
    }

    // Check for geolocation changes
    if (additionalData?.location) {
      const lastLocationKey = `${this.REDIS_KEYS.SUSPICIOUS_ACTIVITY}:${email}:location`;
      const lastLocationData = await cache.get(lastLocationKey);

      if (lastLocationData) {
        const lastLocation = JSON.parse(lastLocationData as string);

        // Simple distance calculation (this is approximate)
        if (
          lastLocation.latitude &&
          lastLocation.longitude &&
          additionalData.location.latitude &&
          additionalData.location.longitude
        ) {
          const distance = this.calculateDistance(
            lastLocation.latitude,
            lastLocation.longitude,
            additionalData.location.latitude,
            additionalData.location.longitude,
          );

          if (distance > AUTH_SECURITY_CONFIG.GEOLOCATION_CHANGE_THRESHOLD) {
            warnings.push(`Login from unusual location (${distance.toFixed(0)}km from last login)`);
            riskScore += 25;
            requiresMFA = true;
          }
        }
      }

      // Update last known location
      await cache.setex(
        lastLocationKey,
        30 * 24 * 60 * 60,
        JSON.stringify(additionalData.location),
      ); // 30 days
    }

    // Check for device changes
    if (additionalData?.deviceFingerprint) {
      const deviceKey = `${this.REDIS_KEYS.DEVICE_FINGERPRINTS}:${email}`;
      const knownDevices = await cache.get(deviceKey);

      if (knownDevices) {
        const devices = JSON.parse(knownDevices as string);

        if (devices.indexOf(additionalData.deviceFingerprint) === -1) {
          warnings.push('Login from new device detected');
          riskScore += 20;
          requiresMFA = true;

          // Add device to known devices
          devices.push(additionalData.deviceFingerprint);
          await cache.setex(deviceKey, 90 * 24 * 60 * 60, JSON.stringify(devices)); // 90 days
        }
      } else {
        // First time login from this device
        await cache.setex(
          deviceKey,
          90 * 24 * 60 * 60,
          JSON.stringify([additionalData.deviceFingerprint]),
        );
      }
    }

    // Check time-based patterns
    const now = new Date();
    const hour = now.getHours();

    // Unusual login hours (2 AM - 6 AM)
    if (hour >= 2 && hour <= 6) {
      warnings.push('Login during unusual hours');
      riskScore += 15;
    }

    // Weekend logins for business accounts might be suspicious
    const dayOfWeek = now.getDay();
    if (dayOfWeek === 0 || dayOfWeek === 6) {
      // This could be configurable per user/organization
      riskScore += 5;
    }

    // Determine if login should be allowed
    const allowed = riskScore < 70 && failedAttempts < AUTH_SECURITY_CONFIG.MAX_LOGIN_ATTEMPTS;

    // Auto-lock if risk is too high
    if (riskScore >= 80) {
      await this.lockAccount(email, 'High risk login attempt detected', 60 * 60); // 1 hour
      return {
        allowed: false,
        reason: 'Login blocked due to high risk',
        warnings,
        riskScore,
        requiresMFA,
      };
    }

    return {
      allowed,
      reason: allowed ? undefined : 'Login denied due to security concerns',
      warnings,
      requiresMFA: requiresMFA || riskScore > 40,
      riskScore,
    };
  }

  /**
   * Manage user sessions
   */
  static async createSession(
    userId: string,
    ip: string,
    userAgent: string,
    additionalData?: {
      deviceFingerprint?: string;
      location?: UserSession['location'];
    },
  ): Promise<string> {
    const cache = redis();
    const sessionId = SecurityUtils.generateSecureToken();
    const sessionsKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:${userId}`;

    const session: UserSession = {
      sessionId,
      userId,
      ip,
      userAgent,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      isActive: true,
      deviceFingerprint: additionalData?.deviceFingerprint,
      location: additionalData?.location,
    };

    // Get existing sessions
    const existingSessions = await cache.get(sessionsKey);
    let sessions: UserSession[] = existingSessions ? JSON.parse(existingSessions as string) : [];

    // Remove inactive sessions and enforce max concurrent sessions
    sessions = sessions.filter(
      (s) => s.isActive && Date.now() - s.lastActivity < AUTH_SECURITY_CONFIG.SESSION_TIMEOUT,
    );

    if (sessions.length >= AUTH_SECURITY_CONFIG.MAX_CONCURRENT_SESSIONS) {
      // Remove oldest session
      sessions.sort((a, b) => a.lastActivity - b.lastActivity);
      sessions = sessions.slice(1);
    }

    sessions.push(session);

    // Store sessions
    await cache.setex(sessionsKey, 30 * 24 * 60 * 60, JSON.stringify(sessions)); // 30 days

    // Store individual session
    const sessionKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:session:${sessionId}`;
    await cache.setex(
      sessionKey,
      AUTH_SECURITY_CONFIG.SESSION_TIMEOUT / 1000,
      JSON.stringify(session),
    );

    return sessionId;
  }

  /**
   * Validate and update session
   */
  static async validateSession(sessionId: string): Promise<{
    isValid: boolean;
    session?: UserSession;
    warnings: string[];
  }> {
    const cache = redis();
    const sessionKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:session:${sessionId}`;

    const sessionData = await cache.get(sessionKey);
    if (!sessionData) {
      return { isValid: false, warnings: ['Session not found'] };
    }

    const session: UserSession = JSON.parse(sessionData as string);
    const warnings: string[] = [];

    // Check session timeout
    if (Date.now() - session.lastActivity > AUTH_SECURITY_CONFIG.SESSION_TIMEOUT) {
      await this.invalidateSession(sessionId);
      return { isValid: false, warnings: ['Session expired'] };
    }

    // Update last activity
    session.lastActivity = Date.now();
    await cache.setex(
      sessionKey,
      AUTH_SECURITY_CONFIG.SESSION_TIMEOUT / 1000,
      JSON.stringify(session),
    );

    // Update in user sessions list
    const sessionsKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:${session.userId}`;
    const existingSessions = await cache.get(sessionsKey);
    if (existingSessions) {
      const sessions: UserSession[] = JSON.parse(existingSessions as string);
      const sessionIndex = sessions.findIndex((s) => s.sessionId === sessionId);
      if (sessionIndex !== -1) {
        sessions[sessionIndex] = session;
        await cache.setex(sessionsKey, 30 * 24 * 60 * 60, JSON.stringify(sessions));
      }
    }

    return { isValid: true, session, warnings };
  }

  /**
   * Invalidate session
   */
  static async invalidateSession(sessionId: string): Promise<void> {
    const cache = redis();
    const sessionKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:session:${sessionId}`;

    // Get session to find user ID
    const sessionData = await cache.get(sessionKey);
    if (sessionData) {
      const session: UserSession = JSON.parse(sessionData as string);

      // Remove from user sessions list
      const sessionsKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:${session.userId}`;
      const existingSessions = await cache.get(sessionsKey);
      if (existingSessions) {
        const sessions: UserSession[] = JSON.parse(existingSessions as string);
        const filteredSessions = sessions.filter((s) => s.sessionId !== sessionId);
        await cache.setex(sessionsKey, 30 * 24 * 60 * 60, JSON.stringify(filteredSessions));
      }
    }

    // Remove individual session
    await cache.del(sessionKey);
  }

  /**
   * Get user's active sessions
   */
  static async getUserSessions(userId: string): Promise<UserSession[]> {
    const cache = redis();
    const sessionsKey = `${this.REDIS_KEYS.ACTIVE_SESSIONS}:${userId}`;

    const sessionsData = await cache.get(sessionsKey);
    if (!sessionsData) return [];

    const sessions: UserSession[] = JSON.parse(sessionsData as string);

    // Filter out expired sessions
    const activeSessions = sessions.filter(
      (s) => s.isActive && Date.now() - s.lastActivity < AUTH_SECURITY_CONFIG.SESSION_TIMEOUT,
    );

    // Update if any sessions were filtered out
    if (activeSessions.length !== sessions.length) {
      await cache.setex(sessionsKey, 30 * 24 * 60 * 60, JSON.stringify(activeSessions));
    }

    return activeSessions;
  }

  /**
   * Calculate distance between two coordinates (Haversine formula)
   */
  private static calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371; // Earth's radius in kilometers
    const dLat = this.toRadians(lat2 - lat1);
    const dLon = this.toRadians(lon2 - lon1);

    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) *
        Math.cos(this.toRadians(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2);

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));

    return R * c;
  }

  private static toRadians(degrees: number): number {
    return degrees * (Math.PI / 180);
  }
}

/**
 * Authentication security middleware
 */
export function createAuthSecurityMiddleware() {
  return async function (c: Context<HonoContext>, next: () => Promise<void>) {
    const sessionUser = c.var.sessionUser;

    if (!sessionUser) {
      return next(); // Not authenticated, continue
    }

    // Get session info
    const sessionCookie = c.req.header('Cookie');
    const sessionId = sessionCookie ? extractSessionId(sessionCookie) : null;

    if (sessionId) {
      const sessionValidation = await AuthSecurityService.validateSession(sessionId);

      if (!sessionValidation.isValid) {
        console.warn('Invalid session detected:', sessionValidation.warnings);
        return c.json({ error: 'Session invalid', warnings: sessionValidation.warnings }, 401);
      }

      if (sessionValidation.warnings.length > 0) {
        console.warn('Session warnings:', sessionValidation.warnings);
      }

      // Add session info to context
      c.set('secureSession', sessionValidation.session);
    }

    return next();
  };
}

/**
 * Extract session ID from cookie (simplified)
 */
function extractSessionId(cookieHeader: string): string | null {
  // This is a simplified implementation
  // In production, you'd properly parse the cookie header
  const match = cookieHeader.match(/session[_-]?id=([^;]+)/i);
  return match ? match[1] : null;
}
