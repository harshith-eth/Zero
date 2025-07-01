import sanitizeHtml from 'sanitize-html';
import { SecurityUtils } from './index';

// Email security configuration
export const EMAIL_SECURITY_CONFIG = {
  // Maximum email size (10MB)
  MAX_EMAIL_SIZE: 10 * 1024 * 1024,

  // Maximum attachment size (25MB)
  MAX_ATTACHMENT_SIZE: 25 * 1024 * 1024,

  // Allowed HTML tags for email content
  ALLOWED_TAGS: [
    'h1',
    'h2',
    'h3',
    'h4',
    'h5',
    'h6',
    'p',
    'br',
    'div',
    'span',
    'strong',
    'b',
    'em',
    'i',
    'u',
    's',
    'ul',
    'ol',
    'li',
    'a',
    'img',
    'table',
    'thead',
    'tbody',
    'tr',
    'td',
    'th',
    'blockquote',
    'pre',
    'code',
    'hr',
  ],

  // Allowed HTML attributes
  ALLOWED_ATTRIBUTES: {
    a: ['href', 'title', 'target'],
    img: ['src', 'alt', 'width', 'height', 'style'],
    div: ['style', 'class'],
    span: ['style', 'class'],
    p: ['style', 'class'],
    table: ['style', 'class', 'border', 'cellpadding', 'cellspacing'],
    td: ['style', 'class', 'colspan', 'rowspan'],
    th: ['style', 'class', 'colspan', 'rowspan'],
    '*': ['style'],
  },

  // Allowed URL schemes
  ALLOWED_SCHEMES: ['http', 'https', 'mailto', 'tel'],

  // Dangerous URL patterns
  DANGEROUS_URL_PATTERNS: [
    /javascript:/i,
    /vbscript:/i,
    /data:text\/html/i,
    /data:application\/javascript/i,
    /blob:/i,
    /file:/i,
  ],

  // Suspicious domains
  SUSPICIOUS_DOMAINS: ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly'],

  // Safe image domains for proxy bypass
  SAFE_IMAGE_DOMAINS: [
    'github.com',
    'githubusercontent.com',
    'gravatar.com',
    'gmail.com',
    'googleusercontent.com',
  ],
};

export interface EmailSecurityResult {
  isSecure: boolean;
  sanitizedContent?: string;
  violations: string[];
  blockedElements: number;
  warnings: string[];
}

export interface AttachmentSecurityResult {
  isSecure: boolean;
  violations: string[];
  fileType: string;
  riskLevel: 'low' | 'medium' | 'high';
}

export class EmailSecurityService {
  /**
   * Comprehensive email content sanitization
   */
  static sanitizeEmailContent(
    html: string,
    options: {
      allowImages?: boolean;
      allowExternalLinks?: boolean;
      maxLength?: number;
    } = {},
  ): EmailSecurityResult {
    const {
      allowImages = false,
      allowExternalLinks = true,
      maxLength = EMAIL_SECURITY_CONFIG.MAX_EMAIL_SIZE,
    } = options;

    const violations: string[] = [];
    const warnings: string[] = [];
    let blockedElements = 0;

    // Check email size
    if (html.length > maxLength) {
      violations.push('Email content exceeds maximum size limit');
      return {
        isSecure: false,
        violations,
        blockedElements,
        warnings,
      };
    }

    // Pre-sanitization analysis
    const dangerousPatterns = [
      /<script[^>]*>/gi,
      /<iframe[^>]*>/gi,
      /<object[^>]*>/gi,
      /<embed[^>]*>/gi,
      /<form[^>]*>/gi,
      /on\w+\s*=/gi,
      /javascript:/gi,
      /vbscript:/gi,
    ];

    dangerousPatterns.forEach((pattern) => {
      const matches = html.match(pattern);
      if (matches) {
        blockedElements += matches.length;
        violations.push(`Blocked ${matches.length} potentially dangerous elements`);
      }
    });

    // Configure sanitization options
    const sanitizeOptions: sanitizeHtml.IOptions = {
      allowedTags: EMAIL_SECURITY_CONFIG.ALLOWED_TAGS,
      allowedAttributes: EMAIL_SECURITY_CONFIG.ALLOWED_ATTRIBUTES,
      allowedSchemes: EMAIL_SECURITY_CONFIG.ALLOWED_SCHEMES,
      allowedSchemesAppliedToAttributes: ['href', 'src'],
      allowedClasses: {},
      allowedStyles: {
        '*': {
          // Allow safe CSS properties
          color: [/^#[0-9a-f]{3,6}$/i, /^rgb\(/i, /^rgba\(/i, /^[a-z]+$/i],
          'background-color': [/^#[0-9a-f]{3,6}$/i, /^rgb\(/i, /^rgba\(/i, /^[a-z]+$/i],
          'font-size': [/^\d+(?:px|em|rem|%)$/],
          'font-weight': [/^(?:normal|bold|bolder|lighter|\d+)$/],
          'font-family': [/.*/],
          'text-align': [/^(?:left|right|center|justify)$/],
          'text-decoration': [/^(?:none|underline|overline|line-through)$/],
          margin: [/^\d+(?:px|em|rem|%)$/],
          padding: [/^\d+(?:px|em|rem|%)$/],
          border: [/.*/],
          width: [/^\d+(?:px|em|rem|%)$/],
          height: [/^\d+(?:px|em|rem|%)$/],
          display: [/^(?:block|inline|inline-block|none)$/],
        },
      },
      transformTags: {
        a: (tagName, attribs) => {
          // Process links
          const href = attribs.href;
          if (href) {
            // Check for dangerous URLs
            if (
              EMAIL_SECURITY_CONFIG.DANGEROUS_URL_PATTERNS.some((pattern) => pattern.test(href))
            ) {
              violations.push(`Blocked dangerous link: ${href}`);
              blockedElements++;
              return { tagName: 'span', attribs: { class: 'blocked-link' } };
            }

            // Check for suspicious domains
            try {
              const url = new URL(href);
              if (EMAIL_SECURITY_CONFIG.SUSPICIOUS_DOMAINS.indexOf(url.hostname) !== -1) {
                warnings.push(`Suspicious link domain detected: ${url.hostname}`);
              }
            } catch (e) {
              // Invalid URL
              violations.push(`Invalid URL blocked: ${href}`);
              blockedElements++;
              return { tagName: 'span', attribs: { class: 'blocked-link' } };
            }

            // Ensure external links open in new tab and have security attributes
            if (!allowExternalLinks && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
              violations.push(`External link blocked: ${href}`);
              blockedElements++;
              return { tagName: 'span', attribs: { class: 'blocked-link' } };
            }

            return {
              tagName: 'a',
              attribs: {
                ...attribs,
                target: '_blank',
                rel: 'noopener noreferrer nofollow',
                href: href,
              },
            };
          }

          return { tagName, attribs };
        },

        img: (tagName, attribs) => {
          // Process images
          const src = attribs.src;
          if (src) {
            // Block images if not allowed
            if (!allowImages) {
              violations.push(`Image blocked: ${src}`);
              blockedElements++;
              return { tagName: 'div', attribs: { class: 'blocked-image' } };
            }

            // Check for dangerous image sources
            if (EMAIL_SECURITY_CONFIG.DANGEROUS_URL_PATTERNS.some((pattern) => pattern.test(src))) {
              violations.push(`Dangerous image source blocked: ${src}`);
              blockedElements++;
              return { tagName: 'div', attribs: { class: 'blocked-image' } };
            }

            // Proxy external images (except from safe domains)
            try {
              const url = new URL(src);
              const isSafeDomain = EMAIL_SECURITY_CONFIG.SAFE_IMAGE_DOMAINS.some(function (domain) {
                return url.hostname.indexOf(domain, url.hostname.length - domain.length) !== -1;
              });

              if (!isSafeDomain && !src.startsWith('data:')) {
                // In a real implementation, you'd proxy the image through your service
                const proxiedSrc = `/api/security/image-proxy?url=${encodeURIComponent(src)}`;
                return {
                  tagName: 'img',
                  attribs: {
                    ...attribs,
                    src: proxiedSrc,
                    'data-original-src': src,
                  },
                };
              }
            } catch (e) {
              // Invalid URL or data URI - allow data URIs for inline images
              if (!src.startsWith('data:image/')) {
                violations.push(`Invalid image source blocked: ${src}`);
                blockedElements++;
                return { tagName: 'div', attribs: { class: 'blocked-image' } };
              }
            }
          }

          return { tagName, attribs };
        },
      },
    };

    // Perform sanitization
    let sanitizedContent;
    try {
      sanitizedContent = sanitizeHtml(html, sanitizeOptions);
    } catch (error) {
      violations.push(`Sanitization failed: ${error}`);
      return {
        isSecure: false,
        violations,
        blockedElements,
        warnings,
      };
    }

    // Post-sanitization checks
    const sizeReduction = ((html.length - sanitizedContent.length) / html.length) * 100;
    if (sizeReduction > 50) {
      warnings.push(
        `Significant content removed during sanitization (${sizeReduction.toFixed(1)}%)`,
      );
    }

    return {
      isSecure: violations.length === 0,
      sanitizedContent,
      violations,
      blockedElements,
      warnings,
    };
  }

  /**
   * Validate email sender and detect spoofing
   */
  static validateEmailSender(
    fromAddress: string,
    fromName?: string,
    headers?: Record<string, string>,
  ): {
    isTrusted: boolean;
    warnings: string[];
    spamScore: number;
  } {
    const warnings: string[] = [];
    let spamScore = 0;

    // Basic email validation
    if (!SecurityUtils.validateEmailSecurity(fromAddress)) {
      warnings.push('Sender email contains suspicious patterns');
      spamScore += 30;
    }

    // Check for display name spoofing
    if (fromName) {
      const suspiciousNamePatterns = [
        /security@/i,
        /noreply@/i,
        /admin@/i,
        /support@/i,
        /paypal/i,
        /amazon/i,
        /apple/i,
        /microsoft/i,
        /google/i,
      ];

      if (suspiciousNamePatterns.some((pattern) => pattern.test(fromName))) {
        const domain = fromAddress.split('@')[1];
        if (domain && fromName.toLowerCase().indexOf(domain.toLowerCase()) === -1) {
          warnings.push('Potential display name spoofing detected');
          spamScore += 40;
        }
      }
    }

    // Check headers for authentication
    if (headers) {
      const authResults = headers['Authentication-Results'] || '';
      const spfPass = authResults.indexOf('spf=pass') !== -1;
      const dkimPass = authResults.indexOf('dkim=pass') !== -1;
      const dmarcPass = authResults.indexOf('dmarc=pass') !== -1;

      if (!spfPass) {
        warnings.push('SPF authentication failed or missing');
        spamScore += 20;
      }

      if (!dkimPass) {
        warnings.push('DKIM authentication failed or missing');
        spamScore += 15;
      }

      if (!dmarcPass) {
        warnings.push('DMARC authentication failed or missing');
        spamScore += 25;
      }
    }

    return {
      isTrusted: spamScore < 50,
      warnings,
      spamScore,
    };
  }

  /**
   * Scan email attachments for security threats
   */
  static scanAttachment(attachment: {
    filename: string;
    contentType: string;
    size: number;
    content?: ArrayBuffer;
  }): AttachmentSecurityResult {
    const violations: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' = 'low';

    // Check file size
    if (attachment.size > EMAIL_SECURITY_CONFIG.MAX_ATTACHMENT_SIZE) {
      violations.push(`Attachment size (${attachment.size} bytes) exceeds limit`);
      riskLevel = 'high';
    }

    // Check file type
    const dangerousTypes = [
      'application/x-msdownload',
      'application/x-executable',
      'application/x-msdos-program',
      'application/x-winexe',
      'application/x-winhelp',
      'application/vnd.ms-cab-compressed',
      'application/java-archive',
      'application/x-java-archive',
      'text/x-script',
      'text/javascript',
      'application/javascript',
    ];

    if (dangerousTypes.indexOf(attachment.contentType) !== -1) {
      violations.push(`Dangerous file type: ${attachment.contentType}`);
      riskLevel = 'high';
    }

    // Check file extension
    const fileExtension = attachment.filename.split('.').pop()?.toLowerCase();
    const dangerousExtensions = [
      'exe',
      'bat',
      'cmd',
      'com',
      'scr',
      'pif',
      'vbs',
      'js',
      'jar',
      'app',
      'deb',
      'pkg',
      'rpm',
      'dmg',
      'iso',
      'msi',
      'dll',
      'sys',
    ];

    if (fileExtension && dangerousExtensions.indexOf(fileExtension) !== -1) {
      violations.push(`Dangerous file extension: .${fileExtension}`);
      riskLevel = 'high';
    }

    // Check for double extensions
    const extensionMatches = attachment.filename.match(/\.[a-zA-Z0-9]+/g);
    if (extensionMatches && extensionMatches.length > 1) {
      violations.push('Multiple file extensions detected (possible disguise)');
      riskLevel = 'medium';
    }

    // Check filename for suspicious patterns
    const suspiciousPatterns = [
      /invoice/i,
      /payment/i,
      /receipt/i,
      /document/i,
      /file/i,
      /photo/i,
      /image/i,
    ];

    if (suspiciousPatterns.some((pattern) => pattern.test(attachment.filename))) {
      if (riskLevel === 'low') riskLevel = 'medium';
    }

    return {
      isSecure: violations.length === 0 && riskLevel === 'low',
      violations,
      fileType: attachment.contentType,
      riskLevel,
    };
  }

  /**
   * Generate security report for email
   */
  static generateEmailSecurityReport(email: {
    from: string;
    fromName?: string;
    subject: string;
    htmlContent: string;
    attachments?: Array<{
      filename: string;
      contentType: string;
      size: number;
    }>;
    headers?: Record<string, string>;
  }): {
    overallRisk: 'low' | 'medium' | 'high';
    recommendations: string[];
    contentSecurity: EmailSecurityResult;
    senderSecurity: ReturnType<typeof EmailSecurityService.validateEmailSender>;
    attachmentSecurity?: AttachmentSecurityResult[];
  } {
    const recommendations: string[] = [];

    // Analyze content
    const contentSecurity = this.sanitizeEmailContent(email.htmlContent, {
      allowImages: false,
      allowExternalLinks: true,
    });

    // Analyze sender
    const senderSecurity = this.validateEmailSender(email.from, email.fromName, email.headers);

    // Analyze attachments
    let attachmentSecurity: AttachmentSecurityResult[] | undefined;
    if (email.attachments && email.attachments.length > 0) {
      attachmentSecurity = email.attachments.map((attachment) => this.scanAttachment(attachment));
    }

    // Calculate overall risk
    let riskScore = 0;

    // Content risk
    if (!contentSecurity.isSecure) riskScore += 30;
    if (contentSecurity.blockedElements > 5) riskScore += 20;

    // Sender risk
    riskScore += senderSecurity.spamScore;

    // Attachment risk
    if (attachmentSecurity) {
      attachmentSecurity.forEach((result) => {
        if (result.riskLevel === 'high') riskScore += 40;
        else if (result.riskLevel === 'medium') riskScore += 20;
      });
    }

    const overallRisk = riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low';

    // Generate recommendations
    if (contentSecurity.violations.length > 0) {
      recommendations.push('Review email content for security violations');
    }

    if (senderSecurity.spamScore > 30) {
      recommendations.push('Verify sender authenticity before trusting content');
    }

    if (attachmentSecurity?.some((result) => !result.isSecure)) {
      recommendations.push('Scan attachments before opening');
    }

    if (overallRisk === 'high') {
      recommendations.push('Consider blocking or quarantining this email');
    }

    return {
      overallRisk,
      recommendations,
      contentSecurity,
      senderSecurity,
      attachmentSecurity,
    };
  }
}

/**
 * Image proxy endpoint handler for secure image loading
 */
export function createImageProxyHandler() {
  return async function (c: any) {
    const imageUrl = c.req.query('url');

    if (!imageUrl) {
      return c.json({ error: 'URL parameter required' }, 400);
    }

    try {
      // Validate URL
      const url = new URL(imageUrl);

      // Check if it's a safe domain
      const isSafeDomain = EMAIL_SECURITY_CONFIG.SAFE_IMAGE_DOMAINS.some(function (domain) {
        return url.hostname.indexOf(domain, url.hostname.length - domain.length) !== -1;
      });

      if (!isSafeDomain) {
        // In production, you'd implement actual image proxying here
        // For now, return a placeholder
        return c.json({ error: 'Image proxy not implemented' }, 501);
      }

      // Proxy the image (simplified implementation)
      const response = await fetch(imageUrl, {
        headers: {
          'User-Agent': 'Zero Email Client Image Proxy/1.0',
        },
      });

      if (!response.ok) {
        return c.json({ error: 'Failed to fetch image' }, 502);
      }

      const contentType = response.headers.get('Content-Type') || 'application/octet-stream';
      const imageBuffer = await response.arrayBuffer();

      return new Response(imageBuffer, {
        headers: {
          'Content-Type': contentType,
          'Cache-Control': 'public, max-age=3600',
          'X-Proxied-By': 'Zero Email Security',
        },
      });
    } catch (error) {
      return c.json({ error: 'Invalid URL or proxy error' }, 400);
    }
  };
}
