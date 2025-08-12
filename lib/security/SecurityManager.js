// framework/lib/security/SecurityManager.js
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

class SecurityManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.rateLimiters = new Map();
    }

    async initialize() {
        this.logger.info('Initializing security components...');
        this.setupRateLimiters();
    }

    setupRateLimiters() {
        // General API rate limiter
        this.rateLimiters.set('api', rateLimit({
            windowMs: this.config.get('RATE_LIMIT_WINDOW'),
            max: this.config.get('RATE_LIMIT_MAX'),
            message: { error: 'Too many requests from this IP' },
            standardHeaders: true,
            legacyHeaders: false,
            trustProxy: true,
            handler: (req, res) => {
                this.logger.securityLog('RATE_LIMIT_EXCEEDED', {
                    path: req.path,
                    method: req.method
                }, req.ip);
                res.status(429).json({ error: 'Too many requests' });
            }
        }));

        // Authentication rate limiter (stricter)
        this.rateLimiters.set('auth', rateLimit({
            windowMs: this.config.get('RATE_LIMIT_WINDOW'),
            max: this.config.get('AUTH_RATE_LIMIT_MAX'),
            skipSuccessfulRequests: true,
            trustProxy: true,
            standardHeaders: true,
            legacyHeaders: false,
            handler: (req, res) => {
                this.logger.securityLog('AUTH_RATE_LIMIT_EXCEEDED', {
                    path: req.path,
                    attempts: req.rateLimit?.remaining || 0
                }, req.ip);
                res.status(429).json({ error: 'Too many authentication attempts' });
            }
        }));
    }

    getHelmetOptions() {
        return {
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    scriptSrc: ["'self'"],
                    imgSrc: ["'self'", "data:", "https:"],
                },
            },
            hsts: {
                maxAge: 31536000,
                includeSubDomains: true,
                preload: true
            },
            crossOriginEmbedderPolicy: false // Allow embedding for admin interfaces
        };
    }

    getCorsOptions() {
        const allowedOrigins = this.config.get('ALLOWED_ORIGINS').split(',');
        
        return {
            origin: (origin, callback) => {
                // Allow requests with no origin (mobile apps, etc.)
                if (!origin) return callback(null, true);
                
                if (allowedOrigins.includes(origin)) {
                    callback(null, true);
                } else {
                    this.logger.securityLog('CORS_VIOLATION', { origin }, null);
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            optionsSuccessStatus: 200,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
        };
    }

    // Security middleware factory
    createSecurityMiddleware() {
        return [
            helmet(this.getHelmetOptions()),
            cors(this.getCorsOptions())
        ];
    }

    // Get rate limiter by name
    getRateLimiter(name) {
        return this.rateLimiters.get(name);
    }

    // Input validation middleware
    validateInput() {
        return (req, res, next) => {
            // Basic input sanitization
            const sanitizeString = (str) => {
                if (typeof str !== 'string') return str;
                return str.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
            };

            const sanitizeObject = (obj) => {
                if (typeof obj !== 'object' || obj === null) return obj;
                
                const sanitized = {};
                for (const [key, value] of Object.entries(obj)) {
                    if (typeof value === 'string') {
                        sanitized[key] = sanitizeString(value);
                    } else if (typeof value === 'object') {
                        sanitized[key] = sanitizeObject(value);
                    } else {
                        sanitized[key] = value;
                    }
                }
                return sanitized;
            };

            // Sanitize request body
            if (req.body) {
                req.body = sanitizeObject(req.body);
            }

            // Sanitize query parameters
            if (req.query) {
                req.query = sanitizeObject(req.query);
            }

            next();
        };
    }

    // Request size limiter
    createRequestSizeLimiter(maxSize = '10mb') {
        return (req, res, next) => {
            const contentLength = parseInt(req.get('content-length') || '0');
            const maxBytes = this.parseSize(maxSize);
            
            if (contentLength > maxBytes) {
                this.logger.securityLog('REQUEST_TOO_LARGE', {
                    contentLength,
                    maxSize,
                    path: req.path
                }, req.ip);
                
                return res.status(413).json({ error: 'Request entity too large' });
            }
            
            next();
        };
    }

    // Parse size string to bytes
    parseSize(size) {
        const match = size.match(/^(\d+(?:\.\d+)?)\s*(kb|mb|gb)?$/i);
        if (!match) return 0;
        
        const value = parseFloat(match[1]);
        const unit = (match[2] || 'b').toLowerCase();
        
        const multipliers = {
            b: 1,
            kb: 1024,
            mb: 1024 * 1024,
            gb: 1024 * 1024 * 1024
        };
        
        return Math.floor(value * (multipliers[unit] || 1));
    }

    // Security headers middleware
    securityHeaders() {
        return (req, res, next) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('X-XSS-Protection', '1; mode=block');
            res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
            
            if (this.config.isProduction()) {
                res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
            }
            
            next();
        };
    }

    // Block common attack patterns
    blockSuspiciousRequests() {
        const suspiciousPatterns = [
            /\.\.\//,  // Directory traversal
            /\/proc\//,  // Linux proc filesystem
            /\/etc\//,   // System configuration
            /<script/i,  // Script injection
            /union.*select/i,  // SQL injection
            /exec\s*\(/i,  // Code execution
        ];

        return (req, res, next) => {
            const checkString = `${req.url} ${JSON.stringify(req.body)} ${JSON.stringify(req.query)}`;
            
            for (const pattern of suspiciousPatterns) {
                if (pattern.test(checkString)) {
                    this.logger.securityLog('SUSPICIOUS_REQUEST', {
                        pattern: pattern.toString(),
                        url: req.url,
                        method: req.method
                    }, req.ip);
                    
                    return res.status(400).json({ error: 'Invalid request' });
                }
            }
            
            next();
        };
    }
}

module.exports = SecurityManager;