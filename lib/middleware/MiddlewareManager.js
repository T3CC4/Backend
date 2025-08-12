// framework/lib/middleware/MiddlewareManager.js
const express = require('express');
const morgan = require('morgan');
const { v4: uuidv4 } = require('uuid');

class MiddlewareManager {
    constructor(config, logger, security, auth) {
        this.config = config;
        this.logger = logger;
        this.security = security;
        this.auth = auth;
    }

    setup(app) {
        this.logger.info('Setting up middleware stack...');

        // Trust proxy (for apps behind reverse proxy)
        app.set('trust proxy', 1);

        // Request ID middleware (first)
        app.use(this.createRequestIdMiddleware());

        // Security middleware
        app.use(...this.security.createSecurityMiddleware());

        // Rate limiting
        app.use('/api/', this.security.getRateLimiter('api'));
        app.use('/api/auth/', this.security.getRateLimiter('auth'));

        // Body parsing with size limits
        app.use(express.json({ 
            limit: '10mb',
            verify: this.createBodyVerificationMiddleware()
        }));
        app.use(express.urlencoded({ 
            extended: true, 
            limit: '10mb',
            verify: this.createBodyVerificationMiddleware()
        }));

        // HTTP request logging
        app.use(this.createHttpLoggingMiddleware());

        // Request timing middleware
        app.use(this.createTimingMiddleware());

        // Input validation and sanitization
        app.use(this.security.validateInput());
        app.use(this.security.blockSuspiciousRequests());

        // Additional security headers
        app.use(this.security.securityHeaders());

        // Request size limiter
        app.use(this.security.createRequestSizeLimiter('10mb'));

        // CORS preflight handler
        app.use(this.createCorsPreflightMiddleware());

        this.logger.info('Middleware stack configured successfully');
    }

    // Generate unique request ID
    createRequestIdMiddleware() {
        return (req, res, next) => {
            req.id = req.headers['x-request-id'] || uuidv4();
            res.setHeader('X-Request-Id', req.id);
            
            // Add request start time
            req.startTime = Date.now();
            
            next();
        };
    }

    // Body verification for JSON parsing
    createBodyVerificationMiddleware() {
        return (req, buf, encoding) => {
            // Log large requests
            if (buf.length > 1024 * 1024) { // 1MB
                this.logger.warn({
                    type: 'LARGE_REQUEST_BODY',
                    size: buf.length,
                    path: req.path,
                    ip: req.ip,
                    requestId: req.id
                });
            }

            // Validate JSON structure depth to prevent DoS
            try {
                if (req.headers['content-type']?.includes('application/json')) {
                    const json = JSON.parse(buf.toString(encoding));
                    const depth = this.getObjectDepth(json);
                    
                    if (depth > 10) {
                        throw new Error('JSON structure too deep');
                    }
                }
            } catch (error) {
                if (error.message === 'JSON structure too deep') {
                    this.logger.securityLog('DEEP_JSON_ATTACK', {
                        path: req.path,
                        size: buf.length
                    }, req.ip);
                    throw error;
                }
                // Let normal JSON parsing errors be handled by Express
            }
        };
    }

    // HTTP request logging with Morgan
    createHttpLoggingMiddleware() {
        return morgan('combined', {
            stream: this.logger.createMorganStream(),
            skip: (req, res) => {
                // Skip health check logs in production to reduce noise
                return this.config.isProduction() && req.path === '/api/health';
            }
        });
    }

    // Request timing middleware
    createTimingMiddleware() {
        return (req, res, next) => {
            const startTime = Date.now();

            // Override res.end to capture response time
            const originalEnd = res.end;
            res.end = function(...args) {
                const responseTime = Date.now() - startTime;
                res.responseTime = responseTime;

                // Log slow requests
                if (responseTime > 5000) { // 5 seconds
                    req.app.locals.logger?.warn({
                        type: 'SLOW_REQUEST',
                        path: req.path,
                        method: req.method,
                        responseTime,
                        requestId: req.id
                    });
                }

                // Set response time header
                res.setHeader('X-Response-Time', `${responseTime}ms`);

                originalEnd.apply(res, args);
            };

            next();
        };
    }

    // CORS preflight handling
    createCorsPreflightMiddleware() {
        return (req, res, next) => {
            if (req.method === 'OPTIONS') {
                // Log preflight requests
                this.logger.debug({
                    type: 'CORS_PREFLIGHT',
                    origin: req.headers.origin,
                    requestedMethod: req.headers['access-control-request-method'],
                    requestedHeaders: req.headers['access-control-request-headers']
                });
            }
            next();
        };
    }

    // Error handling middleware
    createErrorMiddleware() {
        return (err, req, res, next) => {
            const requestId = req.id;
            const errorId = uuidv4();

            // Log the error
            this.logger.error({
                type: 'REQUEST_ERROR',
                errorId,
                requestId,
                error: err.message,
                stack: err.stack,
                path: req.path,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('user-agent'),
                timestamp: new Date().toISOString()
            });

            // Determine error response based on error type
            let statusCode = 500;
            let message = 'Internal server error';

            if (err.name === 'ValidationError') {
                statusCode = 400;
                message = 'Validation error';
            } else if (err.name === 'UnauthorizedError' || err.message.includes('Authentication')) {
                statusCode = 401;
                message = 'Authentication required';
            } else if (err.name === 'ForbiddenError' || err.message.includes('permissions')) {
                statusCode = 403;
                message = 'Insufficient permissions';
            } else if (err.name === 'NotFoundError') {
                statusCode = 404;
                message = 'Resource not found';
            } else if (err.message === 'JSON structure too deep') {
                statusCode = 400;
                message = 'Invalid request structure';
            }

            // Security: Don't expose internal error details in production
            const response = {
                error: message,
                requestId,
                timestamp: new Date().toISOString()
            };

            if (this.config.isDevelopment()) {
                response.details = err.message;
                response.errorId = errorId;
            }

            res.status(statusCode).json(response);
        };
    }

    // Not found middleware (404 handler)
    createNotFoundMiddleware() {
        return (req, res) => {
            this.logger.warn({
                type: 'NOT_FOUND',
                path: req.path,
                method: req.method,
                ip: req.ip,
                userAgent: req.get('user-agent'),
                requestId: req.id
            });

            res.status(404).json({
                error: 'Endpoint not found',
                path: req.path,
                requestId: req.id,
                timestamp: new Date().toISOString()
            });
        };
    }

    // Request context middleware (adds useful request info)
    createContextMiddleware() {
        return (req, res, next) => {
            // Add framework references to request
            req.framework = {
                config: this.config,
                logger: this.logger,
                security: this.security,
                auth: this.auth
            };

            // Add helper methods
            req.getClientIP = () => {
                return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
                       req.headers['x-real-ip'] || 
                       req.connection.remoteAddress || 
                       req.ip;
            };

            req.isSecure = () => {
                return req.secure || 
                       req.headers['x-forwarded-proto'] === 'https';
            };

            req.getUserAgent = () => {
                return req.headers['user-agent'] || 'Unknown';
            };

            next();
        };
    }

    // Health check middleware (bypasses most other middleware)
    createHealthCheckMiddleware() {
        return (req, res, next) => {
            if (req.path === '/api/health') {
                return res.json({
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    uptime: process.uptime(),
                    version: process.version,
                    requestId: req.id
                });
            }
            next();
        };
    }

    // Maintenance mode middleware
    createMaintenanceMiddleware() {
        return (req, res, next) => {
            if (this.config.get('MAINTENANCE_MODE') === 'true') {
                // Allow health checks and admin access during maintenance
                if (req.path === '/api/health' || req.user?.role === 'admin') {
                    return next();
                }

                return res.status(503).json({
                    error: 'Service temporarily unavailable',
                    message: 'System is under maintenance',
                    requestId: req.id
                });
            }
            next();
        };
    }

    // Utility method to calculate object depth
    getObjectDepth(obj) {
        if (typeof obj !== 'object' || obj === null) {
            return 0;
        }

        let maxDepth = 0;
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                const depth = this.getObjectDepth(obj[key]) + 1;
                maxDepth = Math.max(maxDepth, depth);
            }
        }
        return maxDepth;
    }

    // Get middleware stack for specific route patterns
    getAuthenticatedMiddleware() {
        return [
            this.auth.createAuthMiddleware()
        ];
    }

    getAdminMiddleware() {
        return [
            this.auth.createAuthMiddleware(),
            this.auth.createRoleMiddleware('admin')
        ];
    }

    // Cleanup middleware (for graceful shutdown)
    createCleanupMiddleware() {
        return (req, res, next) => {
            // Set Connection: close header during shutdown
            if (this.isShuttingDown) {
                res.setHeader('Connection', 'close');
            }
            next();
        };
    }

    // Signal shutdown to middleware
    signalShutdown() {
        this.isShuttingDown = true;
        this.logger.info('Middleware manager signaled for shutdown');
    }
}

module.exports = MiddlewareManager;