// framework/lib/auth/AuthenticationManager.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

class AuthenticationManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.activeSessions = new Map();
        this.blacklistedTokens = new Set();
    }

    async initialize() {
        this.logger.info('Initializing authentication system...');
        
        // Clean up expired sessions periodically
        setInterval(() => {
            this.cleanupExpiredSessions();
        }, 60000); // Every minute
    }

    // Verify user credentials
    async verifyCredentials(username, password) {
        const adminUsername = this.config.get('ADMIN_USERNAME');
        const adminPasswordHash = this.config.get('ADMIN_PASSWORD_HASH');

        // Check username
        if (username !== adminUsername) {
            return { success: false, reason: 'Invalid username' };
        }

        // Check password
        try {
            const isValid = await bcrypt.compare(password, adminPasswordHash);
            if (!isValid) {
                return { success: false, reason: 'Invalid password' };
            }

            return { success: true, user: { username, role: 'admin' } };
        } catch (error) {
            this.logger.error('Password verification error:', error);
            return { success: false, reason: 'Authentication error' };
        }
    }

    // Generate JWT token
    generateToken(user, expiresIn = null) {
        const payload = {
            username: user.username,
            role: user.role || 'user',
            iat: Math.floor(Date.now() / 1000),
            jti: uuidv4() // JWT ID for token tracking
        };

        const options = {
            expiresIn: expiresIn || this.config.get('JWT_EXPIRES_IN', '24h'),
            issuer: 'SecureBackendFramework',
            audience: 'framework-users'
        };

        const token = jwt.sign(payload, this.config.get('JWT_SECRET'), options);

        // Store session information
        this.activeSessions.set(payload.jti, {
            username: user.username,
            role: user.role,
            createdAt: new Date(),
            lastActivity: new Date(),
            tokenId: payload.jti
        });

        return {
            token,
            tokenId: payload.jti,
            expiresIn: this.parseExpirationTime(options.expiresIn)
        };
    }

    // Verify JWT token
    async verifyToken(token) {
        try {
            // Check if token is blacklisted
            if (this.blacklistedTokens.has(token)) {
                throw new Error('Token has been revoked');
            }

            const decoded = jwt.verify(token, this.config.get('JWT_SECRET'), {
                issuer: 'SecureBackendFramework',
                audience: 'framework-users'
            });

            // Check if session exists
            const session = this.activeSessions.get(decoded.jti);
            if (!session) {
                throw new Error('Session not found');
            }

            // Update last activity
            session.lastActivity = new Date();

            return {
                success: true,
                user: {
                    username: decoded.username,
                    role: decoded.role,
                    tokenId: decoded.jti
                },
                session
            };
        } catch (error) {
            return {
                success: false,
                error: error.message
            };
        }
    }

    // Authentication middleware
    createAuthMiddleware() {
        return async (req, res, next) => {
            try {
                const authHeader = req.headers.authorization;
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    throw new Error('No valid authorization header');
                }

                const token = authHeader.split(' ')[1];
                const verification = await this.verifyToken(token);

                if (!verification.success) {
                    throw new Error(verification.error);
                }

                // Attach user info to request
                req.user = verification.user;
                req.session = verification.session;

                // Log successful authentication
                this.logger.debug({
                    type: 'AUTH_SUCCESS',
                    username: req.user.username,
                    ip: req.ip,
                    path: req.path,
                    timestamp: new Date().toISOString()
                });

                next();
            } catch (error) {
                // Log authentication failure
                this.logger.securityLog('AUTH_FAILURE', {
                    error: error.message,
                    path: req.path,
                    method: req.method
                }, req.ip);

                res.status(401).json({ 
                    error: 'Authentication required',
                    details: error.message 
                });
            }
        };
    }

    // Role-based authorization middleware
    createRoleMiddleware(requiredRole) {
        return (req, res, next) => {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            if (req.user.role !== requiredRole && req.user.role !== 'admin') {
                this.logger.securityLog('AUTHORIZATION_FAILURE', {
                    username: req.user.username,
                    requiredRole,
                    userRole: req.user.role,
                    path: req.path
                }, req.ip);

                return res.status(403).json({ error: 'Insufficient permissions' });
            }

            next();
        };
    }

    // Login handler
    async handleLogin(req, res) {
        const startTime = Date.now();
        const { username, password } = req.body;

        // Input validation
        if (!username || !password) {
            this.logger.securityLog('LOGIN_INVALID_INPUT', { username }, req.ip);
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Verify credentials
        const verification = await this.verifyCredentials(username, password);
        
        if (!verification.success) {
            this.logger.auditLog(username, 'LOGIN_FAILURE', { 
                reason: verification.reason,
                duration: Date.now() - startTime 
            }, req.ip, false);

            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const tokenInfo = this.generateToken(verification.user);

        // Log successful login
        this.logger.auditLog(username, 'LOGIN_SUCCESS', {
            tokenId: tokenInfo.tokenId,
            duration: Date.now() - startTime
        }, req.ip, true);

        res.json({
            success: true,
            token: tokenInfo.token,
            expiresIn: tokenInfo.expiresIn,
            user: {
                username: verification.user.username,
                role: verification.user.role
            }
        });
    }

    // Logout handler
    async handleLogout(req, res) {
        try {
            const tokenId = req.user?.tokenId;
            const username = req.user?.username;

            if (tokenId) {
                // Remove from active sessions
                this.activeSessions.delete(tokenId);
                
                // Add to blacklist (optional, for extra security)
                const authHeader = req.headers.authorization;
                if (authHeader) {
                    const token = authHeader.split(' ')[1];
                    this.blacklistedTokens.add(token);
                }
            }

            this.logger.auditLog(username, 'LOGOUT_SUCCESS', { tokenId }, req.ip, true);

            res.json({ success: true, message: 'Logged out successfully' });
        } catch (error) {
            this.logger.error('Logout error:', error);
            res.status(500).json({ error: 'Logout failed' });
        }
    }

    // Get current user info
    handleUserInfo(req, res) {
        const session = this.activeSessions.get(req.user.tokenId);
        
        res.json({
            user: {
                username: req.user.username,
                role: req.user.role
            },
            session: {
                createdAt: session?.createdAt,
                lastActivity: session?.lastActivity
            }
        });
    }

    // Get active sessions (admin only)
    handleGetSessions(req, res) {
        const sessions = Array.from(this.activeSessions.values()).map(session => ({
            username: session.username,
            role: session.role,
            createdAt: session.createdAt,
            lastActivity: session.lastActivity,
            tokenId: session.tokenId
        }));

        res.json({
            sessions,
            total: sessions.length,
            blacklistedTokens: this.blacklistedTokens.size
        });
    }

    // Revoke session (admin only)
    handleRevokeSession(req, res) {
        const { tokenId } = req.params;
        
        if (this.activeSessions.has(tokenId)) {
            const session = this.activeSessions.get(tokenId);
            this.activeSessions.delete(tokenId);
            
            this.logger.auditLog(req.user.username, 'SESSION_REVOKED', {
                revokedTokenId: tokenId,
                revokedUsername: session.username
            }, req.ip, true);

            res.json({ success: true, message: 'Session revoked' });
        } else {
            res.status(404).json({ error: 'Session not found' });
        }
    }

    // Utility methods
    parseExpirationTime(expiresIn) {
        if (typeof expiresIn === 'number') {
            return expiresIn;
        }
        
        const match = expiresIn.match(/^(\d+)([smhd])$/);
        if (!match) return 86400; // Default to 24 hours
        
        const value = parseInt(match[1]);
        const unit = match[2];
        
        const multipliers = { s: 1, m: 60, h: 3600, d: 86400 };
        return value * (multipliers[unit] || 3600);
    }

    cleanupExpiredSessions() {
        const now = Date.now();
        const expiredSessions = [];

        this.activeSessions.forEach((session, tokenId) => {
            const expiry = this.parseExpirationTime(this.config.get('JWT_EXPIRES_IN', '24h')) * 1000;
            if (now - session.createdAt.getTime() > expiry) {
                expiredSessions.push(tokenId);
            }
        });

        expiredSessions.forEach(tokenId => {
            const session = this.activeSessions.get(tokenId);
            this.activeSessions.delete(tokenId);
            this.logger.debug(`Cleaned up expired session: ${session?.username}`);
        });

        if (expiredSessions.length > 0) {
            this.logger.debug(`Cleaned up ${expiredSessions.length} expired sessions`);
        }
    }

    // Get authentication statistics
    getStats() {
        return {
            activeSessions: this.activeSessions.size,
            blacklistedTokens: this.blacklistedTokens.size,
            sessionDetails: Array.from(this.activeSessions.values()).map(session => ({
                username: session.username,
                role: session.role,
                createdAt: session.createdAt,
                lastActivity: session.lastActivity
            }))
        };
    }

    // Convenience methods for middleware
    getAuthMiddleware() {
        return [this.createAuthMiddleware()];
    }

    getAdminMiddleware() {
        return [
            this.createAuthMiddleware(),
            this.createRoleMiddleware('admin')
        ];
    }
}

module.exports = AuthenticationManager;