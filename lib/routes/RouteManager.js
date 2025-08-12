// framework/lib/routes/RouteManager.js
const express = require('express');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class RouteManager {
    constructor(config, logger, auth, executor) {
        this.config = config;
        this.logger = logger;
        this.auth = auth;
        this.executor = executor;
        this.routes = new Map();
        this.app = null;
    }

    setup(app) {
        this.logger.info('Setting up API routes...');
        this.app = app;

        // Setup core routes
        this.setupHealthRoutes();
        this.setupAuthRoutes();
        this.setupSystemRoutes();
        this.setupCommandRoutes();
        this.setupLogRoutes();
        this.setupSessionRoutes();

        // Setup error handling (must be last)
        this.setupErrorHandling();

        this.logger.info(`Registered ${this.routes.size} route groups`);
    }

    // Create router with logging
    createRouter(name) {
        const router = express.Router();
        this.logger.debug(`Creating router: ${name}`);
        return router;
    }

    // Get authentication middleware
    getAuthMiddleware() {
        return [this.auth.createAuthMiddleware()];
    }

    // Get admin middleware
    getAdminMiddleware() {
        return [
            this.auth.createAuthMiddleware(),
            this.auth.createRoleMiddleware('admin')
        ];
    }

    // Health and status routes
    setupHealthRoutes() {
        const router = this.createRouter('health');

        // Basic health check
        router.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                timestamp: new Date().toISOString(),
                uptime: process.uptime(),
                version: process.version,
                environment: this.config.get('NODE_ENV'),
                requestId: req.id
            });
        });

        // Detailed system status (authenticated)
        router.get('/status', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const status = await this.getSystemStatus();
                
                this.logger.auditLog(req.user.username, 'STATUS_ACCESS', {}, req.ip, true);
                
                res.json({
                    ...status,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Status check failed:', error);
                res.status(500).json({ error: 'Status check failed' });
            }
        });

        this.app.use('/api', router);
        this.routes.set('health', router);
    }

    // Authentication routes
    setupAuthRoutes() {
        const router = this.createRouter('auth');

        // Login
        router.post('/login', async (req, res) => {
            await this.auth.handleLogin(req, res);
        });

        // Logout
        router.post('/logout', ...this.getAuthMiddleware(), async (req, res) => {
            await this.auth.handleLogout(req, res);
        });

        // Get current user info
        router.get('/me', ...this.getAuthMiddleware(), (req, res) => {
            this.auth.handleUserInfo(req, res);
        });

        // Refresh token
        router.post('/refresh', ...this.getAuthMiddleware(), (req, res) => {
            try {
                const tokenInfo = this.auth.generateToken(req.user);
                
                res.json({
                    success: true,
                    token: tokenInfo.token,
                    expiresIn: tokenInfo.expiresIn
                });
            } catch (error) {
                this.logger.error('Token refresh failed:', error);
                res.status(500).json({ error: 'Token refresh failed' });
            }
        });

        this.app.use('/api/auth', router);
        this.routes.set('auth', router);
    }

    // System information routes
    setupSystemRoutes() {
        const router = this.createRouter('system');

        // System information
        router.get('/info', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const [uptime, memory, disk, load] = await Promise.all([
                    execPromise('uptime'),
                    execPromise('free -h'),
                    execPromise('df -h'),
                    execPromise('cat /proc/loadavg')
                ]);

                this.logger.auditLog(req.user.username, 'SYSTEM_INFO_ACCESS', {}, req.ip, true);

                res.json({
                    uptime: uptime.stdout.trim(),
                    memory: memory.stdout,
                    disk: disk.stdout,
                    load: load.stdout.trim(),
                    timestamp: new Date().toISOString(),
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('System info error:', error);
                res.status(500).json({ error: 'Failed to get system info' });
            }
        });

        // Process list
        router.get('/processes', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const { limit = 20 } = req.query;
                const { stdout } = await execPromise(`ps aux --sort=-%cpu | head -${parseInt(limit) + 1}`);

                this.logger.auditLog(req.user.username, 'PROCESS_LIST_ACCESS', { limit }, req.ip, true);

                const lines = stdout.split('\n').filter(line => line);
                const processes = lines.slice(1).map(line => {
                    const values = line.split(/\s+/);
                    return {
                        user: values[0],
                        pid: values[1],
                        cpu: values[2],
                        mem: values[3],
                        vsz: values[4],
                        rss: values[5],
                        tty: values[6],
                        stat: values[7],
                        start: values[8],
                        time: values[9],
                        command: values.slice(10).join(' ')
                    };
                });

                res.json({
                    processes,
                    total: processes.length,
                    timestamp: new Date().toISOString(),
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Process monitoring error:', error);
                res.status(500).json({ error: 'Failed to get process list' });
            }
        });

        // Network connections
        router.get('/network/connections', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const { stdout } = await execPromise('ss -tuln');

                this.logger.auditLog(req.user.username, 'NETWORK_CONNECTIONS_ACCESS', {}, req.ip, true);

                res.json({
                    connections: stdout,
                    timestamp: new Date().toISOString(),
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Network connections error:', error);
                res.status(500).json({ error: 'Failed to get network connections' });
            }
        });

        // System metrics
        router.get('/metrics', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const metrics = await this.collectSystemMetrics();
                
                this.logger.auditLog(req.user.username, 'METRICS_ACCESS', {}, req.ip, true);
                
                res.json({
                    ...metrics,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Metrics collection error:', error);
                res.status(500).json({ error: 'Failed to collect metrics' });
            }
        });

        this.app.use('/api/system', router);
        this.routes.set('system', router);
    }

    // Command execution routes
    setupCommandRoutes() {
        const router = this.createRouter('commands');

        // Execute command
        router.post('/execute', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const { command } = req.body;

                if (!command) {
                    return res.status(400).json({ error: 'Command is required' });
                }

                // Validate command length
                if (command.length > 1000) {
                    return res.status(400).json({ error: 'Command too long' });
                }

                const result = await this.executor.execute(
                    command,
                    req.user.username,
                    req.ip
                );

                res.json({
                    ...result,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Command execution error:', error);
                res.status(400).json({
                    success: false,
                    error: error.message,
                    requestId: req.id
                });
            }
        });

        // Command history (admin only)
        router.get('/history', ...this.getAdminMiddleware(), async (req, res) => {
            try {
                const { limit = 50 } = req.query;
                const history = this.executor.getCommandHistory(parseInt(limit));

                this.logger.auditLog(req.user.username, 'COMMAND_HISTORY_ACCESS', { limit }, req.ip, true);

                res.json({
                    history,
                    total: history.length,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Command history error:', error);
                res.status(500).json({ error: 'Failed to get command history' });
            }
        });

        // Get allowed commands
        router.get('/allowed', ...this.getAuthMiddleware(), (req, res) => {
            const allowedCommands = this.executor.getAllowedCommands();
            const restrictMode = this.config.get('RESTRICT_COMMANDS') === 'true';

            res.json({
                restrictMode,
                allowedCommands: restrictMode ? allowedCommands : 'All commands allowed',
                requestId: req.id
            });
        });

        this.app.use('/api', router);
        this.routes.set('commands', router);
    }

    // Logging routes
    setupLogRoutes() {
        const router = this.createRouter('logs');

        // Get logs
        router.get('/', ...this.getAuthMiddleware(), async (req, res) => {
            try {
                const { type = 'combined', lines = 100 } = req.query;
                const validTypes = ['combined', 'error', 'security', 'audit'];

                if (!validTypes.includes(type)) {
                    return res.status(400).json({ error: 'Invalid log type' });
                }

                const logs = await this.logger.getLogs(type, parseInt(lines));

                this.logger.auditLog(req.user.username, 'LOG_ACCESS', { type, lines }, req.ip, true);

                res.json({
                    ...logs,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Log retrieval error:', error);
                res.status(500).json({ error: 'Failed to retrieve logs' });
            }
        });

        // Get log types
        router.get('/types', ...this.getAuthMiddleware(), (req, res) => {
            res.json({
                types: [
                    { name: 'combined', description: 'All log entries' },
                    { name: 'error', description: 'Error messages only' },
                    { name: 'security', description: 'Security-related events' },
                    { name: 'audit', description: 'Audit trail logs' }
                ],
                requestId: req.id
            });
        });

        // Search logs (admin only)
        router.post('/search', ...this.getAdminMiddleware(), async (req, res) => {
            try {
                const { query, type = 'combined', limit = 100 } = req.body;

                if (!query) {
                    return res.status(400).json({ error: 'Search query is required' });
                }

                const results = await this.searchLogs(query, type, limit);

                this.logger.auditLog(req.user.username, 'LOG_SEARCH', { query, type, limit }, req.ip, true);

                res.json({
                    results,
                    query,
                    type,
                    total: results.length,
                    requestId: req.id
                });
            } catch (error) {
                this.logger.error('Log search error:', error);
                res.status(500).json({ error: 'Log search failed' });
            }
        });

        this.app.use('/api/logs', router);
        this.routes.set('logs', router);
    }

    // Session management routes
    setupSessionRoutes() {
        const router = this.createRouter('sessions');

        // Get active sessions (admin only)
        router.get('/', ...this.getAdminMiddleware(), (req, res) => {
            this.auth.handleGetSessions(req, res);
        });

        // Revoke session (admin only)
        router.delete('/:tokenId', ...this.getAdminMiddleware(), (req, res) => {
            this.auth.handleRevokeSession(req, res);
        });

        // Get session statistics (admin only)
        router.get('/stats', ...this.getAdminMiddleware(), (req, res) => {
            const stats = this.auth.getStats();
            
            this.logger.auditLog(req.user.username, 'SESSION_STATS_ACCESS', {}, req.ip, true);
            
            res.json({
                ...stats,
                requestId: req.id
            });
        });

        this.app.use('/api/sessions', router);
        this.routes.set('sessions', router);
    }

    // Error handling setup
    setupErrorHandling() {
        // 404 handler
        this.app.use((req, res, next) => {
            if (req.path.startsWith('/api/')) {
                this.logger.warn({
                    type: 'NOT_FOUND',
                    path: req.path,
                    method: req.method,
                    ip: req.ip,
                    userAgent: req.get('user-agent'),
                    requestId: req.id
                });

                return res.status(404).json({
                    error: 'API endpoint not found',
                    path: req.path,
                    method: req.method,
                    requestId: req.id,
                    timestamp: new Date().toISOString()
                });
            }
            next();
        });

        // Global error handler
        this.app.use((err, req, res, next) => {
            const requestId = req.id;
            const errorId = require('uuid').v4();

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

            // Determine error response
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
            }

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
        });
    }

    // Helper methods
    async getSystemStatus() {
        try {
            const [health, load, memory] = await Promise.all([
                execPromise('uptime'),
                execPromise('cat /proc/loadavg'),
                execPromise('free -m')
            ]);

            return {
                status: 'operational',
                uptime: health.stdout.trim(),
                load: load.stdout.trim(),
                memory: this.parseMemoryInfo(memory.stdout),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`System status check failed: ${error.message}`);
        }
    }

    async collectSystemMetrics() {
        try {
            const [cpu, memory, disk, network] = await Promise.all([
                this.getCpuUsage(),
                this.getMemoryUsage(),
                this.getDiskUsage(),
                this.getNetworkStats()
            ]);

            return {
                cpu,
                memory,
                disk,
                network,
                nodejs: {
                    version: process.version,
                    uptime: process.uptime(),
                    memoryUsage: process.memoryUsage(),
                    platform: process.platform
                },
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Metrics collection failed: ${error.message}`);
        }
    }

    async getCpuUsage() {
        try {
            const { stdout } = await execPromise("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1");
            return {
                usage: parseFloat(stdout.trim()) || 0,
                cores: require('os').cpus().length
            };
        } catch (error) {
            return { usage: 0, cores: 1, error: error.message };
        }
    }

    async getMemoryUsage() {
        try {
            const { stdout } = await execPromise('free -m');
            const lines = stdout.split('\n');
            const memLine = lines[1].split(/\s+/);
            
            return {
                total: parseInt(memLine[1]),
                used: parseInt(memLine[2]),
                free: parseInt(memLine[3]),
                percentage: Math.round((parseInt(memLine[2]) / parseInt(memLine[1])) * 100)
            };
        } catch (error) {
            return { error: error.message };
        }
    }

    async getDiskUsage() {
        try {
            const { stdout } = await execPromise("df -h / | tail -1 | awk '{print $5}' | cut -d'%' -f1");
            return {
                percentage: parseInt(stdout.trim()) || 0
            };
        } catch (error) {
            return { error: error.message };
        }
    }

    async getNetworkStats() {
        try {
            const { stdout } = await execPromise('cat /proc/net/dev');
            const lines = stdout.split('\n').slice(2);
            const interfaces = lines
                .filter(line => line.trim())
                .map(line => {
                    const parts = line.trim().split(/\s+/);
                    return {
                        interface: parts[0].replace(':', ''),
                        rx_bytes: parseInt(parts[1]),
                        tx_bytes: parseInt(parts[9])
                    };
                });
            
            return { interfaces };
        } catch (error) {
            return { error: error.message };
        }
    }

    parseMemoryInfo(memoryOutput) {
        const lines = memoryOutput.split('\n');
        const memLine = lines[1].split(/\s+/);
        
        return {
            total: `${memLine[1]}MB`,
            used: `${memLine[2]}MB`,
            free: `${memLine[3]}MB`,
            percentage: Math.round((parseInt(memLine[2]) / parseInt(memLine[1])) * 100)
        };
    }

    async searchLogs(query, type, limit) {
        try {
            const logFile = this.logger.getLogPath(type);
            const { stdout } = await execPromise(`grep -i "${query}" "${logFile}" | tail -${limit}`);
            
            return stdout.split('\n').filter(line => line.trim());
        } catch (error) {
            return [];
        }
    }

    // Add custom route
    addRoute(method, path, middleware, handler) {
        if (!this.app) {
            throw new Error('Router not initialized');
        }

        this.app[method.toLowerCase()](path, middleware, handler);
        this.logger.info(`Added custom route: ${method.toUpperCase()} ${path}`);
    }

    // Get route information
    getRoutes() {
        return Array.from(this.routes.keys());
    }
}

module.exports = RouteManager;