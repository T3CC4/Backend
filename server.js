// framework/index.js - Main Framework Entry Point
const express = require('express');
const SecurityManager = require('./lib/security/SecurityManager');
const AuthenticationManager = require('./lib/auth/AuthenticationManager');
const CommandExecutor = require('./lib/execution/CommandExecutor');
const LoggingManager = require('./lib/logging/LoggingManager');
const ConfigManager = require('./lib/config/ConfigManager');
const MiddlewareManager = require('./lib/middleware/MiddlewareManager');
const RouteManager = require('./lib/routes/RouteManager');
const ClientManager = require('./lib/clients/ClientManager');
const ClientRoutes = require('./lib/routes/ClientRoutes');

class SecureBackendFramework {
    constructor(options = {}) {
        this.config = new ConfigManager(options);
        this.app = express();
        this.logger = new LoggingManager(this.config);
        this.security = new SecurityManager(this.config, this.logger);
        this.auth = new AuthenticationManager(this.config, this.logger);
        this.executor = new CommandExecutor(this.config, this.logger);
        this.clientManager = new ClientManager(this.config, this.logger);
        this.middleware = new MiddlewareManager(this.config, this.logger, this.security, this.auth);
        this.routes = new RouteManager(this.config, this.logger, this.auth, this.executor);
        this.clientRoutes = new ClientRoutes(this.config, this.logger, this.auth, this.clientManager);
        
        this.server = null;
        this.isInitialized = false;
    }

    async initialize() {
        if (this.isInitialized) {
            throw new Error('Framework already initialized');
        }

        try {
            // Initialize logging first
            await this.logger.initialize();
            this.logger.info('Initializing Secure Backend Framework...');

            // Initialize security
            await this.security.initialize();

            // Initialize authentication
            await this.auth.initialize();

            // Initialize client manager
            await this.clientManager.initialize();

            // Setup middleware
            this.middleware.setup(this.app);

            // Setup main routes
            this.routes.setup(this.app);

            // Setup client management routes
            this.app.use('/api/clients', this.clientRoutes.createRoutes());

            // Setup error handling
            this.setupErrorHandling();

            // Setup graceful shutdown
            this.setupGracefulShutdown();

            this.isInitialized = true;
            this.logger.info('Framework initialization complete');

        } catch (error) {
            this.logger.error('Framework initialization failed:', error);
            throw error;
        }
    }

    setupErrorHandling() {
        // Global error handler
        this.app.use((err, req, res, next) => {
            this.logger.error({
                type: 'UNHANDLED_ERROR',
                requestId: req.id,
                error: err.message,
                stack: err.stack,
                timestamp: new Date().toISOString()
            });
            
            res.status(500).json({
                error: 'Internal server error',
                requestId: req.id
            });
        });

        // Handle uncaught exceptions
        process.on('uncaughtException', (error) => {
            this.logger.error('Uncaught Exception:', error);
            this.gracefulShutdown();
        });

        process.on('unhandledRejection', (reason, promise) => {
            this.logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
        });
    }

    setupGracefulShutdown() {
        const gracefulShutdown = () => {
            this.logger.info('Received shutdown signal, closing server gracefully...');
            
            if (this.server) {
                this.server.close(() => {
                    this.logger.info('Server closed');
                    process.exit(0);
                });

                // Force close after 30 seconds
                setTimeout(() => {
                    this.logger.error('Could not close connections in time, forcefully shutting down');
                    process.exit(1);
                }, 30000);
            } else {
                process.exit(0);
            }
        };

        process.on('SIGTERM', gracefulShutdown);
        process.on('SIGINT', gracefulShutdown);
    }

    async start() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        const port = this.config.get('PORT', 3000);
        const host = this.config.get('HOST', '0.0.0.0');

        return new Promise((resolve, reject) => {
            this.server = this.app.listen(port, host, (err) => {
                if (err) {
                    this.logger.error('Failed to start server:', err);
                    reject(err);
                } else {
                    this.logger.info(`Secure Backend Framework started on ${host}:${port}`);
                    this.logger.info('Security features: Helmet, CORS, Rate Limiting, JWT Authentication');
                    resolve(this.server);
                }
            });
        });
    }

    async stop() {
        if (this.server) {
            return new Promise((resolve) => {
                this.server.close(() => {
                    this.logger.info('Server stopped');
                    resolve();
                });
            });
        }
    }

    // Plugin system
    use(plugin) {
        if (typeof plugin === 'function') {
            plugin(this);
        } else if (plugin && typeof plugin.install === 'function') {
            plugin.install(this);
        } else {
            throw new Error('Invalid plugin format');
        }
        return this;
    }

    // Getters for framework components
    getApp() { return this.app; }
    getLogger() { return this.logger; }
    getConfig() { return this.config; }
    getSecurity() { return this.security; }
    getAuth() { return this.auth; }
    getExecutor() { return this.executor; }
    getClientManager() { return this.clientManager; }
}

module.exports = SecureBackendFramework;