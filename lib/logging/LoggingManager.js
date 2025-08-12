// framework/lib/logging/LoggingManager.js
const winston = require('winston');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');

class LoggingManager {
    constructor(config) {
        this.config = config;
        this.logger = null;
        this.logDir = config.get('LOG_DIR', './logs');
    }

    async initialize() {
        // Create log directory if it doesn't exist
        try {
            await fs.mkdir(this.logDir, { recursive: true });
        } catch (error) {
            // Directory might already exist, ignore
        }

        // Create Winston logger
        this.logger = winston.createLogger({
            level: this.config.get('LOG_LEVEL', 'info'),
            format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.errors({ stack: true }),
                winston.format.json()
            ),
            transports: this.createTransports()
        });

        // Add development console output
        if (this.config.isDevelopment()) {
            this.logger.add(new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.colorize(),
                    winston.format.simple()
                )
            }));
        }
    }

    createTransports() {
        const transports = [];

        // Production console transport (structured)
        if (!this.config.isDevelopment()) {
            transports.push(new winston.transports.Console({
                format: winston.format.combine(
                    winston.format.timestamp(),
                    winston.format.json()
                )
            }));
        }

        // File transports (only if log directory is writable)
        const fileTransportOptions = {
            maxsize: 10485760, // 10MB
            maxFiles: 10
        };

        try {
            transports.push(
                new winston.transports.File({ 
                    filename: path.join(this.logDir, 'combined.log'),
                    ...fileTransportOptions
                }),
                new winston.transports.File({ 
                    filename: path.join(this.logDir, 'error.log'), 
                    level: 'error',
                    ...fileTransportOptions
                }),
                new winston.transports.File({ 
                    filename: path.join(this.logDir, 'security.log'),
                    level: 'warn',
                    ...fileTransportOptions
                }),
                new winston.transports.File({
                    filename: path.join(this.logDir, 'audit.log'),
                    level: 'info',
                    ...fileTransportOptions
                })
            );
        } catch (error) {
            console.warn('Could not create file transports, using console only:', error.message);
        }

        return transports;
    }

    // Audit logging with structured format
    auditLog(userId, action, details = {}, ip = null, success = true) {
        this.info({
            type: 'AUDIT',
            timestamp: new Date().toISOString(),
            userId,
            action,
            details,
            ip,
            success,
            sessionId: uuidv4()
        });
    }

    // Security event logging
    securityLog(type, details = {}, ip = null) {
        this.warn({
            type: 'SECURITY',
            subType: type,
            timestamp: new Date().toISOString(),
            details,
            ip,
            sessionId: uuidv4()
        });
    }

    // Request logging
    requestLog(req, res = null) {
        const logData = {
            type: 'REQUEST',
            requestId: req.id || uuidv4(),
            method: req.method,
            path: req.path,
            ip: req.ip,
            userAgent: req.get('user-agent'),
            timestamp: new Date().toISOString()
        };

        if (res) {
            logData.statusCode = res.statusCode;
            logData.responseTime = res.responseTime;
        }

        this.info(logData);
    }

    // Command execution logging
    commandLog(commandId, userId, command, success, details = {}, ip = null) {
        this.info({
            type: success ? 'COMMAND_SUCCESS' : 'COMMAND_FAILURE',
            commandId,
            userId,
            ip,
            command: success ? command : '[SANITIZED]',
            details,
            timestamp: new Date().toISOString()
        });
    }

    // Winston proxy methods
    error(message, meta = {}) {
        if (this.logger) {
            this.logger.error(message, meta);
        } else {
            console.error(message, meta);
        }
    }

    warn(message, meta = {}) {
        if (this.logger) {
            this.logger.warn(message, meta);
        } else {
            console.warn(message, meta);
        }
    }

    info(message, meta = {}) {
        if (this.logger) {
            this.logger.info(message, meta);
        } else {
            console.info(message, meta);
        }
    }

    debug(message, meta = {}) {
        if (this.logger) {
            this.logger.debug(message, meta);
        } else {
            console.debug(message, meta);
        }
    }

    // Get logs (for API endpoint)
    async getLogs(type = 'combined', lines = 100) {
        const validTypes = ['combined', 'error', 'security', 'audit'];
        
        if (!validTypes.includes(type)) {
            throw new Error('Invalid log type');
        }

        const logFile = path.join(this.logDir, `${type}.log`);
        
        try {
            const { exec } = require('child_process');
            const util = require('util');
            const execPromise = util.promisify(exec);
            
            const { stdout } = await execPromise(`tail -n ${parseInt(lines)} "${logFile}"`);
            
            return {
                type,
                lines: stdout.split('\n').filter(line => line.trim()),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to read log file: ${error.message}`);
        }
    }

    // Create morgan stream for HTTP logging
    createMorganStream() {
        return {
            write: (message) => {
                this.info(message.trim());
            }
        };
    }
}

module.exports = LoggingManager;