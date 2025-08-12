const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const morgan = require('morgan');
const { exec, spawn } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');

// Environment configuration
require('dotenv').config();

const app = express();

// Trust proxy (nginx)
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || bcrypt.hashSync('changeme', 10);

// Winston Logger Configuration
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        // Write all logs to console
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        // Write all logs to combined.log
        new winston.transports.File({ 
            filename: '/var/log/nodejs/combined.log',
            maxsize: 10485760, // 10MB
            maxFiles: 10
        }),
        // Write error logs to error.log
        new winston.transports.File({ 
            filename: '/var/log/nodejs/error.log', 
            level: 'error',
            maxsize: 10485760,
            maxFiles: 10
        }),
        // Write security events to security.log
        new winston.transports.File({ 
            filename: '/var/log/nodejs/security.log',
            level: 'warn',
            maxsize: 10485760,
            maxFiles: 10
        }),
        // Write audit logs
        new winston.transports.File({
            filename: '/var/log/nodejs/audit.log',
            level: 'info',
            maxsize: 10485760,
            maxFiles: 10
        })
    ]
});

// Audit Logger
const auditLog = (userId, action, details, ip, success = true) => {
    logger.info({
        type: 'AUDIT',
        timestamp: new Date().toISOString(),
        userId,
        action,
        details,
        ip,
        success,
        sessionId: uuidv4()
    });
};

// Security Middleware
app.use(helmet({
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
    }
}));

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true,
    optionsSuccessStatus: 200
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    trustProxy: true, // Trust the proxy to get real IP
    handler: (req, res) => {
        logger.warn({
            type: 'RATE_LIMIT',
            ip: req.ip,
            path: req.path,
            timestamp: new Date().toISOString()
        });
        res.status(429).json({ error: 'Too many requests' });
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // limit auth attempts
    skipSuccessfulRequests: true,
    trustProxy: true, // Trust the proxy to get real IP
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', limiter);
app.use('/api/auth/', authLimiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// HTTP request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Request ID middleware
app.use((req, res, next) => {
    req.id = uuidv4();
    res.setHeader('X-Request-Id', req.id);
    logger.info({
        type: 'REQUEST',
        requestId: req.id,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        timestamp: new Date().toISOString()
    });
    next();
});

// Authentication middleware
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            throw new Error('No token provided');
        }
        
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        logger.warn({
            type: 'AUTH_FAILURE',
            ip: req.ip,
            path: req.path,
            error: error.message,
            timestamp: new Date().toISOString()
        });
        res.status(401).json({ error: 'Authentication required' });
    }
};

// Command execution with security checks
class CommandExecutor {
    constructor() {
        this.allowedCommands = new Set([
            'ls', 'pwd', 'whoami', 'date', 'uptime', 'df', 'free',
            'ps', 'top', 'netstat', 'ss', 'ip', 'hostname', 'uname',
            'cat', 'grep', 'tail', 'head', 'wc', 'find', 'du'
        ]);
        
        this.blockedPatterns = [
            /rm\s+-rf/gi,
            />\s*\/dev\/sda/gi,
            /mkfs/gi,
            /dd\s+if=/gi,
            /format/gi,
            /del\s+\/f/gi,
            /sudo\s+chmod\s+777/gi,
            /\/etc\/passwd/gi,
            /\/etc\/shadow/gi
        ];
    }

    sanitizeCommand(command) {
        // Remove potentially dangerous characters
        let sanitized = command.trim();
        
        // Check for blocked patterns
        for (const pattern of this.blockedPatterns) {
            if (pattern.test(sanitized)) {
                throw new Error('Command contains blocked pattern');
            }
        }
        
        // Validate command is in allowed list (for restricted mode)
        const baseCommand = sanitized.split(' ')[0];
        if (process.env.RESTRICT_COMMANDS === 'true' && !this.allowedCommands.has(baseCommand)) {
            throw new Error(`Command '${baseCommand}' is not in allowed list`);
        }
        
        return sanitized;
    }

    async execute(command, userId, ip) {
        const commandId = uuidv4();
        const startTime = Date.now();
        
        try {
            const sanitizedCommand = this.sanitizeCommand(command);
            
            // Log command execution attempt
            logger.info({
                type: 'COMMAND_EXECUTION',
                commandId,
                userId,
                ip,
                command: sanitizedCommand,
                timestamp: new Date().toISOString()
            });
            
            // Execute with timeout
            const { stdout, stderr } = await execPromise(sanitizedCommand, {
                timeout: 30000, // 30 second timeout
                maxBuffer: 1024 * 1024 * 10, // 10MB buffer
                shell: '/bin/bash'
            });
            
            const executionTime = Date.now() - startTime;
            
            // Log successful execution
            logger.info({
                type: 'COMMAND_SUCCESS',
                commandId,
                userId,
                executionTime,
                outputSize: stdout.length + stderr.length,
                timestamp: new Date().toISOString()
            });
            
            return {
                success: true,
                commandId,
                stdout,
                stderr,
                executionTime
            };
        } catch (error) {
            const executionTime = Date.now() - startTime;
            
            // Log failed execution
            logger.error({
                type: 'COMMAND_FAILURE',
                commandId,
                userId,
                ip,
                command,
                error: error.message,
                executionTime,
                timestamp: new Date().toISOString()
            });
            
            throw error;
        }
    }
}

const commandExecutor = new CommandExecutor();

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Authentication
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Validate input
        if (!username || !password) {
            throw new Error('Username and password required');
        }
        
        // Verify credentials
        if (username !== ADMIN_USERNAME || !await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
            auditLog(username, 'LOGIN_FAILURE', { reason: 'Invalid credentials' }, req.ip, false);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate token
        const token = jwt.sign(
            { username, role: 'admin' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        auditLog(username, 'LOGIN_SUCCESS', {}, req.ip, true);
        
        res.json({
            token,
            expiresIn: 86400
        });
    } catch (error) {
        logger.error('Login error:', error);
        res.status(400).json({ error: error.message });
    }
});

// Execute command (protected)
app.post('/api/execute', authenticate, async (req, res) => {
    try {
        const { command } = req.body;
        
        if (!command) {
            throw new Error('Command is required');
        }
        
        // Validate command length
        if (command.length > 1000) {
            throw new Error('Command too long');
        }
        
        const result = await commandExecutor.execute(
            command,
            req.user.username,
            req.ip
        );
        
        res.json(result);
    } catch (error) {
        logger.error('Command execution error:', error);
        res.status(400).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Get system information (protected)
app.get('/api/system/info', authenticate, async (req, res) => {
    try {
        const [uptime, memory, disk, load] = await Promise.all([
            execPromise('uptime'),
            execPromise('free -h'),
            execPromise('df -h'),
            execPromise('cat /proc/loadavg')
        ]);
        
        auditLog(req.user.username, 'SYSTEM_INFO_ACCESS', {}, req.ip, true);
        
        res.json({
            uptime: uptime.stdout.trim(),
            memory: memory.stdout,
            disk: disk.stdout,
            load: load.stdout.trim(),
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('System info error:', error);
        res.status(500).json({ error: 'Failed to get system info' });
    }
});

// Get logs (protected)
app.get('/api/logs', authenticate, async (req, res) => {
    try {
        const { type = 'combined', lines = 100 } = req.query;
        const validTypes = ['combined', 'error', 'security', 'audit'];
        
        if (!validTypes.includes(type)) {
            throw new Error('Invalid log type');
        }
        
        const logFile = `/var/log/nodejs/${type}.log`;
        const { stdout } = await execPromise(`tail -n ${parseInt(lines)} ${logFile}`);
        
        auditLog(req.user.username, 'LOG_ACCESS', { type, lines }, req.ip, true);
        
        res.json({
            type,
            lines: stdout.split('\n').filter(line => line),
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Log retrieval error:', error);
        res.status(500).json({ error: 'Failed to retrieve logs' });
    }
});

// Process monitoring (protected)
app.get('/api/processes', authenticate, async (req, res) => {
    try {
        const { stdout } = await execPromise('ps aux --sort=-%cpu | head -20');
        
        auditLog(req.user.username, 'PROCESS_LIST_ACCESS', {}, req.ip, true);
        
        const lines = stdout.split('\n').filter(line => line);
        const headers = lines[0].split(/\s+/);
        const processes = lines.slice(1).map(line => {
            const values = line.split(/\s+/);
            return {
                user: values[0],
                pid: values[1],
                cpu: values[2],
                mem: values[3],
                command: values.slice(10).join(' ')
            };
        });
        
        res.json({
            processes,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Process monitoring error:', error);
        res.status(500).json({ error: 'Failed to get process list' });
    }
});

// Network connections (protected)
app.get('/api/network/connections', authenticate, async (req, res) => {
    try {
        const { stdout } = await execPromise('ss -tuln');
        
        auditLog(req.user.username, 'NETWORK_CONNECTIONS_ACCESS', {}, req.ip, true);
        
        res.json({
            connections: stdout,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        logger.error('Network connections error:', error);
        res.status(500).json({ error: 'Failed to get network connections' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    logger.error({
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

// Graceful shutdown
const gracefulShutdown = () => {
    logger.info('Received shutdown signal, closing server gracefully...');
    
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
    
    // Force close after 30 seconds
    setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
    logger.info(`Secure Node.js backend server started on port ${PORT}`);
    logger.info('Security features enabled: Helmet, CORS, Rate Limiting, JWT Authentication');
    logger.info('Logging to: /var/log/nodejs/');
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', error);
    gracefulShutdown();
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

module.exports = app;