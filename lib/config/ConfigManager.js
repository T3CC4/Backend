// framework/lib/config/ConfigManager.js
require('dotenv').config();
const crypto = require('crypto');

class ConfigManager {
    constructor(options = {}) {
        this.config = new Map();
        this.defaults = new Map();
        
        // Set default configuration
        this.setDefaults();
        
        // Override with environment variables
        this.loadFromEnv();
        
        // Override with provided options
        this.loadFromOptions(options);
        
        // Validate required configuration
        this.validate();
    }

    setDefaults() {
        this.defaults.set('PORT', 3000);
        this.defaults.set('HOST', '0.0.0.0');
        this.defaults.set('NODE_ENV', 'development');
        this.defaults.set('JWT_SECRET', crypto.randomBytes(64).toString('hex'));
        this.defaults.set('ADMIN_USERNAME', 'admin');
        this.defaults.set('ADMIN_PASSWORD_HASH', '$2b$10$xK1.VlQXs8Kc5Gkmqp6TDO0PxZ5D3QNgA2qL8kxvM7fW8iBX3jXyG'); // 'changeme'
        this.defaults.set('ALLOWED_ORIGINS', 'http://localhost:3000');
        this.defaults.set('RESTRICT_COMMANDS', 'true');
        this.defaults.set('LOG_LEVEL', 'info');
        this.defaults.set('LOG_DIR', '/var/log/nodejs');
        this.defaults.set('RATE_LIMIT_WINDOW', 15 * 60 * 1000); // 15 minutes
        this.defaults.set('RATE_LIMIT_MAX', 100);
        this.defaults.set('AUTH_RATE_LIMIT_MAX', 5);
        this.defaults.set('COMMAND_TIMEOUT', 30000); // 30 seconds
        this.defaults.set('COMMAND_MAX_BUFFER', 1024 * 1024 * 10); // 10MB
        this.defaults.set('JWT_EXPIRES_IN', '24h');
    }

    loadFromEnv() {
        const envVars = [
            'PORT', 'HOST', 'NODE_ENV', 'JWT_SECRET', 'ADMIN_USERNAME', 
            'ADMIN_PASSWORD_HASH', 'ALLOWED_ORIGINS', 'RESTRICT_COMMANDS',
            'LOG_LEVEL', 'LOG_DIR', 'RATE_LIMIT_WINDOW', 'RATE_LIMIT_MAX',
            'AUTH_RATE_LIMIT_MAX', 'COMMAND_TIMEOUT', 'COMMAND_MAX_BUFFER',
            'JWT_EXPIRES_IN'
        ];

        envVars.forEach(key => {
            const value = process.env[key];
            if (value !== undefined) {
                this.config.set(key, value);
            }
        });
    }

    loadFromOptions(options) {
        Object.entries(options).forEach(([key, value]) => {
            this.config.set(key, value);
        });
    }

    get(key, defaultValue) {
        if (this.config.has(key)) {
            return this.parseValue(this.config.get(key));
        }
        if (this.defaults.has(key)) {
            return this.parseValue(this.defaults.get(key));
        }
        return defaultValue;
    }

    set(key, value) {
        this.config.set(key, value);
    }

    has(key) {
        return this.config.has(key) || this.defaults.has(key);
    }

    getAll() {
        const result = {};
        
        // Add defaults first
        this.defaults.forEach((value, key) => {
            result[key] = this.parseValue(value);
        });
        
        // Override with config
        this.config.forEach((value, key) => {
            result[key] = this.parseValue(value);
        });
        
        return result;
    }

    parseValue(value) {
        if (typeof value !== 'string') {
            return value;
        }

        // Boolean conversion
        if (value.toLowerCase() === 'true') return true;
        if (value.toLowerCase() === 'false') return false;

        // Number conversion
        if (/^\d+$/.test(value)) {
            return parseInt(value, 10);
        }
        if (/^\d+\.\d+$/.test(value)) {
            return parseFloat(value);
        }

        return value;
    }

    validate() {
        const required = ['JWT_SECRET', 'ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH'];
        
        required.forEach(key => {
            if (!this.has(key)) {
                throw new Error(`Required configuration missing: ${key}`);
            }
        });

        // Warn about default values in production
        if (this.get('NODE_ENV') === 'production') {
            if (this.get('ADMIN_PASSWORD_HASH') === this.defaults.get('ADMIN_PASSWORD_HASH')) {
                console.warn('WARNING: Using default admin password in production!');
            }
            if (this.get('JWT_SECRET').length < 32) {
                console.warn('WARNING: JWT_SECRET should be at least 32 characters long!');
            }
        }
    }

    isDevelopment() {
        return this.get('NODE_ENV') === 'development';
    }

    isProduction() {
        return this.get('NODE_ENV') === 'production';
    }

    isTest() {
        return this.get('NODE_ENV') === 'test';
    }
}

module.exports = ConfigManager;