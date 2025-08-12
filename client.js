#!/usr/bin/env node

// client-agent/client.js - Windows Client Agent
const http = require('http');
const https = require('https');
const { exec, spawn } = require('child_process');
const os = require('os');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class WindowsClientAgent {
    constructor() {
        this.config = this.loadConfig();
        this.clientId = this.config.clientId || this.generateClientId();
        this.hostname = os.hostname();
        this.isRunning = false;
        this.heartbeatInterval = null;
        this.commandQueue = [];
        this.activeCommands = new Map();
        
        // Save client ID if generated
        if (!this.config.clientId) {
            this.config.clientId = this.clientId;
            this.saveConfig();
        }

        this.setupLogging();
        this.log('info', `Client agent initialized: ${this.hostname} (${this.clientId})`);
    }

    loadConfig() {
        try {
            const configPath = path.join(__dirname, 'config.json');
            if (fs.existsSync(configPath)) {
                return JSON.parse(fs.readFileSync(configPath, 'utf8'));
            }
        } catch (error) {
            console.error('Failed to load config:', error.message);
        }

        // Default configuration
        return {
            mainServer: {
                host: '45.131.109.191',
                port: 80,
                protocol: 'http'
            },
            authentication: {
                clientSecret: crypto.randomBytes(32).toString('hex')
            },
            settings: {
                heartbeatInterval: 30000,      // 30 seconds
                commandTimeout: 300000,       // 5 minutes
                maxConcurrentCommands: 3,
                logLevel: 'info',
                autoReconnect: true,
                reconnectDelay: 5000
            }
        };
    }

    saveConfig() {
        try {
            const configPath = path.join(__dirname, 'config.json');
            fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
        } catch (error) {
            console.error('Failed to save config:', error.message);
        }
    }

    generateClientId() {
        return `${this.hostname}-${crypto.randomBytes(8).toString('hex')}`.toLowerCase();
    }

    setupLogging() {
        const logDir = path.join(__dirname, 'logs');
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }

        this.logFile = path.join(logDir, 'client.log');
        this.commandLogFile = path.join(logDir, 'commands.log');
    }

    log(level, message, metadata = {}) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            level: level.toUpperCase(),
            clientId: this.clientId,
            hostname: this.hostname,
            message,
            ...metadata
        };

        const logLine = JSON.stringify(logEntry) + '\n';
        
        // Write to local log file
        try {
            fs.appendFileSync(this.logFile, logLine);
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
        }

        // Console output
        console.log(`[${timestamp}] ${level.toUpperCase()}: ${message}`);

        // Send to main server (async, don't wait)
        this.sendLogToServer(logEntry).catch(err => {
            // Silently handle log forwarding failures to avoid loops
        });
    }

    logCommand(commandId, command, result, metadata = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            type: 'COMMAND_EXECUTION',
            commandId,
            clientId: this.clientId,
            hostname: this.hostname,
            command: command.length > 200 ? command.substring(0, 200) + '...' : command,
            success: result.success,
            exitCode: result.exitCode,
            executionTime: result.executionTime,
            outputSize: (result.stdout?.length || 0) + (result.stderr?.length || 0),
            ...metadata
        };

        const logLine = JSON.stringify(logEntry) + '\n';
        
        try {
            fs.appendFileSync(this.commandLogFile, logLine);
        } catch (error) {
            console.error('Failed to write command log:', error.message);
        }
    }

    async start() {
        if (this.isRunning) {
            this.log('warn', 'Client agent already running');
            return;
        }

        this.log('info', 'Starting Windows Client Agent...');
        
        try {
            // Register with main server
            await this.registerWithServer();
            
            // Start heartbeat
            this.startHeartbeat();
            
            // Start command polling
            this.startCommandPolling();
            
            this.isRunning = true;
            this.log('info', 'Client agent started successfully');
            
        } catch (error) {
            this.log('error', 'Failed to start client agent', { error: error.message });
            throw error;
        }
    }

    async stop() {
        if (!this.isRunning) return;

        this.log('info', 'Stopping Windows Client Agent...');
        
        this.isRunning = false;
        
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
        
        if (this.pollingInterval) {
            clearInterval(this.pollingInterval);
        }

        // Cancel active commands
        for (const [commandId, process] of this.activeCommands) {
            try {
                process.kill('SIGTERM');
                this.log('info', `Terminated command: ${commandId}`);
            } catch (error) {
                this.log('error', `Failed to terminate command ${commandId}`, { error: error.message });
            }
        }

        // Unregister from server
        try {
            await this.unregisterFromServer();
        } catch (error) {
            this.log('error', 'Failed to unregister from server', { error: error.message });
        }

        this.log('info', 'Client agent stopped');
    }

    async registerWithServer() {
        const registrationData = {
            clientId: this.clientId,
            hostname: this.hostname,
            platform: os.platform(),
            arch: os.arch(),
            version: process.version,
            capabilities: ['command_execution', 'file_operations', 'system_info'],
            clientSecret: this.config.authentication.clientSecret
        };

        const response = await this.makeRequest('POST', '/api/clients/register', registrationData);
        
        if (!response.success) {
            throw new Error(`Registration failed: ${response.error}`);
        }

        this.serverToken = response.token;
        this.log('info', 'Successfully registered with main server');
    }

    async unregisterFromServer() {
        await this.makeRequest('POST', '/api/clients/unregister', {
            clientId: this.clientId
        });
        
        this.log('info', 'Unregistered from main server');
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(async () => {
            try {
                await this.sendHeartbeat();
            } catch (error) {
                this.log('error', 'Heartbeat failed', { error: error.message });
                
                if (this.config.settings.autoReconnect) {
                    this.scheduleReconnect();
                }
            }
        }, this.config.settings.heartbeatInterval);
    }

    async sendHeartbeat() {
        const heartbeatData = {
            clientId: this.clientId,
            timestamp: new Date().toISOString(),
            status: 'healthy',
            systemInfo: this.getSystemInfo(),
            activeCommands: this.activeCommands.size,
            queuedCommands: this.commandQueue.length
        };

        await this.makeRequest('POST', '/api/clients/heartbeat', heartbeatData);
    }

    startCommandPolling() {
        this.pollingInterval = setInterval(async () => {
            try {
                await this.pollForCommands();
            } catch (error) {
                this.log('error', 'Command polling failed', { error: error.message });
            }
        }, 5000); // Poll every 5 seconds
    }

    async pollForCommands() {
        const response = await this.makeRequest('GET', `/api/clients/${this.clientId}/commands`);
        
        if (response.commands && response.commands.length > 0) {
            for (const command of response.commands) {
                this.commandQueue.push(command);
                this.log('info', `Received command: ${command.id}`);
            }
            
            this.processCommandQueue();
        }
    }

    async processCommandQueue() {
        while (this.commandQueue.length > 0 && this.activeCommands.size < this.config.settings.maxConcurrentCommands) {
            const command = this.commandQueue.shift();
            this.executeCommand(command);
        }
    }

    async executeCommand(command) {
        const { id, command: cmd, timeout, metadata } = command;
        const startTime = Date.now();

        this.log('info', `Executing command: ${id}`, { command: cmd });

        try {
            // Acknowledge command receipt
            await this.makeRequest('POST', `/api/clients/${this.clientId}/commands/${id}/ack`);

            const result = await this.runCommand(cmd, timeout || this.config.settings.commandTimeout);
            const executionTime = Date.now() - startTime;

            result.executionTime = executionTime;
            result.commandId = id;
            result.clientId = this.clientId;

            // Log command execution
            this.logCommand(id, cmd, result, metadata);

            // Send result back to server
            await this.makeRequest('POST', `/api/clients/${this.clientId}/commands/${id}/result`, {
                result,
                metadata: {
                    ...metadata,
                    executionTime,
                    hostname: this.hostname
                }
            });

            this.log('info', `Command completed: ${id}`, { 
                success: result.success, 
                executionTime 
            });

        } catch (error) {
            const executionTime = Date.now() - startTime;
            this.log('error', `Command failed: ${id}`, { 
                error: error.message, 
                executionTime 
            });

            // Send error result
            try {
                await this.makeRequest('POST', `/api/clients/${this.clientId}/commands/${id}/result`, {
                    result: {
                        success: false,
                        error: error.message,
                        exitCode: -1,
                        executionTime
                    }
                });
            } catch (reportError) {
                this.log('error', `Failed to report command error: ${reportError.message}`);
            }
        }
    }

    async runCommand(command, timeout) {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            let stdout = '';
            let stderr = '';

            // Use appropriate shell for Windows
            const shell = process.platform === 'win32' ? 'powershell.exe' : '/bin/bash';
            const args = process.platform === 'win32' ? ['-Command', command] : ['-c', command];

            const childProcess = spawn(shell, args, {
                timeout,
                stdio: ['pipe', 'pipe', 'pipe'],
                shell: false
            });

            this.activeCommands.set(command, childProcess);

            childProcess.stdout.on('data', (data) => {
                stdout += data.toString();
            });

            childProcess.stderr.on('data', (data) => {
                stderr += data.toString();
            });

            childProcess.on('close', (code) => {
                this.activeCommands.delete(command);
                
                resolve({
                    success: code === 0,
                    exitCode: code,
                    stdout: stdout,
                    stderr: stderr,
                    executionTime: Date.now() - startTime
                });
            });

            childProcess.on('error', (error) => {
                this.activeCommands.delete(command);
                reject(error);
            });

            // Handle timeout
            setTimeout(() => {
                if (this.activeCommands.has(command)) {
                    childProcess.kill('SIGTERM');
                    this.activeCommands.delete(command);
                    reject(new Error(`Command timeout after ${timeout}ms`));
                }
            }, timeout);
        });
    }

    getSystemInfo() {
        return {
            hostname: os.hostname(),
            platform: os.platform(),
            arch: os.arch(),
            release: os.release(),
            uptime: os.uptime(),
            loadavg: os.loadavg(),
            totalmem: os.totalmem(),
            freemem: os.freemem(),
            cpus: os.cpus().length,
            nodeVersion: process.version
        };
    }

    async sendLogToServer(logEntry) {
        try {
            await this.makeRequest('POST', '/api/clients/logs', {
                clientId: this.clientId,
                logs: [logEntry]
            });
        } catch (error) {
            // Silently fail to avoid logging loops
        }
    }

    async makeRequest(method, path, data = null) {
        const options = {
            hostname: this.config.mainServer.host,
            port: this.config.mainServer.port,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': `WindowsClientAgent/${this.clientId}`,
                'X-Client-ID': this.clientId
            },
            timeout: 10000
        };

        if (this.serverToken) {
            options.headers['Authorization'] = `Bearer ${this.serverToken}`;
        }

        const body = data ? JSON.stringify(data) : null;
        if (body) {
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        return new Promise((resolve, reject) => {
            const protocol = this.config.mainServer.protocol === 'https' ? https : http;
            
            const req = protocol.request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        const parsedData = responseData ? JSON.parse(responseData) : {};
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            resolve(parsedData);
                        } else {
                            reject(new Error(parsedData.error || `HTTP ${res.statusCode}`));
                        }
                    } catch (e) {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            resolve({ data: responseData });
                        } else {
                            reject(new Error(`HTTP ${res.statusCode}: ${responseData}`));
                        }
                    }
                });
            });

            req.on('error', reject);
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (body) {
                req.write(body);
            }
            req.end();
        });
    }

    scheduleReconnect() {
        if (this.reconnectTimeout) return;
        
        this.log('info', `Scheduling reconnect in ${this.config.settings.reconnectDelay}ms`);
        
        this.reconnectTimeout = setTimeout(async () => {
            this.reconnectTimeout = null;
            
            try {
                await this.registerWithServer();
                this.log('info', 'Reconnected to main server');
            } catch (error) {
                this.log('error', 'Reconnection failed', { error: error.message });
                this.scheduleReconnect();
            }
        }, this.config.settings.reconnectDelay);
    }
}

// Service management for Windows
class WindowsService {
    static install() {
        const Service = require('node-windows').Service;
        
        const svc = new Service({
            name: 'SecureBackendClient',
            description: 'Secure Backend Framework - Windows Client Agent',
            script: path.join(__dirname, 'client.js'),
            nodeOptions: [
                '--harmony',
                '--max_old_space_size=4096'
            ]
        });

        svc.on('install', () => {
            console.log('Service installed successfully');
            svc.start();
        });

        svc.install();
    }

    static uninstall() {
        const Service = require('node-windows').Service;
        
        const svc = new Service({
            name: 'SecureBackendClient',
            script: path.join(__dirname, 'client.js')
        });

        svc.on('uninstall', () => {
            console.log('Service uninstalled successfully');
        });

        svc.uninstall();
    }
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    
    if (args[0] === 'install-service') {
        WindowsService.install();
    } else if (args[0] === 'uninstall-service') {
        WindowsService.uninstall();
    } else {
        const agent = new WindowsClientAgent();
        
        // Graceful shutdown handling
        const shutdown = async () => {
            console.log('\nShutting down client agent...');
            await agent.stop();
            process.exit(0);
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('SIGHUP', shutdown);

        // Start the agent
        agent.start().catch(error => {
            console.error('Failed to start client agent:', error.message);
            process.exit(1);
        });
    }
}

module.exports = WindowsClientAgent;