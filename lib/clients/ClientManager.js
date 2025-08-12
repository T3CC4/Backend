// framework/lib/clients/ClientManager.js
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

class ClientManager {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.clients = new Map(); // clientId -> client info
        this.clientCommands = new Map(); // clientId -> command queue
        this.clientLogs = new Map(); // clientId -> log buffer
        this.heartbeats = new Map(); // clientId -> last heartbeat
        
        this.clientsFilePath = path.join(process.cwd(), 'config', 'clients.json');
        this.logsBasePath = path.join(process.cwd(), 'logs', 'clients');
    }

    async initialize() {
        this.logger.info('Initializing Client Manager...');
        
        await this.setupDirectories();
        await this.loadClientsFromFile();
        this.startHealthMonitoring();
        
        this.logger.info('Client Manager initialized successfully');
    }

    async setupDirectories() {
        try {
            await fs.mkdir(path.dirname(this.clientsFilePath), { recursive: true });
            await fs.mkdir(this.logsBasePath, { recursive: true });
        } catch (error) {
            this.logger.error('Failed to setup client directories:', error);
        }
    }

    async loadClientsFromFile() {
        try {
            const data = await fs.readFile(this.clientsFilePath, 'utf8');
            const clientsData = JSON.parse(data);
            
            for (const [clientId, clientInfo] of Object.entries(clientsData)) {
                this.clients.set(clientId, {
                    ...clientInfo,
                    status: 'offline',
                    lastSeen: null
                });
            }
            
            this.logger.info(`Loaded ${this.clients.size} clients from configuration`);
        } catch (error) {
            if (error.code !== 'ENOENT') {
                this.logger.error('Failed to load clients configuration:', error);
            }
        }
    }

    async saveClientsToFile() {
        try {
            const clientsData = {};
            for (const [clientId, client] of this.clients) {
                clientsData[clientId] = {
                    hostname: client.hostname,
                    platform: client.platform,
                    arch: client.arch,
                    capabilities: client.capabilities,
                    registeredAt: client.registeredAt,
                    clientSecret: client.clientSecret
                };
            }
            
            await fs.writeFile(this.clientsFilePath, JSON.stringify(clientsData, null, 2));
        } catch (error) {
            this.logger.error('Failed to save clients configuration:', error);
        }
    }

    generateClientToken(clientId) {
        const payload = {
            clientId,
            type: 'client',
            iat: Math.floor(Date.now() / 1000)
        };

        return crypto.createHmac('sha256', this.config.get('JWT_SECRET'))
            .update(JSON.stringify(payload))
            .digest('hex');
    }

    async registerClient(registrationData) {
        const { clientId, hostname, platform, arch, capabilities, clientSecret } = registrationData;
        
        this.logger.info(`Client registration request: ${clientId} (${hostname})`);

        // Validate registration data
        if (!clientId || !hostname || !platform || !clientSecret) {
            throw new Error('Invalid registration data');
        }

        // Check if client already exists
        const existingClient = this.clients.get(clientId);
        if (existingClient) {
            // Verify client secret
            if (existingClient.clientSecret !== clientSecret) {
                this.logger.securityLog('CLIENT_AUTH_FAILURE', { 
                    clientId, 
                    hostname,
                    reason: 'Invalid client secret' 
                });
                throw new Error('Authentication failed');
            }
        }

        // Generate server token for this client
        const serverToken = this.generateClientToken(clientId);

        // Create or update client info
        const clientInfo = {
            clientId,
            hostname,
            platform,
            arch,
            capabilities: capabilities || [],
            registeredAt: existingClient?.registeredAt || new Date().toISOString(),
            clientSecret,
            serverToken,
            status: 'online',
            lastSeen: new Date().toISOString(),
            version: registrationData.version || 'unknown'
        };

        this.clients.set(clientId, clientInfo);
        this.clientCommands.set(clientId, []);
        this.clientLogs.set(clientId, []);
        this.heartbeats.set(clientId, Date.now());

        // Create client log directory
        const clientLogDir = path.join(this.logsBasePath, hostname);
        await fs.mkdir(clientLogDir, { recursive: true });

        // Save configuration
        await this.saveClientsToFile();

        this.logger.auditLog('system', 'CLIENT_REGISTERED', {
            clientId,
            hostname,
            platform,
            capabilities
        }, null, true);

        return {
            success: true,
            token: serverToken,
            message: 'Client registered successfully'
        };
    }

    async unregisterClient(clientId) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        // Update status but keep client info
        client.status = 'offline';
        client.lastSeen = new Date().toISOString();

        // Clear runtime data
        this.clientCommands.delete(clientId);
        this.heartbeats.delete(clientId);

        this.logger.auditLog('system', 'CLIENT_UNREGISTERED', {
            clientId,
            hostname: client.hostname
        }, null, true);

        return { success: true };
    }

    async handleHeartbeat(clientId, heartbeatData) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not registered');
        }

        // Update client status
        client.status = 'online';
        client.lastSeen = new Date().toISOString();
        client.systemInfo = heartbeatData.systemInfo;

        this.heartbeats.set(clientId, Date.now());

        this.logger.debug(`Heartbeat received from ${client.hostname} (${clientId})`);

        return { success: true };
    }

    async queueCommand(clientId, command, metadata = {}) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        if (client.status !== 'online') {
            throw new Error('Client is offline');
        }

        const commandId = uuidv4();
        const commandObj = {
            id: commandId,
            command,
            queuedAt: new Date().toISOString(),
            timeout: metadata.timeout || 300000, // 5 minutes default
            metadata: {
                ...metadata,
                queuedBy: metadata.userId || 'system'
            }
        };

        // Add to client's command queue
        if (!this.clientCommands.has(clientId)) {
            this.clientCommands.set(clientId, []);
        }
        
        this.clientCommands.get(clientId).push(commandObj);

        this.logger.auditLog(metadata.userId || 'system', 'COMMAND_QUEUED', {
            commandId,
            clientId,
            hostname: client.hostname,
            command: command.length > 100 ? command.substring(0, 100) + '...' : command
        }, metadata.ip, true);

        return {
            success: true,
            commandId,
            queuedAt: commandObj.queuedAt
        };
    }

    async getClientCommands(clientId) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        const commands = this.clientCommands.get(clientId) || [];
        
        // Clear the command queue after sending
        this.clientCommands.set(clientId, []);

        return {
            commands,
            timestamp: new Date().toISOString()
        };
    }

    async acknowledgeCommand(clientId, commandId) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        this.logger.info(`Command acknowledged: ${commandId} by ${client.hostname}`);

        return { success: true };
    }

    async receiveCommandResult(clientId, commandId, result, metadata = {}) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        // Log command result
        await this.logCommandResult(client, commandId, result, metadata);

        this.logger.auditLog('system', 'COMMAND_COMPLETED', {
            commandId,
            clientId,
            hostname: client.hostname,
            success: result.success,
            executionTime: result.executionTime
        }, null, result.success);

        return { success: true };
    }

    async receiveClientLogs(clientId, logs) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        // Store logs in memory buffer
        if (!this.clientLogs.has(clientId)) {
            this.clientLogs.set(clientId, []);
        }

        const logBuffer = this.clientLogs.get(clientId);
        logBuffer.push(...logs);

        // Keep only last 1000 logs in memory
        if (logBuffer.length > 1000) {
            logBuffer.splice(0, logBuffer.length - 1000);
        }

        // Write logs to file
        await this.writeClientLogs(client, logs);

        return { success: true };
    }

    async writeClientLogs(client, logs) {
        try {
            const logDir = path.join(this.logsBasePath, client.hostname);
            const logFile = path.join(logDir, `${new Date().toISOString().split('T')[0]}.log`);

            const logEntries = logs.map(log => JSON.stringify(log)).join('\n') + '\n';
            
            await fs.appendFile(logFile, logEntries);
        } catch (error) {
            this.logger.error(`Failed to write client logs for ${client.hostname}:`, error);
        }
    }

    async logCommandResult(client, commandId, result, metadata) {
        try {
            const logDir = path.join(this.logsBasePath, client.hostname);
            const commandLogFile = path.join(logDir, 'commands.log');

            const logEntry = {
                timestamp: new Date().toISOString(),
                type: 'COMMAND_RESULT',
                commandId,
                clientId: client.clientId,
                hostname: client.hostname,
                success: result.success,
                exitCode: result.exitCode,
                executionTime: result.executionTime,
                outputSize: (result.stdout?.length || 0) + (result.stderr?.length || 0),
                error: result.error,
                metadata
            };

            await fs.appendFile(commandLogFile, JSON.stringify(logEntry) + '\n');
        } catch (error) {
            this.logger.error(`Failed to write command result log:`, error);
        }
    }

    startHealthMonitoring() {
        setInterval(() => {
            this.checkClientHealth();
        }, 60000); // Check every minute
    }

    checkClientHealth() {
        const now = Date.now();
        const healthTimeout = 120000; // 2 minutes

        for (const [clientId, client] of this.clients) {
            const lastHeartbeat = this.heartbeats.get(clientId);
            
            if (client.status === 'online' && lastHeartbeat) {
                if (now - lastHeartbeat > healthTimeout) {
                    client.status = 'offline';
                    client.lastSeen = new Date(lastHeartbeat).toISOString();
                    
                    this.logger.warn(`Client ${client.hostname} (${clientId}) marked as offline - no heartbeat`);
                    
                    // Clear pending commands for offline client
                    this.clientCommands.set(clientId, []);
                }
            }
        }
    }

    // Get all clients
    getAllClients() {
        const clients = [];
        for (const [clientId, client] of this.clients) {
            clients.push({
                clientId,
                hostname: client.hostname,
                platform: client.platform,
                arch: client.arch,
                status: client.status,
                lastSeen: client.lastSeen,
                registeredAt: client.registeredAt,
                capabilities: client.capabilities,
                systemInfo: client.systemInfo,
                queuedCommands: (this.clientCommands.get(clientId) || []).length
            });
        }
        return clients;
    }

    // Get specific client
    getClient(clientId) {
        const client = this.clients.get(clientId);
        if (!client) return null;

        return {
            clientId,
            hostname: client.hostname,
            platform: client.platform,
            arch: client.arch,
            status: client.status,
            lastSeen: client.lastSeen,
            registeredAt: client.registeredAt,
            capabilities: client.capabilities,
            systemInfo: client.systemInfo,
            queuedCommands: (this.clientCommands.get(clientId) || []).length,
            logBuffer: (this.clientLogs.get(clientId) || []).length
        };
    }

    // Get client logs
    async getClientLogs(clientId, date = null, lines = 100) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        const logDir = path.join(this.logsBasePath, client.hostname);
        const logFile = date 
            ? path.join(logDir, `${date}.log`)
            : path.join(logDir, `${new Date().toISOString().split('T')[0]}.log`);

        try {
            const { exec } = require('child_process');
            const util = require('util');
            const execPromise = util.promisify(exec);
            
            const { stdout } = await execPromise(`tail -n ${lines} "${logFile}"`);
            const logLines = stdout.split('\n')
                .filter(line => line.trim())
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch {
                        return { message: line, timestamp: new Date().toISOString() };
                    }
                });

            return {
                clientId,
                hostname: client.hostname,
                date: date || new Date().toISOString().split('T')[0],
                logs: logLines,
                total: logLines.length
            };
        } catch (error) {
            if (error.code === 'ENOENT') {
                return {
                    clientId,
                    hostname: client.hostname,
                    date: date || new Date().toISOString().split('T')[0],
                    logs: [],
                    total: 0
                };
            }
            throw error;
        }
    }

    // Execute command on specific client
    async executeCommandOnClient(clientId, command, userId, ip, metadata = {}) {
        return await this.queueCommand(clientId, command, {
            ...metadata,
            userId,
            ip,
            executedAt: new Date().toISOString()
        });
    }

    // Execute command on multiple clients
    async executeCommandOnMultipleClients(clientIds, command, userId, ip, metadata = {}) {
        const results = {};
        
        for (const clientId of clientIds) {
            try {
                const result = await this.executeCommandOnClient(clientId, command, userId, ip, metadata);
                results[clientId] = result;
            } catch (error) {
                results[clientId] = {
                    success: false,
                    error: error.message
                };
            }
        }

        return results;
    }

    // Execute command on all online clients
    async executeCommandOnAllClients(command, userId, ip, metadata = {}) {
        const onlineClients = [];
        for (const [clientId, client] of this.clients) {
            if (client.status === 'online') {
                onlineClients.push(clientId);
            }
        }

        return await this.executeCommandOnMultipleClients(onlineClients, command, userId, ip, metadata);
    }

    // Get client statistics
    getClientStats() {
        let onlineCount = 0;
        let offlineCount = 0;
        let totalCommands = 0;
        let totalLogs = 0;

        for (const [clientId, client] of this.clients) {
            if (client.status === 'online') {
                onlineCount++;
            } else {
                offlineCount++;
            }

            totalCommands += (this.clientCommands.get(clientId) || []).length;
            totalLogs += (this.clientLogs.get(clientId) || []).length;
        }

        return {
            total: this.clients.size,
            online: onlineCount,
            offline: offlineCount,
            queuedCommands: totalCommands,
            bufferedLogs: totalLogs,
            platforms: this.getPlatformStats()
        };
    }

    getPlatformStats() {
        const platforms = {};
        for (const [clientId, client] of this.clients) {
            const platform = client.platform || 'unknown';
            platforms[platform] = (platforms[platform] || 0) + 1;
        }
        return platforms;
    }

    // Remove client completely
    async removeClient(clientId) {
        const client = this.clients.get(clientId);
        if (!client) {
            throw new Error('Client not found');
        }

        // Clean up all data
        this.clients.delete(clientId);
        this.clientCommands.delete(clientId);
        this.clientLogs.delete(clientId);
        this.heartbeats.delete(clientId);

        // Save updated configuration
        await this.saveClientsToFile();

        this.logger.auditLog('system', 'CLIENT_REMOVED', {
            clientId,
            hostname: client.hostname
        }, null, true);

        return { success: true };
    }
}

module.exports = ClientManager;