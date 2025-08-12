#!/usr/bin/env node

// admin-tools/multi-admin.js - Multi-Server Management CLI
const http = require('http');
const readline = require('readline');

// Main server connection (hardcoded)
const MAIN_SERVER_IP = '45.131.109.191';
const MAIN_SERVER_PORT = 80;
const MAIN_SERVER_URL = `http://${MAIN_SERVER_IP}:${MAIN_SERVER_PORT}`;

class MultiServerAdmin {
    constructor() {
        this.serverIP = MAIN_SERVER_IP;
        this.serverPort = MAIN_SERVER_PORT;
        this.baseUrl = MAIN_SERVER_URL;
        this.token = null;
        this.connectedClients = new Map();
        this.isAuthenticated = false;
    }

    // HTTP request helper (same as admin.js)
    async request(method, path, data = null) {
        const options = {
            hostname: this.serverIP,
            port: this.serverPort,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'MultiServerAdmin/1.0'
            },
            timeout: 30000
        };

        if (this.token) {
            options.headers['Authorization'] = `Bearer ${this.token}`;
        }

        const body = data ? JSON.stringify(data) : null;
        if (body) {
            options.headers['Content-Length'] = Buffer.byteLength(body);
        }

        return new Promise((resolve, reject) => {
            const req = http.request(options, (res) => {
                let responseData = '';

                res.on('data', (chunk) => {
                    responseData += chunk;
                });

                res.on('end', () => {
                    try {
                        const parsedData = responseData ? JSON.parse(responseData) : {};
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            resolve({
                                status: res.statusCode,
                                headers: res.headers,
                                data: parsedData
                            });
                        } else {
                            reject({
                                status: res.statusCode,
                                error: parsedData.error || `HTTP ${res.statusCode}`,
                                data: parsedData
                            });
                        }
                    } catch (e) {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            resolve({
                                status: res.statusCode,
                                headers: res.headers,
                                data: responseData
                            });
                        } else {
                            reject({ 
                                status: res.statusCode, 
                                error: responseData || 'Unknown error' 
                            });
                        }
                    }
                });
            });

            req.on('error', (error) => {
                if (error.code === 'ECONNREFUSED') {
                    reject({ error: `Cannot connect to main server at ${this.baseUrl}` });
                } else if (error.code === 'ETIMEDOUT') {
                    reject({ error: 'Connection timeout' });
                } else {
                    reject({ error: error.message });
                }
            });

            req.on('timeout', () => {
                req.destroy();
                reject({ error: 'Request timeout (30s)' });
            });

            if (body) {
                req.write(body);
            }
            req.end();
        });
    }

    async login(username, password) {
        try {
            console.log(`\nConnecting to main server at ${this.baseUrl}...`);
            const response = await this.request('POST', '/api/auth/login', {
                username,
                password
            });
            
            this.token = response.data.token;
            this.isAuthenticated = true;
            console.log('✓ Authenticated with main server');
            
            // Load connected clients
            await this.refreshClientList();
            
            return true;
        } catch (error) {
            console.error('✗ Authentication failed:', error.error || error.message);
            return false;
        }
    }

    async refreshClientList() {
        try {
            const response = await this.request('GET', '/api/clients');
            this.connectedClients.clear();
            
            response.data.clients.forEach(client => {
                this.connectedClients.set(client.clientId, {
                    id: client.clientId,
                    hostname: client.hostname,
                    platform: client.platform,
                    status: client.status,
                    lastSeen: client.lastSeen,
                    arch: client.arch
                });
            });
            
            console.log(`✓ Found ${this.connectedClients.size} registered clients`);
        } catch (error) {
            console.error('✗ Failed to refresh client list:', error.error || error.message);
        }
    }

    async showDashboard() {
        if (!this.isAuthenticated) {
            console.log('Not authenticated. Please login first.');
            return;
        }

        console.clear();
        console.log('='.repeat(80));
        console.log('                    MULTI-SERVER NETWORK DASHBOARD');
        console.log('='.repeat(80));

        // Main server status
        try {
            const mainHealth = await this.request('GET', '/api/health');
            const mainUptime = Math.floor(mainHealth.data.uptime / 60);
            console.log(`Main Server (${MAIN_SERVER_IP}): ${mainHealth.data.status} | Uptime: ${mainUptime}min`);
        } catch (error) {
            console.log(`Main Server (${MAIN_SERVER_IP}): ERROR - ${error.error}`);
        }

        console.log('\n--- Connected Clients ---');
        if (this.connectedClients.size === 0) {
            console.log('No clients connected');
        } else {
            console.log('ID'.padEnd(25), 'HOSTNAME'.padEnd(20), 'PLATFORM'.padEnd(12), 'STATUS'.padEnd(10), 'LAST SEEN');
            console.log('-'.repeat(80));
            
            for (const [clientId, client] of this.connectedClients) {
                const lastSeen = client.lastSeen ? new Date(client.lastSeen).toLocaleTimeString() : 'Never';
                const statusIcon = client.status === 'online' ? '🟢' : '🔴';
                
                console.log(
                    `${statusIcon} ${clientId.substring(0, 22)}`.padEnd(25),
                    client.hostname.substring(0, 18).padEnd(20),
                    client.platform.padEnd(12),
                    client.status.padEnd(10),
                    lastSeen
                );
            }
        }

        // Client statistics
        const onlineCount = Array.from(this.connectedClients.values()).filter(c => c.status === 'online').length;
        const offlineCount = this.connectedClients.size - onlineCount;
        
        console.log('\n--- Network Summary ---');
        console.log(`Total Clients: ${this.connectedClients.size} | Online: ${onlineCount} | Offline: ${offlineCount}`);
        console.log('='.repeat(80));
    }

    async executeOnClient(clientId, command) {
        try {
            const client = this.connectedClients.get(clientId);
            if (!client) {
                throw new Error('Client not found');
            }

            console.log(`\nExecuting on ${client.hostname} (${clientId}):`);
            console.log(`Command: ${command}`);
            
            const response = await this.request('POST', `/api/clients/${clientId}/execute`, {
                command,
                timeout: 30000
            });

            if (response.data.success) {
                console.log('✓ Command queued successfully');
                console.log(`Command ID: ${response.data.commandId}`);
                console.log('Note: Results will be processed asynchronously on the client');
            } else {
                console.log('✗ Command failed:', response.data.error);
            }

            return response.data;
        } catch (error) {
            console.error('✗ Execute command failed:', error.error || error.message);
            throw error;
        }
    }

    async executeOnMultipleClients(clientIds, command) {
        try {
            console.log(`\nExecuting on ${clientIds.length} clients:`);
            console.log(`Command: ${command}`);
            
            const response = await this.request('POST', '/api/clients/execute-multi', {
                clientIds,
                command,
                timeout: 30000
            });

            const results = response.data.results;
            const summary = response.data.summary;

            console.log(`\n--- Execution Results ---`);
            console.log(`Total: ${summary.total} | Queued: ${summary.successful} | Failed: ${summary.failed}`);
            
            for (const [clientId, result] of Object.entries(results)) {
                const client = this.connectedClients.get(clientId);
                const hostname = client ? client.hostname : 'Unknown';
                
                if (result.success) {
                    console.log(`✓ ${hostname} (${clientId}): Queued - ${result.commandId}`);
                } else {
                    console.log(`✗ ${hostname} (${clientId}): ${result.error}`);
                }
            }

            return response.data;
        } catch (error) {
            console.error('✗ Multi-client execution failed:', error.error || error.message);
            throw error;
        }
    }

    async executeOnAllClients(command) {
        try {
            const onlineClients = Array.from(this.connectedClients.values())
                .filter(c => c.status === 'online');

            if (onlineClients.length === 0) {
                console.log('No online clients available');
                return;
            }

            console.log(`\nExecuting on ALL ${onlineClients.length} online clients:`);
            console.log(`Command: ${command}`);
            
            const response = await this.request('POST', '/api/clients/execute-all', {
                command,
                timeout: 30000
            });

            const results = response.data.results;
            const summary = response.data.summary;

            console.log(`\n--- Execution Results ---`);
            console.log(`Total: ${summary.total} | Queued: ${summary.successful} | Failed: ${summary.failed}`);
            
            for (const [clientId, result] of Object.entries(results)) {
                const client = this.connectedClients.get(clientId);
                const hostname = client ? client.hostname : 'Unknown';
                
                if (result.success) {
                    console.log(`✓ ${hostname}: Queued - ${result.commandId}`);
                } else {
                    console.log(`✗ ${hostname}: ${result.error}`);
                }
            }

            return response.data;
        } catch (error) {
            console.error('✗ All-client execution failed:', error.error || error.message);
            throw error;
        }
    }

    async getClientLogs(clientId, lines = 50) {
        try {
            const client = this.connectedClients.get(clientId);
            if (!client) {
                throw new Error('Client not found');
            }

            const response = await this.request('GET', `/api/clients/${clientId}/logs?lines=${lines}`);
            const logs = response.data;

            console.log(`\n=== Logs for ${logs.hostname} (${logs.date}) ===`);
            if (logs.logs.length === 0) {
                console.log('No logs available');
            } else {
                logs.logs.forEach(log => {
                    const timestamp = new Date(log.timestamp).toLocaleTimeString();
                    const level = log.level || 'INFO';
                    const message = log.message || JSON.stringify(log);
                    console.log(`[${timestamp}] ${level}: ${message}`);
                });
            }
            console.log(`Total: ${logs.total} log entries\n`);

            return logs;
        } catch (error) {
            console.error('✗ Failed to get client logs:', error.error || error.message);
            throw error;
        }
    }

    listClients() {
        if (this.connectedClients.size === 0) {
            console.log('No clients registered');
            return;
        }

        console.log('\n=== Registered Clients ===');
        console.log('ID'.padEnd(25), 'HOSTNAME'.padEnd(20), 'PLATFORM'.padEnd(12), 'STATUS'.padEnd(10));
        console.log('-'.repeat(70));
        
        for (const [clientId, client] of this.connectedClients) {
            const statusIcon = client.status === 'online' ? '🟢' : '🔴';
            console.log(
                `${statusIcon} ${clientId.substring(0, 22)}`.padEnd(25),
                client.hostname.substring(0, 18).padEnd(20),
                client.platform.padEnd(12),
                client.status.padEnd(10)
            );
        }
        console.log('');
    }

    getClientById(identifier) {
        // Try exact clientId match first
        if (this.connectedClients.has(identifier)) {
            return identifier;
        }

        // Try hostname match
        for (const [clientId, client] of this.connectedClients) {
            if (client.hostname.toLowerCase().includes(identifier.toLowerCase())) {
                return clientId;
            }
        }

        return null;
    }
}

// Interactive CLI
async function startMultiServerCLI() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: 'multi-admin> '
    });

    const admin = new MultiServerAdmin();
    
    console.log('================================================');
    console.log('    Multi-Server Network Administration CLI    ');
    console.log('================================================');
    console.log('Manage your entire server network from one place\n');
    
    // Login
    console.log('Please login to the main server:');
    const username = await new Promise(resolve => {
        rl.question('Username: ', resolve);
    });
    
    const password = await new Promise(resolve => {
        rl.question('Password: ', (answer) => {
            console.log('');
            resolve(answer);
        });
        rl.stdoutMuted = true;
        rl._writeToOutput = function _writeToOutput(stringToWrite) {
            if (!rl.stdoutMuted) {
                rl.output.write(stringToWrite);
            } else {
                rl.output.write('*');
            }
        };
    });
    rl.stdoutMuted = false;
    rl._writeToOutput = function _writeToOutput(stringToWrite) {
        rl.output.write(stringToWrite);
    };
    
    const loginSuccess = await admin.login(username, password);
    if (!loginSuccess) {
        console.log('Authentication failed. Exiting...');
        process.exit(1);
    }

    console.log('\n✓ Connected to multi-server network\n');

    // Command handlers
    const commands = {
        help: () => {
            console.log('\nMulti-Server Commands:');
            console.log('  dashboard          - Show network overview dashboard');
            console.log('  list               - List all registered clients');
            console.log('  refresh            - Refresh client list');
            console.log('  exec <client> <cmd> - Execute command on specific client');
            console.log('  exec-multi <ids> <cmd> - Execute on multiple clients (comma-separated)');
            console.log('  exec-all <cmd>     - Execute command on all online clients');
            console.log('  logs <client>      - View logs from specific client');
            console.log('  health             - Check main server health');
            console.log('  clear              - Clear screen');
            console.log('  exit               - Exit multi-server admin');
            console.log('\nExamples:');
            console.log('  exec win-server-01 "Get-Process | Select -First 5"');
            console.log('  exec-all "systeminfo | findstr /C:\\"Total Physical Memory\\""');
            console.log('  logs win-server-01');
            console.log('');
        }
    };

    // Show initial dashboard
    await admin.showDashboard();
    
    // Main command loop
    rl.prompt();
    
    rl.on('line', async (line) => {
        const [cmd, ...args] = line.trim().split(' ');
        
        try {
            switch (cmd) {
                case 'help':
                case '?':
                    commands.help();
                    break;

                case 'dashboard':
                case 'dash':
                    await admin.showDashboard();
                    break;

                case 'list':
                case 'ls':
                    admin.listClients();
                    break;

                case 'refresh':
                    await admin.refreshClientList();
                    break;

                case 'exec':
                    if (args.length < 2) {
                        console.log('Usage: exec <client-id-or-hostname> <command>');
                    } else {
                        const clientIdentifier = args[0];
                        const command = args.slice(1).join(' ');
                        const clientId = admin.getClientById(clientIdentifier);
                        
                        if (!clientId) {
                            console.log(`Client '${clientIdentifier}' not found. Use 'list' to see available clients.`);
                        } else {
                            await admin.executeOnClient(clientId, command);
                        }
                    }
                    break;

                case 'exec-multi':
                    if (args.length < 2) {
                        console.log('Usage: exec-multi <client1,client2,client3> <command>');
                    } else {
                        const clientIdentifiers = args[0].split(',');
                        const command = args.slice(1).join(' ');
                        
                        const clientIds = clientIdentifiers.map(id => admin.getClientById(id.trim())).filter(Boolean);
                        
                        if (clientIds.length === 0) {
                            console.log('No valid clients found');
                        } else {
                            await admin.executeOnMultipleClients(clientIds, command);
                        }
                    }
                    break;

                case 'exec-all':
                    if (args.length === 0) {
                        console.log('Usage: exec-all <command>');
                    } else {
                        const command = args.join(' ');
                        await admin.executeOnAllClients(command);
                    }
                    break;

                case 'logs':
                    if (args.length === 0) {
                        console.log('Usage: logs <client-id-or-hostname> [lines]');
                    } else {
                        const clientIdentifier = args[0];
                        const lines = args[1] ? parseInt(args[1]) : 50;
                        const clientId = admin.getClientById(clientIdentifier);
                        
                        if (!clientId) {
                            console.log(`Client '${clientIdentifier}' not found`);
                        } else {
                            await admin.getClientLogs(clientId, lines);
                        }
                    }
                    break;

                case 'health':
                    try {
                        const health = await admin.request('GET', '/api/health');
                        console.log('✓ Main server is healthy');
                        console.log(`  Status: ${health.data.status}`);
                        console.log(`  Uptime: ${Math.floor(health.data.uptime / 60)} minutes`);
                    } catch (error) {
                        console.log('✗ Main server health check failed:', error.error);
                    }
                    break;

                case 'clear':
                case 'cls':
                    console.clear();
                    console.log('Multi-Server Admin CLI - Connected to', MAIN_SERVER_IP);
                    break;

                case 'exit':
                case 'quit':
                case 'q':
                    console.log('\nDisconnecting from multi-server network...');
                    rl.close();
                    process.exit(0);
                    break;

                case '':
                    break;

                default:
                    console.log(`Unknown command: ${cmd}`);
                    console.log('Type "help" for available commands');
            }
        } catch (error) {
            console.error('Error:', error.message || error);
        }
        
        rl.prompt();
    });

    rl.on('close', () => {
        console.log('\nMulti-server session ended');
        process.exit(0);
    });
}

// Main execution
if (require.main === module) {
    startMultiServerCLI().catch(console.error);
}

module.exports = MultiServerAdmin;