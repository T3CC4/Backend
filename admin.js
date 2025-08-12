#!/usr/bin/env node

// admin.js - Administrative client for the Secure Backend Framework
const http = require('http');
const https = require('https');
const readline = require('readline');

// Server configuration - hardcoded for your backend
const SERVER_IP = '45.131.109.191';
const SERVER_PORT = 80;
const SERVER_URL = `http://${SERVER_IP}:${SERVER_PORT}`;

class AdminClient {
    constructor() {
        this.serverIP = SERVER_IP;
        this.serverPort = SERVER_PORT;
        this.baseUrl = SERVER_URL;
        this.token = null;
        
        // Command history
        this.history = [];
        this.historyIndex = -1;
    }

    // HTTP request helper
    async request(method, path, data = null) {
        const options = {
            hostname: this.serverIP,
            port: this.serverPort,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'User-Agent': 'SecureBackendFramework-AdminClient/1.0'
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
                    reject({ error: `Cannot connect to server at ${this.baseUrl}` });
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

    // Authentication
    async login(username, password) {
        try {
            console.log(`\nConnecting to ${this.baseUrl}...`);
            const response = await this.request('POST', '/api/auth/login', {
                username,
                password
            });
            
            this.token = response.data.token;
            console.log('✓ Login successful');
            console.log(`  Token expires in: ${response.data.expiresIn} seconds`);
            return response.data;
        } catch (error) {
            console.error('✗ Login failed:', error.error || error.message);
            throw error;
        }
    }

    // Execute command
    async executeCommand(command) {
        try {
            // Add to history
            if (command && !this.history.includes(command)) {
                this.history.push(command);
                if (this.history.length > 100) {
                    this.history.shift();
                }
            }

            const response = await this.request('POST', '/api/execute', { command });
            const data = response.data;
            
            console.log('✓ Command executed');
            console.log('  ID:', data.commandId);
            console.log('  Time:', data.executionTime + 'ms');
            
            if (data.stdout) {
                console.log('\n--- Output ---');
                console.log(data.stdout);
                if (!data.stdout.endsWith('\n')) console.log('');
            }
            
            if (data.stderr) {
                console.log('\n--- Errors ---');
                console.log(data.stderr);
            }
            
            return data;
        } catch (error) {
            console.error('✗ Command failed:', error.error || error.message);
            throw error;
        }
    }

    // Get system information
    async getSystemInfo() {
        try {
            const response = await this.request('GET', '/api/system/info');
            return response.data;
        } catch (error) {
            console.error('✗ Failed to get system info:', error.error || error.message);
            throw error;
        }
    }

    // Get logs
    async getLogs(type = 'combined', lines = 50) {
        try {
            const response = await this.request('GET', `/api/logs?type=${type}&lines=${lines}`);
            return response.data;
        } catch (error) {
            console.error('✗ Failed to get logs:', error.error || error.message);
            throw error;
        }
    }

    // Get process list
    async getProcesses() {
        try {
            const response = await this.request('GET', '/api/processes');
            return response.data;
        } catch (error) {
            console.error('✗ Failed to get processes:', error.error || error.message);
            throw error;
        }
    }

    // Get network connections
    async getNetworkConnections() {
        try {
            const response = await this.request('GET', '/api/network/connections');
            return response.data;
        } catch (error) {
            console.error('✗ Failed to get network connections:', error.error || error.message);
            throw error;
        }
    }

    // Health check
    async healthCheck() {
        try {
            const response = await this.request('GET', '/api/health');
            console.log('✓ Server is healthy');
            console.log('  Status:', response.data.status);
            console.log('  Uptime:', Math.floor(response.data.uptime / 60), 'minutes');
            return response.data;
        } catch (error) {
            console.error('✗ Server unreachable:', error.error || error.message);
            throw error;
        }
    }

    // Server stats dashboard
    async showDashboard() {
        try {
            console.log('\n' + '='.repeat(60));
            console.log('             SERVER DASHBOARD');
            console.log('='.repeat(60));

            // Health check
            const health = await this.request('GET', '/api/health');
            console.log(`Status: ${health.data.status} | Uptime: ${Math.floor(health.data.uptime / 60)}min`);

            // System info
            const sysInfo = await this.getSystemInfo();
            console.log('\n--- System Information ---');
            console.log(sysInfo.uptime.trim());
            console.log('Load:', sysInfo.load);

            // Top processes
            const processes = await this.getProcesses();
            console.log('\n--- Top Processes (CPU) ---');
            console.log('PID      USER         CPU   MEM   COMMAND');
            console.log('-'.repeat(60));
            processes.processes.slice(0, 8).forEach(p => {
                const cmd = p.command.length > 25 ? p.command.substring(0, 22) + '...' : p.command;
                console.log(
                    p.pid.toString().padEnd(8),
                    p.user.substring(0, 12).padEnd(12),
                    (p.cpu + '%').padEnd(6),
                    (p.mem + '%').padEnd(6),
                    cmd
                );
            });

            console.log('\n' + '='.repeat(60));

        } catch (error) {
            console.error('✗ Failed to load dashboard:', error.error || error.message);
        }
    }
}

// Interactive CLI
async function startCLI() {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
        prompt: 'admin> ',
        historySize: 100
    });

    const client = new AdminClient();
    
    console.log('==========================================');
    console.log('    Secure Backend Framework Admin CLI    ');
    console.log('==========================================');
    console.log('Type "help" for commands\n');
    
    // Check server connection
    console.log('Checking server connection...');
    try {
        await client.healthCheck();
        console.log('');
    } catch (error) {
        console.error('\n⚠ Warning: Server may be unreachable\n');
    }

    // Login
    console.log('Please login to the backend:');
    const username = await new Promise(resolve => {
        rl.question('Username: ', resolve);
    });
    
    // Hide password input
    const password = await new Promise(resolve => {
        rl.question('Password: ', (answer) => {
            console.log('');
            resolve(answer);
        });
        // Mask password input
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
    
    try {
        await client.login(username, password);
        console.log('\n✓ Connected to backend\n');
    } catch (error) {
        console.error('\n✗ Authentication failed');
        console.error('Check your credentials and try again.\n');
        process.exit(1);
    }
    
    // Command handlers
    const commands = {
        help: () => {
            console.log('\nAvailable Commands:');
            console.log('  exec <cmd>       - Execute command on server');
            console.log('  dashboard        - Show server dashboard');
            console.log('  sys              - Show system information');
            console.log('  ps               - Show running processes');
            console.log('  net              - Show network connections');
            console.log('  logs [type]      - Show logs (combined/error/security/audit)');
            console.log('  health           - Check server health');
            console.log('  history          - Show command history');
            console.log('  clear            - Clear screen');
            console.log('  exit             - Disconnect and exit');
            console.log('\nTip: Use arrow keys for command history\n');
        }
    };
    
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
                    
                case 'clear':
                case 'cls':
                    console.clear();
                    console.log('Framework Admin CLI - Connected to', SERVER_IP);
                    break;

                case 'dashboard':
                case 'dash':
                    await client.showDashboard();
                    break;
                    
                case 'exec':
                case 'run':
                case '$':
                    if (args.length === 0) {
                        console.log('Usage: exec <command>');
                    } else {
                        await client.executeCommand(args.join(' '));
                    }
                    break;
                    
                case 'sys':
                case 'sysinfo':
                case 'system':
                    const sysInfo = await client.getSystemInfo();
                    console.log('\n=== System Information ===');
                    console.log(sysInfo.uptime);
                    console.log('Load:', sysInfo.load);
                    console.log('\nMemory:');
                    console.log(sysInfo.memory);
                    console.log('\nDisk Usage:');
                    console.log(sysInfo.disk);
                    break;
                    
                case 'ps':
                case 'processes':
                case 'proc':
                    const procs = await client.getProcesses();
                    console.log('\n=== Top Processes (by CPU) ===');
                    console.log('PID      USER         CPU   MEM   COMMAND');
                    console.log('-'.repeat(70));
                    procs.processes.slice(0, 15).forEach(p => {
                        const cmd = p.command.length > 40 ? p.command.substring(0, 37) + '...' : p.command;
                        console.log(
                            p.pid.toString().padEnd(8),
                            p.user.substring(0, 12).padEnd(12),
                            (p.cpu + '%').padEnd(6),
                            (p.mem + '%').padEnd(6),
                            cmd
                        );
                    });
                    console.log('');
                    break;
                    
                case 'net':
                case 'network':
                case 'netstat':
                    const net = await client.getNetworkConnections();
                    console.log('\n=== Network Connections ===');
                    console.log(net.connections);
                    break;
                    
                case 'logs':
                case 'log':
                    const logType = args[0] || 'combined';
                    const validTypes = ['combined', 'error', 'security', 'audit'];
                    
                    if (!validTypes.includes(logType)) {
                        console.log('Valid log types: combined, error, security, audit');
                    } else {
                        const logs = await client.getLogs(logType, 25);
                        console.log(`\n=== ${logType.toUpperCase()} Logs (last 25) ===`);
                        logs.lines.forEach(line => {
                            console.log(line);
                        });
                        console.log('');
                    }
                    break;

                case 'history':
                case 'hist':
                    console.log('\n=== Command History ===');
                    client.history.forEach((cmd, index) => {
                        console.log(`${(index + 1).toString().padStart(3)}: ${cmd}`);
                    });
                    console.log('');
                    break;
                    
                case 'health':
                case 'status':
                    await client.healthCheck();
                    break;
                    
                case 'exit':
                case 'quit':
                case 'q':
                    console.log('\nDisconnecting from backend...');
                    rl.close();
                    process.exit(0);
                    break;
                    
                case '':
                    // Empty line, just show prompt again
                    break;
                    
                default:
                    console.log(`Unknown command: ${cmd}`);
                    console.log('Type "help" for available commands');
            }
        } catch (error) {
            console.error('Error:', error.error || error.message);
        }
        
        rl.prompt();
    });
    
    rl.on('close', () => {
        console.log('\nConnection closed');
        process.exit(0);
    });

    // Handle Ctrl+C gracefully
    rl.on('SIGINT', () => {
        console.log('\nUse "exit" to quit gracefully');
        rl.prompt();
    });
}

// Quick test mode
async function quickTest(username, password) {
    const client = new AdminClient();
    
    console.log(`Testing connection to ${SERVER_URL}...`);
    
    try {
        // Test health
        await client.healthCheck();
        
        // Test login
        await client.login(username, password);
        
        // Test command execution
        console.log('\nTesting command execution...');
        await client.executeCommand('whoami');
        await client.executeCommand('pwd');
        
        console.log('\n✓ All tests passed!');
        console.log('Backend is fully operational.\n');
        
    } catch (error) {
        console.error('\n✗ Test failed:', error.error || error.message);
        process.exit(1);
    }
}

// Main execution
if (require.main === module) {
    const args = process.argv.slice(2);
    
    console.log('Secure Backend Framework - Admin Client');
    console.log(`Server: ${SERVER_URL}\n`);
    
    if (args.length === 0) {
        // Default: start interactive CLI
        startCLI().catch(console.error);
    } else if (args[0] === 'test' && args.length === 3) {
        // Test mode: node admin.js test username password
        quickTest(args[1], args[2]).catch(console.error);
    } else if (args[0] === 'health') {
        // Quick health check: node admin.js health
        const client = new AdminClient();
        client.healthCheck().catch(() => process.exit(1));
    } else {
        console.log('Usage:');
        console.log('  node admin.js                      # Interactive mode');
        console.log('  node admin.js test user pass       # Quick test');
        console.log('  node admin.js health                # Health check');
        console.log(`\nServer: ${SERVER_URL}`);
        process.exit(0);
    }
}

module.exports = AdminClient;