// framework/lib/execution/CommandExecutor.js
const { exec, spawn } = require('child_process');
const util = require('util');
const { v4: uuidv4 } = require('uuid');
const execPromise = util.promisify(exec);

class CommandExecutor {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.commandHistory = [];
        this.activeCommands = new Map();
        
        // Safe commands for restricted mode
        this.allowedCommands = new Set([
            'ls', 'pwd', 'whoami', 'date', 'uptime', 'df', 'free',
            'ps', 'top', 'htop', 'netstat', 'ss', 'ip', 'hostname', 'uname',
            'cat', 'grep', 'tail', 'head', 'wc', 'find', 'du', 'which',
            'systemctl', 'service', 'mount', 'lsblk', 'lsof', 'iptables',
            'journalctl', 'dmesg', 'lscpu', 'lsmem', 'lsusb', 'lspci'
        ]);
        
        // Dangerous patterns to block
        this.blockedPatterns = [
            /rm\s+-rf/gi,
            />\s*\/dev\/sda/gi,
            /mkfs/gi,
            /dd\s+if=/gi,
            /format/gi,
            /del\s+\/f/gi,
            /sudo\s+chmod\s+777/gi,
            /\/etc\/passwd/gi,
            /\/etc\/shadow/gi,
            /shutdown/gi,
            /reboot/gi,
            /halt/gi,
            /init\s+0/gi,
            /init\s+6/gi,
            /poweroff/gi,
            /wall\s/gi,
            /write\s/gi,
            /fork\(\)/gi,
            /while\s*\[\s*1/gi,
            /:\(\)\{.*:\|:&\}/gi // Fork bomb
        ];
    }

    sanitizeCommand(command) {
        let sanitized = command.trim();
        
        // Check for blocked patterns
        for (const pattern of this.blockedPatterns) {
            if (pattern.test(sanitized)) {
                throw new Error(`Command contains blocked pattern: ${pattern.source}`);
            }
        }
        
        // Check if in restricted mode
        if (this.config.get('RESTRICT_COMMANDS') === 'true') {
            const baseCommand = sanitized.split(' ')[0];
            if (!this.allowedCommands.has(baseCommand)) {
                throw new Error(`Command '${baseCommand}' is not in allowed list`);
            }
        }
        
        // Additional safety checks
        if (sanitized.length > 1000) {
            throw new Error('Command too long');
        }
        
        if (sanitized.includes('$(') || sanitized.includes('`')) {
            throw new Error('Command substitution not allowed');
        }
        
        return sanitized;
    }

    async execute(command, userId, ip) {
        const commandId = uuidv4();
        const startTime = Date.now();
        
        try {
            const sanitizedCommand = this.sanitizeCommand(command);
            
            this.logger.info({
                type: 'COMMAND_EXECUTION_START',
                commandId,
                userId,
                ip,
                command: sanitizedCommand,
                timestamp: new Date().toISOString()
            });
            
            // Execute with timeout and limits
            const result = await this.executeWithLimits(sanitizedCommand, {
                timeout: this.config.get('COMMAND_TIMEOUT', 30000),
                maxBuffer: this.config.get('COMMAND_MAX_BUFFER', 1024 * 1024 * 10)
            });
            
            const executionTime = Date.now() - startTime;
            
            // Add to command history
            this.addToHistory({
                commandId,
                command: sanitizedCommand,
                userId,
                ip,
                timestamp: new Date().toISOString(),
                executionTime,
                success: true,
                outputSize: result.stdout.length + result.stderr.length
            });
            
            this.logger.commandLog(commandId, userId, sanitizedCommand, true, {
                executionTime,
                outputSize: result.stdout.length + result.stderr.length
            }, ip);
            
            return {
                success: true,
                commandId,
                stdout: result.stdout,
                stderr: result.stderr,
                executionTime
            };
            
        } catch (error) {
            const executionTime = Date.now() - startTime;
            
            // Add failed command to history
            this.addToHistory({
                commandId,
                command: command, // Original command for debugging
                userId,
                ip,
                timestamp: new Date().toISOString(),
                executionTime,
                success: false,
                error: error.message
            });
            
            this.logger.commandLog(commandId, userId, '[SANITIZED]', false, {
                error: error.message,
                executionTime
            }, ip);
            
            throw error;
        }
    }

    async executeWithLimits(command, options = {}) {
        const {
            timeout = 30000,
            maxBuffer = 1024 * 1024 * 10,
            shell = '/bin/bash'
        } = options;

        return new Promise((resolve, reject) => {
            const child = exec(command, {
                timeout,
                maxBuffer,
                shell,
                env: {
                    ...process.env,
                    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                }
            }, (error, stdout, stderr) => {
                if (error) {
                    if (error.code === 'ETIMEDOUT') {
                        reject(new Error(`Command timeout after ${timeout}ms`));
                    } else if (error.code === 'EMAXBUFFER') {
                        reject(new Error('Command output too large'));
                    } else {
                        reject(error);
                    }
                } else {
                    resolve({ stdout, stderr });
                }
            });

            // Track active command
            const commandId = uuidv4();
            this.activeCommands.set(commandId, child);

            child.on('exit', () => {
                this.activeCommands.delete(commandId);
            });
        });
    }

    addToHistory(commandRecord) {
        this.commandHistory.push(commandRecord);
        
        // Keep only last 1000 commands
        if (this.commandHistory.length > 1000) {
            this.commandHistory.shift();
        }
    }

    getCommandHistory(limit = 50) {
        return this.commandHistory
            .slice(-limit)
            .map(record => ({
                commandId: record.commandId,
                command: record.success ? record.command : '[FAILED]',
                userId: record.userId,
                timestamp: record.timestamp,
                executionTime: record.executionTime,
                success: record.success,
                outputSize: record.outputSize,
                error: record.error
            }));
    }

    getAllowedCommands() {
        return Array.from(this.allowedCommands);
    }

    getActiveCommands() {
        return Array.from(this.activeCommands.keys());
    }

    killActiveCommand(commandId) {
        const process = this.activeCommands.get(commandId);
        if (process) {
            process.kill('SIGTERM');
            this.activeCommands.delete(commandId);
            return true;
        }
        return false;
    }

    killAllActiveCommands() {
        let killed = 0;
        for (const [commandId, process] of this.activeCommands) {
            try {
                process.kill('SIGTERM');
                killed++;
            } catch (error) {
                this.logger.warn(`Failed to kill command ${commandId}:`, error.message);
            }
        }
        this.activeCommands.clear();
        return killed;
    }

    // System information commands
    async getSystemInfo() {
        try {
            const [uptime, memory, disk, load] = await Promise.all([
                execPromise('uptime'),
                execPromise('free -h'),
                execPromise('df -h'),
                execPromise('cat /proc/loadavg')
            ]);

            return {
                uptime: uptime.stdout.trim(),
                memory: memory.stdout,
                disk: disk.stdout,
                load: load.stdout.trim(),
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to get system info: ${error.message}`);
        }
    }

    async getProcessList(limit = 20) {
        try {
            const { stdout } = await execPromise(`ps aux --sort=-%cpu | head -${parseInt(limit) + 1}`);

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

            return {
                processes,
                total: processes.length,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to get process list: ${error.message}`);
        }
    }

    async getNetworkConnections() {
        try {
            const { stdout } = await execPromise('ss -tuln');
            return {
                connections: stdout,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`Failed to get network connections: ${error.message}`);
        }
    }

    // Security: Add command to allowed list (admin only)
    addAllowedCommand(command) {
        this.allowedCommands.add(command);
        this.logger.auditLog('system', 'COMMAND_WHITELIST_UPDATED', {
            action: 'add',
            command
        }, null, true);
    }

    // Security: Remove command from allowed list (admin only)
    removeAllowedCommand(command) {
        this.allowedCommands.delete(command);
        this.logger.auditLog('system', 'COMMAND_WHITELIST_UPDATED', {
            action: 'remove',
            command
        }, null, true);
    }

    // Get execution statistics
    getExecutionStats() {
        const recentCommands = this.commandHistory.slice(-100);
        const successful = recentCommands.filter(cmd => cmd.success).length;
        const failed = recentCommands.length - successful;
        
        const avgExecutionTime = recentCommands.length > 0
            ? recentCommands.reduce((sum, cmd) => sum + cmd.executionTime, 0) / recentCommands.length
            : 0;

        const commandsByUser = {};
        recentCommands.forEach(cmd => {
            commandsByUser[cmd.userId] = (commandsByUser[cmd.userId] || 0) + 1;
        });

        return {
            total: this.commandHistory.length,
            recent: recentCommands.length,
            successful,
            failed,
            successRate: recentCommands.length > 0 ? (successful / recentCommands.length * 100).toFixed(2) : 0,
            avgExecutionTime: Math.round(avgExecutionTime),
            activeCommands: this.activeCommands.size,
            commandsByUser,
            restrictedMode: this.config.get('RESTRICT_COMMANDS') === 'true',
            allowedCommandsCount: this.allowedCommands.size
        };
    }

    // Batch command execution
    async executeBatch(commands, userId, ip) {
        const batchId = uuidv4();
        const results = [];
        
        this.logger.info({
            type: 'BATCH_EXECUTION_START',
            batchId,
            commandCount: commands.length,
            userId,
            ip
        });

        for (let i = 0; i < commands.length; i++) {
            try {
                const result = await this.execute(commands[i], userId, ip);
                results.push({
                    index: i,
                    command: commands[i],
                    ...result
                });
            } catch (error) {
                results.push({
                    index: i,
                    command: commands[i],
                    success: false,
                    error: error.message
                });
            }
        }

        this.logger.info({
            type: 'BATCH_EXECUTION_COMPLETE',
            batchId,
            successful: results.filter(r => r.success).length,
            failed: results.filter(r => !r.success).length
        });

        return {
            batchId,
            results,
            summary: {
                total: commands.length,
                successful: results.filter(r => r.success).length,
                failed: results.filter(r => !r.success).length
            }
        };
    }

    // Scheduled command execution
    scheduleCommand(command, userId, delay, metadata = {}) {
        const scheduledId = uuidv4();
        
        this.logger.info({
            type: 'COMMAND_SCHEDULED',
            scheduledId,
            command: command.length > 100 ? command.substring(0, 100) + '...' : command,
            userId,
            delay,
            executeAt: new Date(Date.now() + delay).toISOString()
        });

        setTimeout(async () => {
            try {
                await this.execute(command, userId, metadata.ip);
                this.logger.info(`Scheduled command executed: ${scheduledId}`);
            } catch (error) {
                this.logger.error(`Scheduled command failed: ${scheduledId}`, error);
            }
        }, delay);

        return {
            scheduledId,
            executeAt: new Date(Date.now() + delay).toISOString()
        };
    }

    // Command validation without execution
    validateCommand(command) {
        try {
            this.sanitizeCommand(command);
            return {
                valid: true,
                command: command.trim()
            };
        } catch (error) {
            return {
                valid: false,
                error: error.message,
                command: command.trim()
            };
        }
    }

    // Get blocked patterns (for admin interface)
    getBlockedPatterns() {
        return this.blockedPatterns.map(pattern => pattern.source);
    }

    // Add blocked pattern (admin only)
    addBlockedPattern(pattern) {
        try {
            const regex = new RegExp(pattern, 'gi');
            this.blockedPatterns.push(regex);
            
            this.logger.auditLog('system', 'BLOCKED_PATTERN_ADDED', {
                pattern
            }, null, true);
            
            return { success: true };
        } catch (error) {
            throw new Error(`Invalid regex pattern: ${error.message}`);
        }
    }

    // Remove blocked pattern (admin only)
    removeBlockedPattern(index) {
        if (index >= 0 && index < this.blockedPatterns.length) {
            const removed = this.blockedPatterns.splice(index, 1)[0];
            
            this.logger.auditLog('system', 'BLOCKED_PATTERN_REMOVED', {
                pattern: removed.source
            }, null, true);
            
            return { success: true, removed: removed.source };
        }
        throw new Error('Invalid pattern index');
    }
}

module.exports = CommandExecutor;