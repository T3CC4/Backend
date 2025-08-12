// framework/lib/routes/ClientRoutes.js
const express = require('express');

class ClientRoutes {
    constructor(config, logger, auth, clientManager) {
        this.config = config;
        this.logger = logger;
        this.auth = auth;
        this.clientManager = clientManager;
    }

    createRoutes() {
        const router = express.Router();

        // Client registration
        router.post('/register', async (req, res) => {
            try {
                const result = await this.clientManager.registerClient(req.body);
                res.json(result);
            } catch (error) {
                this.logger.error('Client registration error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Client unregistration
        router.post('/unregister', this.validateClientAuth(), async (req, res) => {
            try {
                const { clientId } = req.body;
                const result = await this.clientManager.unregisterClient(clientId);
                res.json(result);
            } catch (error) {
                this.logger.error('Client unregistration error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Heartbeat endpoint
        router.post('/heartbeat', this.validateClientAuth(), async (req, res) => {
            try {
                const clientId = req.headers['x-client-id'];
                const result = await this.clientManager.handleHeartbeat(clientId, req.body);
                res.json(result);
            } catch (error) {
                this.logger.error('Heartbeat error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Get commands for client
        router.get('/:clientId/commands', this.validateClientAuth(), async (req, res) => {
            try {
                const { clientId } = req.params;
                const result = await this.clientManager.getClientCommands(clientId);
                res.json(result);
            } catch (error) {
                this.logger.error('Get commands error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Command acknowledgment
        router.post('/:clientId/commands/:commandId/ack', this.validateClientAuth(), async (req, res) => {
            try {
                const { clientId, commandId } = req.params;
                const result = await this.clientManager.acknowledgeCommand(clientId, commandId);
                res.json(result);
            } catch (error) {
                this.logger.error('Command ack error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Command result submission
        router.post('/:clientId/commands/:commandId/result', this.validateClientAuth(), async (req, res) => {
            try {
                const { clientId, commandId } = req.params;
                const { result, metadata } = req.body;
                const submitResult = await this.clientManager.receiveCommandResult(clientId, commandId, result, metadata);
                res.json(submitResult);
            } catch (error) {
                this.logger.error('Command result error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Log submission
        router.post('/logs', this.validateClientAuth(), async (req, res) => {
            try {
                const { clientId, logs } = req.body;
                const result = await this.clientManager.receiveClientLogs(clientId, logs);
                res.json(result);
            } catch (error) {
                this.logger.error('Log submission error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Admin routes (require authentication)
        
        // List all clients
        router.get('/', ...this.auth.getAuthMiddleware(), (req, res) => {
            try {
                const clients = this.clientManager.getAllClients();
                res.json({
                    clients,
                    total: clients.length,
                    online: clients.filter(c => c.status === 'online').length,
                    offline: clients.filter(c => c.status === 'offline').length
                });
            } catch (error) {
                this.logger.error('List clients error:', error);
                res.status(500).json({ error: 'Failed to list clients' });
            }
        });

        // Get specific client
        router.get('/:clientId', ...this.auth.getAuthMiddleware(), (req, res) => {
            try {
                const { clientId } = req.params;
                const client = this.clientManager.getClient(clientId);
                
                if (!client) {
                    return res.status(404).json({ error: 'Client not found' });
                }
                
                res.json(client);
            } catch (error) {
                this.logger.error('Get client error:', error);
                res.status(500).json({ error: 'Failed to get client' });
            }
        });

        // Execute command on client
        router.post('/:clientId/execute', ...this.auth.getAuthMiddleware(), async (req, res) => {
            try {
                const { clientId } = req.params;
                const { command, timeout, metadata } = req.body;
                
                if (!command) {
                    return res.status(400).json({ error: 'Command is required' });
                }

                const result = await this.clientManager.executeCommandOnClient(
                    clientId, 
                    command, 
                    req.user.username, 
                    req.ip,
                    { timeout, ...metadata }
                );
                
                res.json(result);
            } catch (error) {
                this.logger.error('Execute command error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Execute command on multiple clients
        router.post('/execute-multi', ...this.auth.getAuthMiddleware(), async (req, res) => {
            try {
                const { clientIds, command, timeout, metadata } = req.body;
                
                if (!clientIds || !Array.isArray(clientIds) || clientIds.length === 0) {
                    return res.status(400).json({ error: 'Client IDs array is required' });
                }
                
                if (!command) {
                    return res.status(400).json({ error: 'Command is required' });
                }

                const results = await this.clientManager.executeCommandOnMultipleClients(
                    clientIds, 
                    command, 
                    req.user.username, 
                    req.ip,
                    { timeout, ...metadata }
                );
                
                res.json({
                    results,
                    summary: {
                        total: clientIds.length,
                        successful: Object.values(results).filter(r => r.success).length,
                        failed: Object.values(results).filter(r => !r.success).length
                    }
                });
            } catch (error) {
                this.logger.error('Execute multi command error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Execute command on all online clients
        router.post('/execute-all', ...this.auth.getAuthMiddleware(), async (req, res) => {
            try {
                const { command, timeout, metadata } = req.body;
                
                if (!command) {
                    return res.status(400).json({ error: 'Command is required' });
                }

                const results = await this.clientManager.executeCommandOnAllClients(
                    command, 
                    req.user.username, 
                    req.ip,
                    { timeout, ...metadata }
                );
                
                res.json({
                    results,
                    summary: {
                        total: Object.keys(results).length,
                        successful: Object.values(results).filter(r => r.success).length,
                        failed: Object.values(results).filter(r => !r.success).length
                    }
                });
            } catch (error) {
                this.logger.error('Execute all command error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Get client logs
        router.get('/:clientId/logs', ...this.auth.getAuthMiddleware(), async (req, res) => {
            try {
                const { clientId } = req.params;
                const { date, lines = 100 } = req.query;
                
                const logs = await this.clientManager.getClientLogs(clientId, date, parseInt(lines));
                res.json(logs);
            } catch (error) {
                this.logger.error('Get client logs error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Remove client
        router.delete('/:clientId', ...this.auth.getAdminMiddleware(), async (req, res) => {
            try {
                const { clientId } = req.params;
                const result = await this.clientManager.removeClient(clientId);
                
                this.logger.auditLog(req.user.username, 'CLIENT_REMOVED', {
                    clientId
                }, req.ip, true);
                
                res.json(result);
            } catch (error) {
                this.logger.error('Remove client error:', error);
                res.status(400).json({ 
                    success: false, 
                    error: error.message 
                });
            }
        });

        // Get client statistics
        router.get('/stats/overview', ...this.auth.getAuthMiddleware(), (req, res) => {
            try {
                const stats = this.clientManager.getClientStats();
                res.json(stats);
            } catch (error) {
                this.logger.error('Get client stats error:', error);
                res.status(500).json({ error: 'Failed to get client statistics' });
            }
        });

        return router;
    }

    // Client authentication middleware
    validateClientAuth() {
        return (req, res, next) => {
            const clientId = req.headers['x-client-id'];
            const authHeader = req.headers.authorization;

            if (!clientId) {
                return res.status(401).json({ error: 'Client ID required' });
            }

            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Client token required' });
            }

            const token = authHeader.split(' ')[1];
            
            // Validate client token (simple HMAC validation)
            try {
                const client = this.clientManager.getClient(clientId);
                if (!client) {
                    return res.status(401).json({ error: 'Client not registered' });
                }

                // In a real implementation, you'd validate the token properly
                // For now, just check if client exists
                req.clientId = clientId;
                req.client = client;
                next();
            } catch (error) {
                this.logger.securityLog('CLIENT_AUTH_FAILURE', {
                    clientId,
                    error: error.message
                }, req.ip);
                
                res.status(401).json({ error: 'Invalid client token' });
            }
        };
    }
}

module.exports = ClientRoutes;