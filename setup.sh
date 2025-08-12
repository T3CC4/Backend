#!/bin/bash
# setup.sh - Complete Node.js Backend Server Setup for Debian 11
# Run as root or with sudo

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

APP_DIR="/opt/nodejs-backend"
APP_USER="nodeapp"
LOG_DIR="/var/log/nodejs"

echo -e "${GREEN}=== Node.js Secure Backend Server Setup ===${NC}"

# 1. System Update and Dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    curl \
    gnupg \
    build-essential \
    git \
    nginx \
    certbot \
    python3-certbot-nginx \
    ufw \
    fail2ban \
    auditd \
    rsyslog

# 3. Create application user
echo -e "${YELLOW}Creating application user...${NC}"
if ! id "$APP_USER" &>/dev/null; then
    useradd -r -s /bin/bash -d /home/$APP_USER -m $APP_USER
fi

# 4. Create application directory
echo -e "${YELLOW}Setting up application directory...${NC}"
mkdir -p $APP_DIR
mkdir -p $LOG_DIR
chown -R $APP_USER:$APP_USER $LOG_DIR

# 5. Create package.json
cat > $APP_DIR/package.json << 'EOF'
{
  "name": "secure-nodejs-backend",
  "version": "1.0.0",
  "description": "Secure Node.js backend with comprehensive logging and command execution",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest",
    "audit": "npm audit",
    "audit-fix": "npm audit fix"
  },
  "dependencies": {
    "express": "^4.18.2",
    "helmet": "^7.1.0",
    "express-rate-limit": "^7.1.5",
    "winston": "^3.11.0",
    "morgan": "^1.10.0",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "validator": "^13.11.0",
    "uuid": "^9.0.1",
    "compression": "^1.7.4",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}
EOF

# 6. Create .env file
cat > $APP_DIR/.env << 'EOF'
# Server Configuration
PORT=3000
NODE_ENV=production

# Security
JWT_SECRET=CHANGE_THIS_TO_RANDOM_64_CHAR_STRING
ADMIN_USERNAME=admin
# Default password is 'changeme' - CHANGE THIS IMMEDIATELY
ADMIN_PASSWORD_HASH=$2b$10$xK1.VlQXs8Kc5Gkmqp6TDO0PxZ5D3QNgA2qL8kxvM7fW8iBX3jXyG

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com

# Command Execution
RESTRICT_COMMANDS=true

# Logging
LOG_LEVEL=info
EOF

# 7. Copy server.js from artifact
cp /path/to/server.js $APP_DIR/server.js

# 8. Install Node.js dependencies
echo -e "${YELLOW}Installing Node.js dependencies...${NC}"
cd $APP_DIR
npm install --production

# 9. Set proper permissions
chown -R $APP_USER:$APP_USER $APP_DIR
chmod 600 $APP_DIR/.env

# 10. Create systemd service
echo -e "${YELLOW}Creating systemd service...${NC}"
cat > /etc/systemd/system/nodejs-backend.service << EOF
[Unit]
Description=Secure Node.js Backend Server
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Environment
Environment="NODE_ENV=production"

[Install]
WantedBy=multi-user.target
EOF

# 11. Configure Nginx reverse proxy
echo -e "${YELLOW}Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/nodejs-backend << 'EOF'
upstream nodejs_backend {
    server 127.0.0.1:3000;
    keepalive 64;
}

server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    # SSL configuration (will be managed by Certbot)
    # ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    # ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Logging
    access_log /var/log/nginx/nodejs-backend-access.log;
    error_log /var/log/nginx/nodejs-backend-error.log;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req zone=api burst=20 nodelay;
    
    location / {
        proxy_pass http://nodejs_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF

ln -sf /etc/nginx/sites-available/nodejs-backend /etc/nginx/sites-enabled/

# 12. Configure firewall
echo -e "${YELLOW}Configuring firewall...${NC}"
ufw --force disable
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# 13. Configure Fail2ban for Node.js
echo -e "${YELLOW}Configuring Fail2ban...${NC}"
cat > /etc/fail2ban/filter.d/nodejs-backend.conf << 'EOF'
[Definition]
failregex = .*"type":"AUTH_FAILURE".*"ip":"<HOST>".*
            .*"type":"RATE_LIMIT".*"ip":"<HOST>".*
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/nodejs-backend.conf << 'EOF'
[nodejs-backend]
enabled = true
filter = nodejs-backend
logpath = /var/log/nodejs/security.log
maxretry = 5
findtime = 600
bantime = 3600
action = iptables-multiport[name=nodejs, port="80,443"]
EOF

# 14. Configure audit rules
echo -e "${YELLOW}Configuring audit system...${NC}"
cat >> /etc/audit/rules.d/nodejs.rules << 'EOF'
# Monitor Node.js application
-w /opt/nodejs-backend -p wa -k nodejs_app
-w /var/log/nodejs -p wa -k nodejs_logs
EOF

# 15. Create log rotation
echo -e "${YELLOW}Setting up log rotation...${NC}"
cat > /etc/logrotate.d/nodejs-backend << 'EOF'
/var/log/nodejs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 nodeapp nodeapp
    sharedscripts
    postrotate
        systemctl reload nodejs-backend
    endscript
}
EOF

# 16. Create monitoring script
cat > /usr/local/bin/monitor-nodejs.sh << 'EOF'
#!/bin/bash
# Simple monitoring script

SERVICE="nodejs-backend"
URL="http://localhost:3000/api/health"

# Check if service is running
if ! systemctl is-active --quiet $SERVICE; then
    echo "$(date): $SERVICE is not running, attempting restart"
    systemctl restart $SERVICE
    logger -t nodejs-monitor "$SERVICE was down, attempted restart"
fi

# Check health endpoint
if ! curl -f -s $URL > /dev/null; then
    echo "$(date): Health check failed"
    logger -t nodejs-monitor "Health check failed for $SERVICE"
fi
EOF

chmod +x /usr/local/bin/monitor-nodejs.sh

# Add to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor-nodejs.sh") | crontab -

# 17. Enable and start services
echo -e "${YELLOW}Starting services...${NC}"
systemctl daemon-reload
systemctl enable auditd
systemctl enable fail2ban
systemctl enable nodejs-backend
systemctl restart auditd
systemctl restart fail2ban
systemctl restart nginx
systemctl start nodejs-backend

# 18. Create admin utility script
cat > /usr/local/bin/nodejs-admin << 'EOF'
#!/bin/bash

case "$1" in
    status)
        systemctl status nodejs-backend
        ;;
    restart)
        systemctl restart nodejs-backend
        ;;
    logs)
        journalctl -u nodejs-backend -f
        ;;
    security-logs)
        tail -f /var/log/nodejs/security.log
        ;;
    audit-logs)
        tail -f /var/log/nodejs/audit.log
        ;;
    reset-password)
        echo "Enter new admin password:"
        read -s password
        hash=$(node -e "const bcrypt=require('bcrypt'); console.log(bcrypt.hashSync('$password', 10));")
        sed -i "s/ADMIN_PASSWORD_HASH=.*/ADMIN_PASSWORD_HASH=$hash/" /opt/nodejs-backend/.env
        systemctl restart nodejs-backend
        echo "Password updated"
        ;;
    *)
        echo "Usage: nodejs-admin {status|restart|logs|security-logs|audit-logs|reset-password}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/nodejs-admin

# 19. Display summary
echo -e "${GREEN}=== Setup Complete ===${NC}"
echo -e "${GREEN}Node.js Backend Server is now running!${NC}"
echo
echo -e "${YELLOW}Important next steps:${NC}"
echo "1. Update domain in /etc/nginx/sites-available/nodejs-backend"
echo "2. Run: certbot --nginx -d your-domain.com (for SSL)"
echo "3. Change admin password: nodejs-admin reset-password"
echo "4. Update JWT_SECRET in /opt/nodejs-backend/.env"
echo "5. Review firewall rules: ufw status"
echo
echo -e "${YELLOW}Service Management:${NC}"
echo "- Status: systemctl status nodejs-backend"
echo "- Logs: journalctl -u nodejs-backend -f"
echo "- Admin tool: nodejs-admin {command}"
echo
echo -e "${YELLOW}API Endpoints:${NC}"
echo "- Health: GET /api/health"
echo "- Login: POST /api/auth/login"
echo "- Execute: POST /api/execute (authenticated)"
echo "- System Info: GET /api/system/info (authenticated)"
echo "- Logs: GET /api/logs (authenticated)"
echo "- Processes: GET /api/processes (authenticated)"
echo
echo -e "${GREEN}Security features enabled:${NC}"
echo "✓ JWT Authentication"
echo "✓ Rate limiting"
echo "✓ Helmet security headers"
echo "✓ Command sanitization"
echo "✓ Comprehensive audit logging"
echo "✓ Fail2ban intrusion prevention"
echo "✓ UFW firewall"
echo "✓ Nginx reverse proxy"
echo "✓ Systemd service hardening"