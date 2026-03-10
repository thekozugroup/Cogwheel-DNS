# Deploy Cogwheel to Raspberry Pi (fractal.local)

## Manual Deployment Steps

Since SSH password authentication is currently failing, follow these manual steps:

### Option 1: Using USB/Network Transfer

1. **Copy Docker image to Pi:**
   ```bash
   # On your Mac, the image is ready at:
   /tmp/cogwheel-arm64.tar.gz
   
   # Transfer via USB drive or network share to the Pi
   # Then on the Pi:
   gunzip -c /path/to/cogwheel-arm64.tar.gz | docker load
   ```

2. **Run Cogwheel container:**
   ```bash
   docker run -d \
     --name cogwheel \
     --restart unless-stopped \
     -p 53:53/udp \
     -p 53:53/tcp \
     -p 8080:8080 \
     -v cogwheel_data:/app/data \
     cogwheel:arm64
   ```

3. **Verify deployment:**
   ```bash
   docker ps | grep cogwheel
   curl http://localhost:8080/api/v1/dashboard
   ```

4. **Access Web UI:**
   Open browser to: http://fractal.local:8080

### Option 2: Fix SSH Authentication

1. **On Raspberry Pi, enable password auth:**
   ```bash
   sudo nano /etc/ssh/sshd_config
   # Ensure these lines are present:
   PasswordAuthentication yes
   PermitEmptyPasswords no
   ```

2. **Restart SSH:**
   ```bash
   sudo systemctl restart ssh
   ```

3. **Then run automated deployment:**
   ```bash
   ./deploy-to-fractal.sh
   ```

### Option 3: Add SSH Key Manually

1. **On Raspberry Pi:**
   ```bash
   mkdir -p ~/.ssh
   echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHJZG1OsE5mIYcCbctw11rjGTAHLiDjhJiYGawhRkI/8 cogwheel-deployment" >> ~/.ssh/authorized_keys
   chmod 700 ~/.ssh
   chmod 600 ~/.ssh/authorized_keys
   ```

2. **Then run automated deployment:**
   ```bash
   ./deploy-to-fractal.sh
   ```

## Post-Deployment Verification

1. **Check container status:**
   ```bash
   docker ps
   docker logs cogwheel
   ```

2. **Test DNS resolution:**
   ```bash
   dig @fractal.local google.com
   ```

3. **Access Web UI:**
   - Navigate to http://fractal.local:8080
   - Verify dashboard loads
   - Check Tailscale status card
   - Test load testing endpoint

4. **Test API endpoints:**
   ```bash
   curl http://fractal.local:8080/api/v1/dashboard
   curl http://fractal.local:8080/api/v1/tailscale/status
   curl http://fractal.local:8080/api/v1/false-positive-budget
   ```

## Troubleshooting

### Container won't start
```bash
docker logs cogwheel
docker rm -f cogwheel
# Re-run docker run command
```

### Port 53 already in use
```bash
# Check what's using port 53
sudo netstat -tulpn | grep :53
# Stop conflicting service (e.g., systemd-resolved)
sudo systemctl stop systemd-resolved
```

### Web UI not accessible
```bash
# Check if container is running
docker ps | grep cogwheel
# Check firewall rules
sudo ufw status
# Allow port 8080 if needed
sudo ufw allow 8080/tcp
```

## Deployment Script (when SSH works)

The automated deployment script is at:
```
/tmp/deploy-fractal.sh
```

Run it with:
```bash
bash /tmp/deploy-fractal.sh
```

This will:
1. Build ARM64 Docker image (if not already built)
2. Export to tarball
3. Transfer to Pi via SCP
4. Load image on Pi
5. Stop old container
6. Run new container with proper networking
