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
     -p 53:30053/udp \
     -p 53:30053/tcp \
     -p 30080:30080 \
     -e COGWHEEL_PROFILE=dev \
     -e COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:30080 \
     -e COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:30053 \
     -e COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:30053 \
     -e COGWHEEL_SERVER__ADVERTISED_DNS_PORT=53 \
     -e COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db \
     -v /home/michaelwong/cogwheel-data:/app/data \
     cogwheel:arm64
   ```

3. **Verify deployment:**
   ```bash
   docker ps | grep cogwheel
   curl http://localhost:30080/api/v1/dashboard
   ```

4. **Access Web UI:**
   Open browser to: http://fractal.local:30080

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
   - Navigate to http://fractal.local:30080
   - Verify dashboard loads
   - Check Tailscale status card
   - Test load testing endpoint

4. **Test API endpoints:**
   ```bash
   curl http://fractal.local:30080/api/v1/dashboard
   curl http://fractal.local:30080/api/v1/tailscale/status
   curl http://fractal.local:30080/api/v1/false-positive-budget
   ```

## Rollback

If a deployment update regresses DNS or the Web UI, roll back to the previous image immediately:

```bash
docker ps -a --format '{{.Image}} {{.Names}}'
docker rm -f cogwheel
docker run -d \
  --name cogwheel \
  --restart unless-stopped \
   -p 53:30053/udp \
   -p 53:30053/tcp \
   -p 30080:30080 \
   -e COGWHEEL_PROFILE=dev \
   -e COGWHEEL_SERVER__HTTP_BIND_ADDR=0.0.0.0:30080 \
   -e COGWHEEL_SERVER__DNS_UDP_BIND_ADDR=0.0.0.0:30053 \
   -e COGWHEEL_SERVER__DNS_TCP_BIND_ADDR=0.0.0.0:30053 \
   -e COGWHEEL_SERVER__ADVERTISED_DNS_PORT=53 \
   -e COGWHEEL_STORAGE__DATABASE_URL=sqlite:///app/data/cogwheel.db \
   -v /home/michaelwong/cogwheel-data:/app/data \
   <previous-image-tag>
```

Keep `/home/michaelwong/cogwheel-data` mounted so rollback preserves state. Verify rollback with:

```bash
curl http://fractal.local:30080/api/v1/dashboard
curl -I http://fractal.local:30080/
dig @fractal.local example.com +short
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
# Stop or reconfigure conflicting service (for example systemd-resolved or another DNS server)
sudo systemctl stop systemd-resolved
```

The tracked installer script `scripts/install-home-docker.sh` automatically disables the `systemd-resolved` stub listener before publishing host port `53`.

### Web UI not accessible
```bash
# Check if container is running
docker ps | grep cogwheel
# Check firewall rules
sudo ufw status
# Allow port 30080 if needed
sudo ufw allow 30080/tcp
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

## Optional Tailscale Install

If you want the node to advertise itself as a Tailscale exit node and keep exit-node DNS traffic on Cogwheel, run the tracked installer with:

```bash
sudo INSTALL_TAILSCALE=1 TAILSCALE_AUTH_KEY=tskey-example scripts/install-home-docker.sh
```

If you prefer to authenticate interactively, omit `TAILSCALE_AUTH_KEY` and complete `tailscale up --advertise-exit-node --accept-dns=false` after the package install finishes.
