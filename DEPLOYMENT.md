# Cogwheel Deployment Guide

## Raspberry Pi Deployment (fractal.local)

### Prerequisites
- Raspberry Pi 5 with 16GB Optane storage
- Docker installed on Pi
- Network access to Pi (fractal.local or 192.168.86.249)

### Automated Deployment

Run from development machine:
```bash
./deploy-to-fractal.sh
```

This will:
1. Build ARM64 Docker image
2. Transfer to Pi via SSH
3. Load and start container

### Manual Deployment

1. **Build Docker image:**
   ```bash
   docker buildx build --platform linux/arm64 -t cogwheel:arm64 --load .
   ```

2. **Export image:**
   ```bash
   docker save cogwheel:arm64 | gzip > cogwheel-arm64.tar.gz
   ```

3. **Transfer to Pi:**
   ```bash
   scp cogwheel-arm64.tar.gz michaelwong@fractal.local:/tmp/
   ```

4. **Deploy on Pi:**
   ```bash
   ssh michaelwong@fractal.local
   docker load -i /tmp/cogwheel-arm64.tar.gz
   docker run -d \
     --name cogwheel \
     --restart unless-stopped \
     -p 8080:8080 \
     -p 53:53/udp \
     -p 53:53/tcp \
     -v /opt/cogwheel/data:/app/data \
     cogwheel:arm64
   ```

### Access

- **Web UI:** http://fractal.local:8080
- **DNS Server:** 192.168.86.249:53

### Configuration

Data persists in `/opt/cogwheel/data` on the Pi.

### Troubleshooting

**SSH Authentication Failing:**
- Ensure password is: `203237`
- User: `michaelwong` or `pi`
- Try: `ssh-copy-id michaelwong@fractal.local` for key-based auth

**Container Won't Start:**
```bash
docker logs cogwheel
docker ps -a | grep cogwheel
```

**Port Conflicts:**
```bash
sudo netstat -tlnp | grep :53
sudo netstat -tlnp | grep :8080
```

### Testing Web UI

After deployment, verify:
1. Open http://fractal.local:8080 in browser
2. Check dashboard loads with:
   - Protection status
   - Runtime health metrics
   - Tailscale status (if configured)
   - Load test controls
   - False-positive budget display

### Phase 8 Testing

Run load tests from Web UI or API:
```bash
curl -X POST http://fractal.local:8080/api/v1/load-test \
  -H "Content-Type: application/json" \
  -d '{"duration_secs": 30, "qps": 100, "cache_hit_ratio": 0.7}'
```

Check false-positive budget:
```bash
curl http://fractal.local:8080/api/v1/false-positive-budget
```

Run Rust optimization benchmark:
```bash
curl http://fractal.local:8080/api/v1/benchmark/rust-opts
```
