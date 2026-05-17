#!/bin/bash
# MIRAGE — demo deployment setup script
# Run as root on a fresh Ubuntu 22.04 VM:
#   git clone <repo> && cd AI-Honeypot && bash deploy/setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."

# ── Docker ────────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    echo "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
fi

# ── Keys ──────────────────────────────────────────────────────────────────────
API_KEY=$(openssl rand -hex 32)
SECRET_KEY=$(openssl rand -hex 32)

# ── .env ──────────────────────────────────────────────────────────────────────
cat > .env <<EOF
DEMO_MODE=true
APP_ENV=development
API_KEY=${API_KEY}
SECRET_ENCRYPTION_KEY=${SECRET_KEY}
GEMINI_API_KEY=
OPENAI_API_KEY=
CORS_ORIGINS=*
TRUSTED_PROXIES=172.16.0.0/12
HONEYPOT_RISK_THRESHOLD=0.6
EOF

# ── Frontend config with API key ──────────────────────────────────────────────
cat > frontend/config.local.js <<EOF
window.MIRAGE_CONFIG = {
  apiBase: window.location.protocol + '//' + window.location.host + '/api/v1',
  wsUrl:   (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host + '/ws/live',
  apiKey:  '${API_KEY}',
};
EOF

# ── Start ─────────────────────────────────────────────────────────────────────
echo "Building and starting services..."
docker compose up -d --build

# Wait for health checks
echo "Waiting for services to be healthy..."
sleep 10

PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "<your-vm-ip>")

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║          MIRAGE is up!                           ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║  Dashboard: http://${PUBLIC_IP}                  "
echo "║  API Key:   ${API_KEY}                           "
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "To view logs:  docker compose logs -f"
echo "To stop:       docker compose down"
