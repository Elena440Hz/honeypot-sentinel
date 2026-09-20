#!/usr/bin/env bash
# ============================================================
# setup_cowrie.sh — stand up the Cowrie SSH honeypot on Ubuntu 22.04
# Run this ON THE AZURE VM after you SSH in.
#
# This reflects the ACTUAL working setup (verified end-to-end), using
# Cowrie's current pip-based install. It is the corrected version — the
# original clone-and-copy-config approach broke because Cowrie moved to a
# modern packaging layout (see docs/BUILD_LOG.md section 5).
#
# Port design (important — see BUILD_LOG.md section 6):
#   * 22   = public bait, redirected to 2223 via iptables
#   * 2223 = Cowrie's fake SSH (unprivileged port)
#   * 2222 = YOUR real admin SSH (allowed inbound in the NSG)
# ============================================================
set -euo pipefail

# --- 0. Move REAL admin SSH off port 22 -> 2222 ---------------------------
# Port 22 must be free for the honeypot redirect. Your genuine SSH moves to
# 2222 (which the NSG must allow inbound). CAUTION: after this restarts sshd,
# reconnect on 2222 in a SECOND terminal BEFORE closing your current one:
#     ssh -i <key>.pem -p 2222 azureuser@<ip>
sudo sed -i 's/^#\?Port 22$/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart ssh
echo ">>> Admin SSH is now on 2222. Confirm a new session works before closing this one!"

# --- 1. System dependencies (Cowrie's crypto libs compile against these) ---
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv libssl-dev libffi-dev \
  build-essential libpython3-dev python3-minimal

# --- 2. Create an unprivileged user to run Cowrie -------------------------
sudo adduser --disabled-password --gecos "" cowrie || true

# --- 3. Install Cowrie via pip as the cowrie user -------------------------
sudo -u cowrie bash <<'EOF'
set -e
cd ~
mkdir -p honeypot && cd honeypot
python3 -m venv cowrie-env
source cowrie-env/bin/activate
pip install --upgrade pip
pip install cowrie
cowrie init            # generates etc/cowrie.cfg from the bundled template

# Move Cowrie's fake SSH off 2222 -> 2223 so it never collides with the
# real admin SSH on 2222.
sed -i 's/tcp:2222:interface=0.0.0.0/tcp:2223:interface=0.0.0.0/' etc/cowrie.cfg
grep listen_endpoints etc/cowrie.cfg   # should now show 2223
EOF

# --- 4. Redirect public port 22 -> Cowrie's 2223 --------------------------
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2223

# --- 5. Make the redirect survive reboots ---------------------------------
# During install, if prompted "Save current IPv4 rules?" choose YES.
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
sudo netfilter-persistent save
sudo grep 2223 /etc/iptables/rules.v4   # confirm the redirect is saved

# --- 6. systemd service so Cowrie auto-starts on boot ---------------------
# NOTE the Environment= lines: systemd runs with a bare PATH, so we must
# point it at the virtualenv or Cowrie's launcher can't find `twistd`
# (this was the failure in BUILD_LOG.md section on the systemd unit).
sudo tee /etc/systemd/system/cowrie.service > /dev/null <<'EOF'
[Unit]
Description=Cowrie SSH Honeypot
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
User=cowrie
Group=cowrie
WorkingDirectory=/home/cowrie/honeypot
Environment=HOME=/home/cowrie
Environment=VIRTUAL_ENV=/home/cowrie/honeypot/cowrie-env
Environment=PATH=/home/cowrie/honeypot/cowrie-env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/home/cowrie/honeypot/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/honeypot/cowrie-env/bin/cowrie stop

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sudo systemctl status cowrie --no-pager

echo ">>> Done. Cowrie listens on 2223; public :22 is redirected to it."
echo ">>> Logs (JSON, one event per line):"
echo "    /home/cowrie/honeypot/var/log/cowrie/cowrie.json"
echo ">>> Watch live:  sudo tail -f /home/cowrie/honeypot/var/log/cowrie/cowrie.json"

# --- REMINDERS (do these OUTSIDE this script) -----------------------------
# * In the NSG: allow inbound 22 (bait) AND 2222 (your admin SSH).
# * After install, lock down OUTBOUND egress in the NSG (allow 80/443/53,
#   deny the rest) — defense-in-depth. See docs/SETUP.md Phase 4.
# * Real admin SSH is on 2222:  ssh -i <key>.pem -p 2222 azureuser@<ip>
