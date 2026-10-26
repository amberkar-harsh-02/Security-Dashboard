#!/usr/bin/env bash
# Update the SIEM on the server after copying a new release to /opt/siem.
# The frontend is built on the laptop (`npm run build:siem`) because the server has no Node.
set -euo pipefail

cd /opt/siem/backend
sudo -u siem ./venv/bin/pip install --quiet -r requirements.txt
sudo systemctl restart siem
sleep 2
curl -fsS http://127.0.0.1:5050/api/health && echo " SIEM is up"
