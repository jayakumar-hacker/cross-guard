#!/bin/bash

echo "[*] Detecting OS…"
OS=$(uname -s)

if [[ "$OS" != "Linux" ]]; then
    echo "[!] This installer is only for Linux."
    exit 1
fi

echo "[*] Updating packages…"
sudo apt update -y

echo "[*] Installing Python3 & pip…"
sudo apt install -y python3 python3-pip

echo "[*] Creating folder structure…"
mkdir -p logs temp reports rules scripts/linux scripts/windows runners

echo "[*] Setting execution permissions…"
chmod +x scripts/linux/*.sh 2>/dev/null
chmod +x engine.py 2>/dev/null
chmod +x runners/runner_linux.py 2>/dev/null

echo "[*] Installing Python dependencies…"
pip3 install -r requirements.txt

echo "[*] Installation complete!"
echo "Run Cross-Guard with:  python3 engine.py --mode audit"
