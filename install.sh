#!/bin/bash
# Install script for dji-mic Linux driver & CLI

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo:"
    echo "  sudo ./install.sh"
    exit 1
fi

echo "Installing udev rule for DJI Mic Mini..."
cp "$DIR/99-dji-mic.rules" /etc/udev/rules.d/99-dji-mic.rules
udevadm control --reload-rules
udevadm trigger

echo "Installing dji-mic command to /usr/local/bin..."
ln -sf "$DIR/dji-mic" /usr/local/bin/dji-mic
chmod +x "$DIR/dji-mic"

echo "Done! You can now run 'dji-mic' from any terminal without sudo."
echo "Note: If the receiver is currently connected, unplug and replug it once for udev permissions to apply."
