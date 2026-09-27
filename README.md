# dji-mic - Linux Driver & CLI for DJI Mic Mini

CLI tool to manage and configure the DJI Mic Mini on Linux over USB.

### Quick Setup

1. Install udev rule and CLI symlink (requires sudo once):
```bash
sudo ./install.sh
```

2. Unplug and replug the receiver so the new udev permissions apply.

3. Run:
```bash
dji-mic status
```

### Usage

```bash
# General status (battery, transmitters, firmware, current settings)
dji-mic status

# Live terminal monitor with real-time VU meter and battery indicators
dji-mic monitor

# Noise cancellation
dji-mic nc strong          # Switch to Strong mode
dji-mic nc basic           # Switch to Basic mode
dji-mic nc off             # Turn off noise cancellation
dji-mic nc on              # Turn on noise cancellation

# Audio settings
dji-mic stereo on          # Separate channels: TX1 left, TX2 right
dji-mic stereo off         # Mono mixed
dji-mic lowcut on          # Enable low-cut filter
dji-mic set safety-track on
dji-mic set clip-limiter on

# Hardware options
dji-mic leds off           # Turn off TX LEDs
dji-mic set auto-off-rx on # Auto shut down receiver after 15m
dji-mic set auto-off-tx on # Auto shut down transmitters after 15m
dji-mic set camera-power on

# Voice Tone (Mic Mini 2 only)
dji-mic set tone rich --tx 1
dji-mic set tone bright --tx 2

# Linux system audio
dji-mic volume 80%
dji-mic mute
dji-mic unmute
```
