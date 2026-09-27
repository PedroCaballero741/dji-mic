"""
Linux audio subsystem integration (ALSA & PipeWire/WirePlumber).
Controls system capture volume and mute status for the DJI Mic.
"""

import subprocess
import shutil
import re
from typing import Optional, Tuple, Dict, Any


def get_alsa_card_index() -> Optional[str]:
    """Find ALSA sound card ID or index for DJI Mic."""
    try:
        with open("/proc/asound/cards", "r") as f:
            cards = f.read()
        # Look for card line containing 'Rx' or 'Wireless Mic Rx'
        for line in cards.splitlines():
            if "Wireless Mic Rx" in line or "[Rx" in line:
                m = re.match(r"\s*(\d+)\s+\[", line)
                if m:
                    return m.group(1)
        # Fallback to name 'Rx'
        return "Rx"
    except Exception:
        return "Rx"


def get_alsa_volume() -> Optional[Dict[str, Any]]:
    """Query current capture volume and mute state via ALSA mixer."""
    if not shutil.which("amixer"):
        return None

    card = get_alsa_card_index()
    try:
        res = subprocess.run(
            ["amixer", "-c", str(card), "get", "Mic"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            return None

        # Parse output: Mono: Capture 151 [100%] [-0.06dB] [on]
        pct_match = re.search(r"\[(\d+)%\]", res.stdout)
        db_match = re.search(r"\[(-?\d+\.?\d*dB)\]", res.stdout)
        switch_match = re.search(r"\[(on|off)\]", res.stdout)

        return {
            "percent": int(pct_match.group(1)) if pct_match else None,
            "db": db_match.group(1) if db_match else None,
            "muted": switch_match.group(1) == "off" if switch_match else False,
        }
    except Exception:
        return None


def set_alsa_volume(val_str: str) -> bool:
    """Set capture volume via ALSA mixer (e.g. '80%', '100%')."""
    if not shutil.which("amixer"):
        return False
    card = get_alsa_card_index()
    try:
        res = subprocess.run(
            ["amixer", "-c", str(card), "set", "Mic", val_str],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def set_alsa_mute(muted: bool) -> bool:
    """Mute or unmute capture via ALSA mixer."""
    if not shutil.which("amixer"):
        return False
    card = get_alsa_card_index()
    cmd_val = "mute" if muted else "unmute"
    try:
        res = subprocess.run(
            ["amixer", "-c", str(card), "set", "Mic", cmd_val],
            capture_output=True,
            text=True,
            check=False,
        )
        return res.returncode == 0
    except Exception:
        return False


def get_pipewire_source_id() -> Optional[str]:
    """Find WirePlumber source ID for Wireless Mic Rx."""
    if not shutil.which("wpctl"):
        return None
    try:
        res = subprocess.run(
            ["wpctl", "status"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            return None

        in_sources = False
        for line in res.stdout.splitlines():
            if "Sources:" in line:
                in_sources = True
                continue
            if in_sources:
                if line.strip().startswith("Filters:") or line.strip().startswith("Streams:"):
                    break
                if "Wireless Mic Rx" in line:
                    m = re.search(r"(\d+)\.\s+Wireless Mic Rx", line)
                    if m:
                        return m.group(1)
        return None
    except Exception:
        return None
