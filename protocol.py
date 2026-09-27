"""
DJI Mic Mini protocol parser, framing, and command generator.
Supports both v1 and v2 wire protocols.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

# DUML start-of-frame marker and protocol version
SOF = 0x55
VERSION = 0x04

# CRC-16 table (reflected 0x8408 polynomial / X-25)
CRC16_TABLE = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
]

V1_INIT = 0x0000
V1_RESIDUE = 0xbb01

V2_INIT = 0x3692
V2_RESIDUE = 0x0000


def crc8_dji(data: bytes) -> int:
    """Compute CRC-8 over header (poly 0x31, init 0xEE, reflected in/out)."""
    crc = 0xee
    for b in data:
        b_ref = int(f"{b:08b}"[::-1], 2)
        crc ^= b_ref
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xff
            else:
                crc = (crc << 1) & 0xff
    return int(f"{crc:08b}"[::-1], 2)


def crc16_step(crc: int, byte: int) -> int:
    return (crc >> 8) ^ CRC16_TABLE[(crc ^ byte) & 0xff]


def crc16_checksum(data: bytes, init: int) -> int:
    crc = init
    for b in data:
        crc = crc16_step(crc, b)
    return crc


def crc16_verify(packet: bytes, init: int, residue: int) -> bool:
    if len(packet) < 2:
        return False
    return crc16_checksum(packet, init) == residue


def crc16_bytes(body: bytes, init: int, residue: int) -> bytes:
    """Find the 2 CRC bytes such that checksum(body + crc, init) == residue."""
    v = crc16_checksum(body, init)
    for b0 in range(256):
        v1 = crc16_step(v, b0)
        target = residue ^ (v1 >> 8)
        if target in CRC16_TABLE:
            idx = CRC16_TABLE.index(target)
            b1 = (v1 ^ idx) & 0xff
            return bytes([b0, b1])
    raise RuntimeError("CRC table does not cover residue")


@dataclass
class TxInfo:
    unit: int = 1  # 1 or 2
    level: Optional[int] = None
    serial: Optional[str] = None
    firmware: Optional[str] = None
    product_name: Optional[str] = None
    voice_tone: Optional[str] = None  # standard, rich, bright
    charging: Optional[bool] = None
    battery: Optional[int] = None  # 1 (full) to 7 (empty)


@dataclass
class RxInfo:
    serial: Optional[str] = None
    firmware: Optional[str] = None


@dataclass
class DeviceStatus:
    connected: bool = False
    dialect: str = "v2"  # "v1" or "v2"
    gain_dial_db: Optional[int] = None
    nc_enabled: bool = False
    rx: Optional[RxInfo] = None
    tx: List[Optional[TxInfo]] = field(default_factory=lambda: [None, None])
    settings: Dict[str, str] = field(default_factory=dict)

    def tx_count(self) -> int:
        return sum(1 for t in self.tx if t is not None)


def parse_ascii_string(data: bytes) -> str:
    """Parse null-terminated or fixed-width ASCII string."""
    null_pos = data.find(b"\x00")
    if null_pos != -1:
        data = data[:null_pos]
    return data.decode("latin1", errors="replace").strip()


def take_frames(buffer: bytearray) -> List[bytes]:
    """Scan and extract complete DUML frames from buffer."""
    frames = []
    while True:
        # Find SOF
        start = -1
        for i in range(len(buffer) - 2):
            if buffer[i] == SOF and buffer[i + 2] == VERSION:
                start = i
                break

        if start == -1:
            if len(buffer) > 0 and buffer[-1] == SOF:
                del buffer[:-1]
            else:
                buffer.clear()
            break

        if start > 0:
            del buffer[:start]

        if len(buffer) < 4:
            break

        frame_len = buffer[1]
        if frame_len < 4 or frame_len > 256:
            # Bogus length, advance 1 byte and retry
            del buffer[:1]
            continue

        if len(buffer) < frame_len:
            break

        frame = bytes(buffer[:frame_len])
        del buffer[:frame_len]
        frames.append(frame)

    return frames


def detect_dialect(frame: bytes) -> Optional[str]:
    """Check heartbeat marker at offset 8..11 to determine protocol dialect."""
    if len(frame) < 12:
        return None
    if frame[8] == 0x00 and frame[9] == 0x5b and frame[10] == 0x03:
        if frame[11] == 0x00:
            return "v1"
        elif frame[11] == 0x03:
            return "v2"
    return None


def decode_v1_heartbeat(status: DeviceStatus, frame: bytes) -> Optional[DeviceStatus]:
    """Decode legacy v1 heartbeat frame."""
    header_len = 14
    rx_len = 22
    if len(frame) < header_len + rx_len:
        return None

    status.dialect = "v1"
    status.connected = True

    # Parse TX slots
    off = header_len
    tx_list: List[Optional[TxInfo]] = [None, None]
    state_byte = 0
    flags_byte = 0
    led_off = None

    for slot_idx in range(2):
        if off + 1 >= len(frame):
            break
        flags = frame[off + 1]
        if flags & 0x20 != 0:
            # Present TX (23 bytes)
            if off + 23 > len(frame):
                break
            state_byte = frame[off]
            flags_byte = flags
            level = frame[off + 2]
            led_off = (frame[off + 3] & 0x80) != 0
            fw_bytes = frame[off + 4:off + 8]
            fw_str = f"{fw_bytes[0]:02d}.{fw_bytes[1]:02d}.{fw_bytes[2]:02d}.{fw_bytes[3]:02d}"
            serial = parse_ascii_string(frame[off + 9:off + 23])

            tx_list[slot_idx] = TxInfo(
                unit=slot_idx + 1,
                level=level,
                serial=serial,
                firmware=fw_str,
            )
            off += 23
        else:
            # Absent stub (9 bytes)
            if off + 9 > len(frame):
                break
            if state_byte == 0:
                state_byte = frame[off]
                flags_byte = flags
            off += 9

    status.tx = tx_list
    status.nc_enabled = (flags_byte & 0x01) != 0

    # Parse RX slot
    if off + rx_len <= len(frame):
        rx_flags0 = frame[off]
        rx_flags1 = frame[off + 1]
        fw_bytes = frame[off + 2:off + 6]
        fw_str = f"{fw_bytes[0]:02d}.{fw_bytes[1]:02d}.{fw_bytes[2]:02d}.{fw_bytes[3]:02d}"
        serial = parse_ascii_string(frame[off + 7:off + 21])
        plug_free = frame[off + 21] == 0x01

        status.rx = RxInfo(serial=serial, firmware=fw_str)

        status.settings["noise-cancel"] = "strong" if (state_byte & 0x20) else "basic"
        status.settings["noise-cancel-power"] = "on" if status.nc_enabled else "off"
        status.settings["low-cut"] = "on" if (state_byte & 0x04) else "off"
        status.settings["stereo"] = "stereo" if (rx_flags0 & 0x08) else "mono"
        status.settings["camera-power"] = "on" if (rx_flags0 & 0x01) else "off"
        status.settings["auto-off-15m"] = "on" if (rx_flags0 & 0x02) else "off"
        status.settings["safety-track"] = "on" if (rx_flags1 & 0x80) else "off"
        status.settings["clip-limiter"] = "on" if (rx_flags1 & 0x20) else "off"
        status.settings["plug-free"] = "on" if plug_free else "off"
        if led_off is not None:
            status.settings["mic-leds"] = "off" if led_off else "on"

    return status


def decode_v2_status(status: DeviceStatus, frame: bytes) -> Optional[DeviceStatus]:
    """Decode v2 periodic status push (52-byte header + 32-byte slot per TX)."""
    header_len = 52
    slot_len = 32
    if len(frame) < header_len + 2:
        return None

    remainder = len(frame) - (header_len + 2)
    if remainder % slot_len != 0:
        return None

    tx_slots_in_frame = min(2, remainder // slot_len)

    flags1 = frame[20]
    flags2 = frame[21]
    dial_raw = frame[22]
    status.gain_dial_db = int.from_bytes([dial_raw], byteorder="little", signed=True)
    flags3 = frame[48]

    status.dialect = "v2"
    status.connected = True
    status.nc_enabled = (flags1 & 0x20) != 0

    connected_mask = frame[44]
    for i in range(2):
        is_conn = (connected_mask & (1 << i)) != 0
        if is_conn:
            if status.tx[i] is None:
                status.tx[i] = TxInfo(unit=i + 1)
        else:
            status.tx[i] = None

    # Parse present TX slots
    tx_flags = None
    low_cut_flags = None
    for pos in range(tx_slots_in_frame):
        slot_off = header_len + pos * slot_len
        unit_byte = frame[slot_off + 1]
        idx = unit_byte - 1
        if 0 <= idx < 2 and status.tx[idx] is not None:
            tx = status.tx[idx]
            slot_flags_6 = frame[slot_off + 6]
            slot_flags_7 = frame[slot_off + 7]
            slot_flags_9 = frame[slot_off + 9]

            tx_flags = slot_flags_6
            low_cut_flags = slot_flags_9

            # Voice tone
            if slot_flags_9 & 0x80:
                tx.voice_tone = "bright"
            elif slot_flags_9 & 0x40:
                tx.voice_tone = "rich"
            else:
                tx.voice_tone = "standard"

            # Battery & charging
            tx.charging = (slot_flags_7 & 0x02) != 0
            tx.battery = (slot_flags_7 >> 2) & 0x07

    # Global settings
    status.settings["noise-cancel"] = "strong" if (flags1 & 0x08) else "basic"
    status.settings["noise-cancel-power"] = "on" if (flags1 & 0x20) else "off"
    status.settings["camera-power"] = "on" if (flags1 & 0x80) else "off"
    status.settings["auto-off-15m"] = "on" if (flags2 & 0x01) else "off"
    status.settings["stereo"] = "stereo" if (flags2 & 0x04) else "mono"
    status.settings["plug-free"] = "on" if (flags3 & 0x02) else "off"
    status.settings["clip-limiter"] = "on" if (flags3 & 0x10) else "off"
    status.settings["safety-track"] = "on" if (flags3 & 0x40) else "off"

    if tx_flags is not None:
        status.settings["mic-leds"] = "off" if (tx_flags & 0x02) else "on"
        status.settings["tx-auto-off-15m"] = "on" if (tx_flags & 0x10) else "off"
        status.settings["noise-cancel-button"] = "on" if (tx_flags & 0x80) else "off"

    if low_cut_flags is not None:
        status.settings["low-cut"] = "on" if (low_cut_flags & 0x20) else "off"

    return status


def decode_v2_records(status: DeviceStatus, frame: bytes) -> Optional[DeviceStatus]:
    """Decode v2 identity and live audio level records."""
    records_start = 14
    record_hdr_len = 6
    if len(frame) < records_start + 2:
        return None

    end = len(frame) - 2  # Strip trailing CRC
    i = records_start
    matched = False

    while i + record_hdr_len <= end:
        tag = frame[i]
        index = frame[i + 1]
        length = frame[i + 5]
        data_start = i + record_hdr_len
        data_end = data_start + length
        if data_end > end:
            break

        data = frame[data_start:data_end]

        if tag == 0x01 and len(data) > 4:
            # Firmware version: 4 bytes (MSB last, so data[3].data[2].data[1].data[0])
            fw_str = f"{data[3]:02d}.{data[2]:02d}.{data[1]:02d}.{data[0]:02d}"
            serial = parse_ascii_string(data[4:])
            if index == 0:
                if status.rx is None:
                    status.rx = RxInfo()
                status.rx.serial = serial
                status.rx.firmware = fw_str
            elif index in (1, 2):
                idx = index - 1
                if status.tx[idx] is None:
                    status.tx[idx] = TxInfo(unit=index)
                status.tx[idx].serial = serial
                status.tx[idx].firmware = fw_str
            matched = True

        elif tag == 0x05 and len(data) == 1 and index in (1, 2):
            idx = index - 1
            if status.tx[idx] is None:
                status.tx[idx] = TxInfo(unit=index)
            status.tx[idx].level = data[0]
            matched = True

        elif tag == 0x06 and index in (1, 2):
            idx = index - 1
            if status.tx[idx] is None:
                status.tx[idx] = TxInfo(unit=index)
            status.tx[idx].product_name = parse_ascii_string(data)
            matched = True

        i = data_end

    return status if matched else None


def decode_frame(status: DeviceStatus, frame: bytes) -> Optional[DeviceStatus]:
    """Process any valid DUML frame and update device status."""
    dialect = detect_dialect(frame)
    if dialect == "v1":
        return decode_v1_heartbeat(status, frame)
    elif dialect == "v2":
        # Try status push first, fallback to records
        res = decode_v2_status(status, frame)
        if res is not None:
            return res
        return decode_v2_records(status, frame)
    return None


# Commands dictionary with metadata
# Format: id: (label, target_str, v1_cmd, v2_cmd, valid_values_dict)
SETTINGS_SPEC = {
    "noise-cancel": {
        "label": "Noise Cancel Mode",
        "target": "tx",
        "v1": 0x031d,
        "v2": 0x0037,
        "values": {"basic": 0x00, "strong": 0x01},
        "default": "basic",
    },
    "noise-cancel-power": {
        "label": "Noise Cancelling",
        "target": "tx",
        "v1": None,
        "v2": 0x0038,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "noise-cancel-button": {
        "label": "Toggle NC via TX Power Button",
        "target": "tx",
        "v1": None,
        "v2": 0x000f,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "low-cut": {
        "label": "Low Cut Filter",
        "target": "tx",
        "v1": 0x0303,
        "v2": 0x0003,
        "values": {"off": 0x00, "on": 0x01},
        "default": "off",
    },
    "stereo": {
        "label": "Audio Channels",
        "target": "rx",
        "v1": 0x0008,
        "v2": 0x0008,
        "values": {"mono": 0x00, "stereo": 0x02},
        "default": "mono",
    },
    "safety-track": {
        "label": "Safety Track (-6dB)",
        "target": "rx",
        "v1": 0x0021,
        "v2": 0x0021,
        "values": {"off": 0x00, "on": 0x01},
        "default": "off",
    },
    "clip-limiter": {
        "label": "Clipping Control",
        "target": "rx",
        "v1": 0x001e,
        "v2": 0x001e,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "auto-off-15m": {
        "label": "Auto Power Off RX (15 min)",
        "target": "rx",
        "v1": 0x0010,
        "v2": 0x0010,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "tx-auto-off-15m": {
        "label": "Auto Power Off TX (15 min)",
        "target": "tx",
        "v1": None,
        "v2": 0x0010,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "camera-power": {
        "label": "Power On/Off with Camera",
        "target": "rx",
        "v1": 0x0020,
        "v2": 0x0020,
        "values": {"off": 0x00, "on": 0x01},
        "default": "on",
    },
    "plug-free": {
        "label": "Plug-Free External Speaker",
        "target": "rx",
        "v1": 0x0023,
        "v2": 0x0023,
        "values": {"off": 0x00, "on": 0x01},
        "default": "off",
    },
    "mic-leds": {
        "label": "Transmitter LEDs",
        "target": "tx",
        "v1": 0x030a,
        "v2": 0x000a,
        "values": {"on": 0x00, "off": 0x02},  # wire value is inverted
        "default": "on",
    },
    "voice-tone": {
        "label": "Voice Tone",
        "target": "tx_unit",  # requires tx=1 or tx=2
        "v1": None,
        "v2": 0x0029,
        "values": {"standard": 0x00, "rich": 0x01, "bright": 0x02},
        "default": "standard",
    },
}


def build_command_packet(
    dialect: str,
    seq: int,
    setting_id: str,
    value_str: str,
    tx_unit: Optional[int] = None,
) -> bytes:
    """Build a command frame for the requested setting."""
    spec = SETTINGS_SPEC.get(setting_id)
    if not spec:
        raise ValueError(f"Unknown setting: {setting_id}")

    val_map = spec["values"]
    if value_str.lower() not in val_map:
        raise ValueError(
            f"Invalid value '{value_str}' for {setting_id}. Options: {list(val_map.keys())}"
        )

    wire_val = val_map[value_str.lower()]

    if dialect == "v1":
        cmd_id = spec["v1"]
        if cmd_id is None:
            raise ValueError(f"Setting '{setting_id}' is not supported on v1 firmware")
        body = bytearray([
            SOF,
            19,
            0x04,
            0x03,  # Header CRC-8 for 19-byte packet
            0x02,  # Audio subsystem
            0x5a,
            seq & 0xff,
            (seq >> 8) & 0xff,
            0x40,  # ACK requested
            0x5b,
            0x01,
            0x00,
            (cmd_id >> 8) & 0xff,
            cmd_id & 0xff,
            0x00,
            0x01,
            wire_val,
        ])
        crc = crc16_bytes(body, V1_INIT, V1_RESIDUE)
        return bytes(body + crc)

    else:  # v2
        cmd_id = spec["v2"]
        target_type = spec["target"]
        if target_type == "rx":
            target = 0x0000
        elif target_type == "tx":
            target = 0xffff
        elif target_type == "tx_unit":
            if tx_unit not in (1, 2):
                raise ValueError("Target TX unit must be 1 or 2 for this setting")
            target = tx_unit
        else:
            target = 0xffff

        body = bytearray([
            SOF,
            22,
            0x04,
            0xfc,  # Header CRC-8 for 22-byte packet
            0x02,  # Audio subsystem
            0x5a,
            seq & 0xff,
            (seq >> 8) & 0xff,
            0x40,  # ACK requested
            0x5b,
            0x01,
            0x02,  # Target-addressed command
            target & 0xff,
            (target >> 8) & 0xff,
            0x00,
            0x00,
            cmd_id & 0xff,
            (cmd_id >> 8) & 0xff,
            0x01,
            wire_val,
        ])
        crc = crc16_bytes(body, V2_INIT, V2_RESIDUE)
        return bytes(body + crc)
