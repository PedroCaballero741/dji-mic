"""
DJI Mic Mini USB communication layer using libusb-1.0 via ctypes.
Communicates over Interface 6 using Bulk transfers.
Endpoints:
  EP 0x06 OUT: Host to device commands
  EP 0x86 IN:  Device to host heartbeats and ACKs
"""

import ctypes
import ctypes.util
import os
import sys
import time
from typing import Callable, List, Optional, Tuple

from protocol import (
    DeviceStatus,
    build_command_packet,
    decode_frame,
    detect_dialect,
    take_frames,
)

DJI_VENDOR_ID = 0x2CA3
DJI_PRODUCT_ID = 0x4011

DJI_INTERFACE = 6
EP_BULK_OUT = 0x06
EP_BULK_IN = 0x86

# Load libusb-1.0
_lib_name = ctypes.util.find_library("usb-1.0") or "libusb-1.0.so.0"
try:
    _lib = ctypes.CDLL(_lib_name)
except OSError as e:
    _lib = None


# libusb definitions
class DeviceDescriptor(ctypes.Structure):
    _fields_ = [
        ("bLength", ctypes.c_uint8),
        ("bDescriptorType", ctypes.c_uint8),
        ("bcdUSB", ctypes.c_uint16),
        ("bDeviceClass", ctypes.c_uint8),
        ("bDeviceSubClass", ctypes.c_uint8),
        ("bDeviceProtocol", ctypes.c_uint8),
        ("bMaxPacketSize0", ctypes.c_uint8),
        ("idVendor", ctypes.c_uint16),
        ("idProduct", ctypes.c_uint16),
        ("bcdDevice", ctypes.c_uint16),
        ("iManufacturer", ctypes.c_uint8),
        ("iProduct", ctypes.c_uint8),
        ("iSerialNumber", ctypes.c_uint8),
        ("bNumConfigurations", ctypes.c_uint8),
    ]


if _lib:
    _lib.libusb_init.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    _lib.libusb_init.restype = ctypes.c_int

    _lib.libusb_exit.argtypes = [ctypes.c_void_p]
    _lib.libusb_exit.restype = None

    _lib.libusb_get_device_list.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),
    ]
    _lib.libusb_get_device_list.restype = ctypes.c_ssize_t

    _lib.libusb_free_device_list.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_int]
    _lib.libusb_free_device_list.restype = None

    _lib.libusb_get_device_descriptor.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(DeviceDescriptor),
    ]
    _lib.libusb_get_device_descriptor.restype = ctypes.c_int

    _lib.libusb_open.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    _lib.libusb_open.restype = ctypes.c_int

    _lib.libusb_close.argtypes = [ctypes.c_void_p]
    _lib.libusb_close.restype = None

    _lib.libusb_claim_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
    _lib.libusb_claim_interface.restype = ctypes.c_int

    _lib.libusb_release_interface.argtypes = [ctypes.c_void_p, ctypes.c_int]
    _lib.libusb_release_interface.restype = ctypes.c_int

    _lib.libusb_bulk_transfer.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint8,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint,
    ]
    _lib.libusb_bulk_transfer.restype = ctypes.c_int

    _lib.libusb_strerror.argtypes = [ctypes.c_int]
    _lib.libusb_strerror.restype = ctypes.c_char_p


class DjiMicException(Exception):
    pass


class DjiMicPermissionError(DjiMicException):
    pass


class DjiMicNotFoundError(DjiMicException):
    pass


class DjiMicDevice:
    """Manages connection, heartbeats, and commands to the DJI Mic Mini."""

    def __init__(self):
        if not _lib:
            raise DjiMicException("libusb-1.0 not found on the system")
        self.ctx = ctypes.c_void_p()
        self.handle = ctypes.c_void_p()
        self.seq = 1
        self.rx_buffer = bytearray()
        self.status = DeviceStatus()
        self.interface_claimed = False

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def open(self):
        """Find and open the DJI Mic Mini device."""
        ret = _lib.libusb_init(ctypes.byref(self.ctx))
        if ret != 0:
            raise DjiMicException(f"Failed to initialize libusb: error {ret}")

        dev_list = ctypes.POINTER(ctypes.c_void_p)()
        cnt = _lib.libusb_get_device_list(self.ctx, ctypes.byref(dev_list))
        if cnt < 0:
            _lib.libusb_exit(self.ctx)
            raise DjiMicException("Failed to enumerate USB devices")

        found_dev = None
        for i in range(cnt):
            dev = dev_list[i]
            desc = DeviceDescriptor()
            _lib.libusb_get_device_descriptor(dev, ctypes.byref(desc))
            if desc.idVendor == DJI_VENDOR_ID and desc.idProduct == DJI_PRODUCT_ID:
                found_dev = dev
                break

        if not found_dev:
            _lib.libusb_free_device_list(dev_list, 1)
            _lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p()
            raise DjiMicNotFoundError(
                "DJI Mic Mini not found. Make sure the receiver is plugged in via USB-C."
            )

        open_handle = ctypes.c_void_p()
        ret = _lib.libusb_open(found_dev, ctypes.byref(open_handle))
        _lib.libusb_free_device_list(dev_list, 1)

        if ret == -3:  # LIBUSB_ERROR_ACCESS
            _lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p()
            raise DjiMicPermissionError(
                "Permission denied accessing DJI Mic Mini USB device.\n"
                "To fix this without root, install the udev rule:\n"
                "  sudo ./install.sh\n"
                "or run the command with sudo."
            )
        elif ret != 0:
            err_msg = _lib.libusb_strerror(ret).decode("utf-8", errors="replace")
            _lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p()
            raise DjiMicException(f"Failed to open DJI Mic Mini: {err_msg} ({ret})")

        self.handle = open_handle

        # Claim vendor Interface 6
        ret = _lib.libusb_claim_interface(self.handle, DJI_INTERFACE)
        if ret != 0:
            err_msg = _lib.libusb_strerror(ret).decode("utf-8", errors="replace")
            self.close()
            raise DjiMicException(
                f"Failed to claim DJI Mic Mini interface {DJI_INTERFACE}: {err_msg} ({ret})"
            )

        self.interface_claimed = True

    def close(self):
        """Release interface and close USB connection."""
        if self.handle:
            if self.interface_claimed:
                _lib.libusb_release_interface(self.handle, DJI_INTERFACE)
                self.interface_claimed = False
            _lib.libusb_close(self.handle)
            self.handle = ctypes.c_void_p()

        if self.ctx:
            _lib.libusb_exit(self.ctx)
            self.ctx = ctypes.c_void_p()

    def read_raw(self, timeout_ms: int = 150) -> bytes:
        """Perform a single bulk transfer read from EP 0x86."""
        if not self.handle:
            return b""
        buf_size = 512
        raw_buf = (ctypes.c_uint8 * buf_size)()
        transferred = ctypes.c_int(0)

        ret = _lib.libusb_bulk_transfer(
            self.handle,
            EP_BULK_IN,
            raw_buf,
            buf_size,
            ctypes.byref(transferred),
            timeout_ms,
        )

        if ret == 0 and transferred.value > 0:
            return bytes(raw_buf[: transferred.value])
        return b""

    def write_raw(self, data: bytes, timeout_ms: int = 1000) -> bool:
        """Perform a single bulk transfer write to EP 0x06."""
        if not self.handle:
            return False
        raw_buf = (ctypes.c_uint8 * len(data))(*data)
        transferred = ctypes.c_int(0)

        ret = _lib.libusb_bulk_transfer(
            self.handle,
            EP_BULK_OUT,
            raw_buf,
            len(data),
            ctypes.byref(transferred),
            timeout_ms,
        )

        return ret == 0 and transferred.value == len(data)

    def poll_frames(self, timeout_ms: int = 150) -> List[bytes]:
        """Read pending data and return any completed DUML frames."""
        chunk = self.read_raw(timeout_ms)
        if chunk:
            self.rx_buffer.extend(chunk)
            frames = take_frames(self.rx_buffer)
            for f in frames:
                # Update status with heartbeat / record frames
                dialect = detect_dialect(f)
                if dialect:
                    self.status.dialect = dialect
                decode_frame(self.status, f)
            return frames
        return []

    def sync_status(self, duration_s: float = 1.0) -> DeviceStatus:
        """Listen to incoming frames for duration_s to build fresh state."""
        start = time.time()
        while time.time() - start < duration_s:
            self.poll_frames(timeout_ms=100)
            time.sleep(0.02)
        return self.status

    def set_setting(
        self,
        setting_id: str,
        value: str,
        tx_unit: Optional[int] = None,
        timeout_s: float = 2.0,
    ) -> bool:
        """Send a setting command and wait for ACK."""
        # Ensure we know the dialect
        if not self.status.dialect:
            self.sync_status(0.5)

        dialect = self.status.dialect or "v2"
        seq = self.seq
        self.seq = (self.seq + 1) & 0xFFFF
        if self.seq == 0:
            self.seq = 1

        cmd_pkt = build_command_packet(dialect, seq, setting_id, value, tx_unit=tx_unit)

        if not self.write_raw(cmd_pkt):
            raise DjiMicException(f"Failed to write command packet for {setting_id}")

        # Wait for ACK packet (len 14, byte 8 == 0x80, echoed seq)
        start = time.time()
        ack_received = False

        while time.time() - start < timeout_s:
            frames = self.poll_frames(timeout_ms=100)
            for f in frames:
                if len(f) == 14 and f[8] == 0x80:
                    ack_seq = f[6] | (f[7] << 8)
                    if ack_seq == seq:
                        ack_received = True
                        break
            if ack_received:
                break
            time.sleep(0.01)

        # Allow status frames to catch up with the new value
        time.sleep(0.2)
        self.poll_frames(timeout_ms=100)
        return ack_received
