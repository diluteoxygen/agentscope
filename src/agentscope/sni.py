"""
TLS Client Hello Server Name Indication (SNI) parser.
Extracts the target hostname directly from TLS handshake packets without external dependencies.
"""

from __future__ import annotations
import struct
from typing import Optional


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Parses a raw TLS Client Hello packet and returns the SNI hostname if present.
    
    TLS Record Format:
    - 1 byte: Content Type (0x16 = Handshake)
    - 2 bytes: Legacy Version (0x0301 or 0x0303)
    - 2 bytes: Length of Handshake payload
    
    Handshake Format:
    - 1 byte: Handshake Type (0x01 = Client Hello)
    - 3 bytes: Length
    - 2 bytes: Client Version
    - 32 bytes: Random
    - 1 byte: Session ID Length (N), followed by N bytes
    - 2 bytes: Cipher Suites Length (M), followed by M bytes
    - 1 byte: Compression Methods Length (K), followed by K bytes
    - 2 bytes: Extensions Length, followed by Extensions list
    """
    if len(payload) < 43:
        return None

    # Check for TLS Handshake (0x16)
    if payload[0] != 0x16:
        return None

    # Handshake type Client Hello (0x01)
    if payload[5] != 0x01:
        return None

    try:
        offset = 5 + 4  # Skip handshake header (1 byte type + 3 bytes length)
        offset += 2     # Skip client version
        offset += 32    # Skip client random

        # Skip Session ID
        if offset >= len(payload):
            return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Skip Cipher Suites
        if offset + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2 + cipher_suites_len

        # Skip Compression Methods
        if offset >= len(payload):
            return None
        compression_len = payload[offset]
        offset += 1 + compression_len

        # Extensions
        if offset + 2 > len(payload):
            return None
        extensions_len = struct.unpack("!H", payload[offset:offset+2])[0]
        offset += 2
        extensions_end = offset + extensions_len

        while offset + 4 <= min(extensions_end, len(payload)):
            ext_type, ext_len = struct.unpack("!HH", payload[offset:offset+4])
            offset += 4

            # Extension Type 0x0000 = server_name
            if ext_type == 0x0000:
                if offset + 2 > len(payload):
                    return None
                sni_list_len = struct.unpack("!H", payload[offset:offset+2])[0]
                sni_offset = offset + 2
                
                if sni_offset + 3 <= len(payload):
                    name_type = payload[sni_offset]
                    name_len = struct.unpack("!H", payload[sni_offset+1:sni_offset+3])[0]
                    # Name Type 0 = host_name
                    if name_type == 0 and sni_offset + 3 + name_len <= len(payload):
                        hostname = payload[sni_offset+3:sni_offset+3+name_len].decode("utf-8", errors="replace")
                        return hostname

            offset += ext_len

    except Exception:
        return None

    return None
