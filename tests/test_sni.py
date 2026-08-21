"""
Unit tests for TLS Client Hello SNI parser.
"""

import unittest
import struct
from agentscope.sni import extract_tls_sni


def build_synthetic_client_hello(hostname: str) -> bytes:
    """
    Constructs a valid binary TLS Client Hello record containing the given SNI hostname.
    """
    host_bytes = hostname.encode("utf-8")
    
    # Server Name extension (0x0000)
    server_name_data = bytes([0x00]) + struct.pack("!H", len(host_bytes)) + host_bytes
    sni_ext_data = struct.pack("!H", len(server_name_data)) + server_name_data
    ext_block = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # Extensions wrapper
    extensions = struct.pack("!H", len(ext_block)) + ext_block

    # Handshake body:
    # client_version (2) + random (32) + session_id_len (1) + cipher_suites_len (2) + cipher (2) + comp_len (1) + comp (1) + extensions
    handshake_body = (
        struct.pack("!H", 0x0303) +  # TLS 1.2
        (b"\x00" * 32) +             # random
        bytes([0x00]) +              # session_id_len 0
        struct.pack("!H", 2) + bytes([0x13, 0x01]) +  # 1 cipher suite (TLS_AES_128_GCM_SHA256)
        bytes([0x01, 0x00]) +        # compression: 1 method, null
        extensions
    )

    # Handshake header: type (1) = 0x01, length (3)
    handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:] + handshake_body

    # TLS Record header: type (1) = 0x16, version (2) = 0x0301, length (2)
    tls_record = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake_header)) + handshake_header
    return tls_record


class TestSNIParser(unittest.TestCase):
    def test_extract_valid_sni(self):
        packet = build_synthetic_client_hello("api.github.com")
        extracted = extract_tls_sni(packet)
        self.assertEqual(extracted, "api.github.com")

        packet2 = build_synthetic_client_hello("registry.npmjs.org")
        extracted2 = extract_tls_sni(packet2)
        self.assertEqual(extracted2, "registry.npmjs.org")

    def test_extract_invalid_or_short_packets(self):
        self.assertIsNone(extract_tls_sni(b""))
        self.assertIsNone(extract_tls_sni(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
        self.assertIsNone(extract_tls_sni(bytes([0x16, 0x03, 0x01, 0x00, 0x05])))

    def test_packet_without_sni(self):
        # Build handshake without extensions
        handshake_body = (
            struct.pack("!H", 0x0303) +
            (b"\x00" * 32) +
            bytes([0x00]) +
            struct.pack("!H", 2) + bytes([0x13, 0x01]) +
            bytes([0x01, 0x00])
        )
        handshake_header = bytes([0x01]) + struct.pack("!I", len(handshake_body))[1:] + handshake_body
        tls_record = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(handshake_header)) + handshake_header
        
        self.assertIsNone(extract_tls_sni(tls_record))


if __name__ == "__main__":
    unittest.main()
