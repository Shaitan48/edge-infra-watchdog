"""Zero-dependency SNMPv2c SetRequest encoder and PoE port controller (RFC 3621)."""

from __future__ import annotations

import logging
import secrets
import socket
import subprocess

logger = logging.getLogger(__name__)

# RFC 3621 POWER-ETHERNET-MIB: pethPsePortAdminEnable (1 = enable, 2 = disable)
SNMP_POE_OID_PREFIX = "1.3.6.1.2.1.105.1.1.1.3.1"


def encode_asn1_tlv(tag: int, value: bytes) -> bytes:
    """Encode an ASN.1/BER Tag-Length-Value tuple."""
    length = len(value)
    if length < 128:
        return bytes([tag, length]) + value
    len_bytes = []
    remaining = length
    while remaining > 0:
        len_bytes.insert(0, remaining & 0xFF)
        remaining >>= 8
    return bytes([tag, 0x80 | len(len_bytes)]) + bytes(len_bytes) + value


def encode_asn1_integer(val: int) -> bytes:
    """Encode an integer as ASN.1 INTEGER (tag 0x02)."""
    if val == 0:
        return b"\x02\x01\x00"
    parts = []
    if val < 0:
        val &= 0xFFFFFFFF
        is_neg = True
    else:
        is_neg = False
    while val > 0:
        parts.insert(0, val & 0xFF)
        val >>= 8
    if not is_neg and parts and (parts[0] & 0x80):
        parts.insert(0, 0x00)
    return encode_asn1_tlv(0x02, bytes(parts))


def encode_asn1_octet_string(data: bytes) -> bytes:
    """Encode an octet string (tag 0x04)."""
    return encode_asn1_tlv(0x04, data)


def encode_asn1_oid(oid_str: str) -> bytes:
    """Encode a dotted OID string into ASN.1 OBJECT IDENTIFIER (tag 0x06)."""
    sub_ids = [int(p) for p in oid_str.strip(".").split(".") if p]
    if len(sub_ids) < 2:
        raise ValueError(f"Invalid OID: {oid_str!r}")
    encoded = [40 * sub_ids[0] + sub_ids[1]]
    for sub in sub_ids[2:]:
        if sub < 128:
            encoded.append(sub)
        else:
            buf = [sub & 0x7F]
            sub >>= 7
            while sub > 0:
                buf.insert(0, 0x80 | (sub & 0x7F))
                sub >>= 7
            encoded.extend(buf)
    return encode_asn1_tlv(0x06, bytes(encoded))


def build_snmpv2c_set_packet(
    community: str, oid_str: str, int_value: int, request_id: int = 1
) -> bytes:
    """Build a raw SNMPv2c SetRequest-PDU (RFC 1905 / RFC 1157) packet."""
    varbind = encode_asn1_tlv(
        0x30, encode_asn1_oid(oid_str) + encode_asn1_integer(int_value)
    )
    varbind_list = encode_asn1_tlv(0x30, varbind)
    pdu_body = (
        encode_asn1_integer(request_id)
        + encode_asn1_integer(0)  # error-status = 0
        + encode_asn1_integer(0)  # error-index = 0
        + varbind_list
    )
    set_pdu = encode_asn1_tlv(0xA3, pdu_body)
    message = (
        encode_asn1_integer(1)  # version = 1 (SNMPv2c)
        + encode_asn1_octet_string(community.encode("latin-1", errors="replace"))
        + set_pdu
    )
    return encode_asn1_tlv(0x30, message)


def _read_tlv_length(buf: bytes, offset: int) -> tuple[int, int]:
    """Read BER TLV length starting at offset, returning (length, next_offset)."""
    first = buf[offset]
    if first < 0x80:
        return first, offset + 1
    num_octets = first & 0x7F
    if num_octets == 0 or offset + 1 + num_octets > len(buf):
        raise ValueError("Malformed BER length")
    val = int.from_bytes(buf[offset + 1 : offset + 1 + num_octets], "big")
    return val, offset + 1 + num_octets


def _is_valid_snmp_response(resp: bytes) -> bool:
    """Verify SNMP response contains GetResponse-PDU (0xA2) with error-status == 0."""
    if len(resp) < 6 or resp[0] != 0x30:
        return False
    idx = resp.find(b"\xa2")
    if idx < 0 or idx + 2 >= len(resp):
        return False
    try:
        _, pos = _read_tlv_length(resp, idx + 1)
        # First element inside GetResponse is request-id (INTEGER 0x02)
        if pos >= len(resp) or resp[pos] != 0x02:
            return False
        req_len, pos = _read_tlv_length(resp, pos + 1)
        pos += req_len
        # Second element is error-status (INTEGER 0x02)
        if pos >= len(resp) or resp[pos] != 0x02:
            return False
        err_len, pos = _read_tlv_length(resp, pos + 1)
        if pos + err_len > len(resp):
            return False
        err_status = int.from_bytes(resp[pos : pos + err_len], "big")
        return err_status == 0
    except (ValueError, IndexError):
        return False


def snmp_set_socket(
    ip: str,
    community: str,
    oid_str: str,
    int_value: int,
    port: int = 161,
    timeout: float = 3.0,
) -> bool:
    """Send an SNMPv2c SetRequest over raw UDP without external libraries."""
    req_id = secrets.randbelow(0x7FFFFFFF) + 1
    packet = build_snmpv2c_set_packet(community, oid_str, int_value, request_id=req_id)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, port))
        resp, _ = sock.recvfrom(4096)
        return _is_valid_snmp_response(resp)
    except OSError as exc:
        logger.debug("SNMP UDP socket error (%s:%d): %s", ip, port, exc)
        return False
    finally:
        sock.close()


def snmp_set_cli_fallback(
    ip: str, community: str, oid_str: str, int_value: int
) -> bool:
    """Fallback to system `snmpset` utility if available."""
    try:
        cmd = [
            "snmpset",
            "-v2c",
            "-c",
            community,
            "-t",
            "2",
            "-r",
            "1",
            ip,
            oid_str,
            "i",
            str(int_value),
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        return res.returncode == 0
    except OSError:
        return False
    except subprocess.SubprocessError:
        return False


def snmp_set_poe(
    ip: str,
    community: str,
    port_num: int,
    enable: bool,
    snmp_port: int = 161,
    oid_prefix: str = SNMP_POE_OID_PREFIX,
) -> bool:
    """Enable or disable a PoE switch port via RFC 3621 pethPsePortAdminEnable."""
    oid = f"{oid_prefix}.{port_num}"
    val = 1 if enable else 2
    if snmp_set_socket(ip, community, oid, val, port=snmp_port):
        return True
    return snmp_set_cli_fallback(ip, community, oid, val)
