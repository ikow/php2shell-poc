"""Deterministic Ethernet/IPv4/TCP capture synthesis. No sockets are opened."""

import ipaddress
import struct
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack("!{}H".format(len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def packet(src, dst, sport, dport, seq, ack, flags, payload=b""):
    source, destination = (
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp) + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        source,
        destination,
    )
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\x02\0\0\0\0\x01\x02\0\0\0\0\x02\x08\0" + ip + tcp + payload


def write_capture(path, request, response, repeat=1):
    """One independent TCP connection per exchange; repeated probes share source IP."""
    if not 1 <= repeat <= 10:
        raise ValueError("repeat must be between 1 and 10")
    data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    timestamp = 1700000000
    for index in range(repeat):
        client, server, port = "203.0.113.10", "192.0.2.10", 40000 + index
        cseq, sseq = 1000, 9000
        frames = []

        def emit(reverse, flags, payload=b""):
            nonlocal cseq, sseq
            if reverse:
                frame = packet(server, client, 80, port, sseq, cseq, flags, payload)
                sseq += len(payload) + bool(flags & 3)
            else:
                frame = packet(client, server, port, 80, cseq, sseq, flags, payload)
                cseq += len(payload) + bool(flags & 3)
            frames.append(frame)

        # SYN has no acknowledgment; remaining packets use established sequence numbers.
        frames.append(packet(client, server, port, 80, cseq, 0, 2))
        cseq += 1
        emit(True, 0x12)
        emit(False, 0x10)
        for reverse, content in (
            (False, request.encode("utf-8")),
            (True, response.encode("utf-8")),
        ):
            for offset in range(0, len(content), 1400):
                emit(reverse, 0x18, content[offset : offset + 1400])
            emit(not reverse, 0x10)
        emit(False, 0x11)
        emit(True, 0x11)
        emit(False, 0x10)
        for micros, frame in enumerate(frames):
            data.extend(
                struct.pack(
                    "<IIII", timestamp + index, micros * 1000, len(frame), len(frame)
                )
            )
            data.extend(frame)
    Path(path).write_bytes(data)


def inspect_capture(path):
    """Bounded classic-PCAP envelope validation; native Suricata handles reassembly."""
    size = Path(path).stat().st_size
    if size > 64 * 1024 * 1024:
        raise ValueError("PCAP exceeds 64 MiB")
    with Path(path).open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        ):
            raise ValueError("Expected classic PCAP (pcapng is not supported)")
        endian = "<" if header[0] in (0xD4, 0x4D) else ">"
        _, major, minor, _, _, snaplen, link = struct.unpack(endian + "IHHIIII", header)
        if (major, minor) != (2, 4) or link != 1 or not 1 <= snaplen <= 262144:
            raise ValueError("Expected Ethernet PCAP v2.4 with a bounded snap length")
        count = 0
        while True:
            entry = stream.read(16)
            if not entry:
                break
            if len(entry) != 16:
                raise ValueError("Truncated PCAP packet header")
            _, _, captured, original = struct.unpack(endian + "IIII", entry)
            if (
                captured > snaplen
                or captured > original
                or len(stream.read(captured)) != captured
            ):
                raise ValueError("Invalid or truncated PCAP packet")
            count += 1
            if count > 200000:
                raise ValueError("PCAP exceeds 200000 packets")
        if count == 0:
            raise ValueError("PCAP contains no packets")
    return {"packets": count, "bytes": size, "link_type": "Ethernet"}
