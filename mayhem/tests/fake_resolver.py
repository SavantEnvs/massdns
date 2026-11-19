#!/usr/bin/env python3
"""Tiny canned DNS resolver on 127.0.0.1 for mayhem/test.sh (upstream's tests/ need 8.8.8.8).

Usage: fake_resolver.py <portfile>   binds an ephemeral UDP port, writes it to <portfile>, then
answers queries from the fixed ZONE table below until killed. Unknown names get NXDOMAIN.
"""
import socket
import struct
import sys

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV = 1, 2, 5, 6, 12, 15, 16, 28, 33


def name(n):
    out = b""
    for label in n.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def rdata(rtype, value):
    if rtype == A:
        return socket.inet_pton(socket.AF_INET, value)
    if rtype == AAAA:
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in (CNAME, PTR, NS):
        return name(value)
    if rtype == MX:
        return struct.pack(">H", value[0]) + name(value[1])
    if rtype == TXT:
        return b"".join(bytes([len(s)]) + s.encode() for s in value)
    if rtype == SRV:
        return struct.pack(">HHH", *value[:3]) + name(value[3])
    if rtype == SOA:
        return name(value[0]) + name(value[1]) + struct.pack(">IIIII", *value[2:])
    raise ValueError(rtype)


# (qname, qtype) -> list of (owner, type, ttl, value)
ZONE = {
    ("example.com", A): [("example.com", A, 3600, "93.184.216.34")],
    ("example.com", AAAA): [("example.com", AAAA, 3600, "2606:2800:220:1:248:1893:25c8:1946")],
    ("example.com", MX): [("example.com", MX, 300, (10, "mail.example.com")),
                          ("example.com", MX, 300, (20, "backup.example.com"))],
    ("example.com", TXT): [("example.com", TXT, 60, ["v=spf1 -all", "hello world"])],
    ("example.com", SOA): [("example.com", SOA, 900,
                            ("ns1.example.com", "hostmaster.example.com", 2024010101, 7200, 3600, 1209600, 300))],
    ("www.example.com", A): [("www.example.com", CNAME, 120, "example.com"),
                             ("example.com", A, 3600, "93.184.216.34")],
    ("_sip._tcp.example.com", SRV): [("_sip._tcp.example.com", SRV, 86400, (10, 60, 5060, "sip.example.com"))],
    ("4.3.2.1.in-addr.arpa", PTR): [("4.3.2.1.in-addr.arpa", PTR, 86400, "host.example.com")],
}


def parse_qname(pkt, off):
    labels = []
    while pkt[off]:
        ln = pkt[off]
        labels.append(pkt[off + 1:off + 1 + ln].decode("ascii", "replace").lower())
        off += 1 + ln
    return ".".join(labels), off + 1


def answer(pkt):
    qid, flags, qd = struct.unpack(">HHH", pkt[:6])
    if qd != 1:
        return None
    qname, off = parse_qname(pkt, 12)
    qtype, qclass = struct.unpack(">HH", pkt[off:off + 4])
    question = pkt[12:off + 4]
    rrs = ZONE.get((qname, qtype))
    rcode = 0 if rrs is not None or any(k[0] == qname for k in ZONE) else 3
    rrs = rrs or []
    rflags = 0x8000 | (flags & 0x0100) | 0x0080 | rcode  # QR, copy RD, RA
    body = b""
    for owner, rtype, ttl, value in rrs:
        rd = rdata(rtype, value)
        own = b"\xc0\x0c" if owner == qname else name(owner)
        body += own + struct.pack(">HHIH", rtype, 1, ttl, len(rd)) + rd
    return struct.pack(">HHHHHH", qid, rflags, 1, len(rrs), 0, 0) + question + body


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    with open(sys.argv[1] + ".tmp", "w") as f:
        f.write(str(s.getsockname()[1]))
    import os
    os.rename(sys.argv[1] + ".tmp", sys.argv[1])
    while True:
        pkt, addr = s.recvfrom(65535)
        try:
            reply = answer(pkt)
        except Exception:
            reply = None
        if reply:
            s.sendto(reply, addr)


if __name__ == "__main__":
    main()
