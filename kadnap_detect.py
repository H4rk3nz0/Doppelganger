#!/usr/bin/env python3
"""
kadnap_pcap_detect.py — Pure-Python KadNap info_hash hunter for packet captures.

KadNap (a DHT/BitTorrent IoT botnet) finds its C2 rendezvous on the public
BitTorrent Mainline DHT using a *deterministic, time-rotating info_hash*. A new
info_hash is derived every 3-hour window from a fixed 64-byte XOR key. Any host
that queries the DHT (get_peers / announce_peer) for one of these hashes — or
offers it in a BitTorrent handshake — is part of the KadNap swarm.

This tool:
  1. Pre-computes every KadNap info_hash for the last N days (default 60 ≈ two
     months) up to +12h from now, for BOTH known key lineages (r1 and r3).
  2. Reads packet captures using a self-contained, dependency-free parser
     (pcap / modified-pcap / pcapng / snoop, transparently gzip/bz2/xz-compressed).
  3. Pulls every info_hash out of DHT and BitTorrent traffic and flags which
     source IPs matched which pre-computed hashes — rendered as a table.

The info_hash algorithm + both XOR keys were taken from the verified KadNap
analysis and re-confirmed byte-for-byte against live capture traffic.

Usage:
    python3 kadnap_pcap_detect.py capture.pcap [more.pcapng.gz ...]
    python3 kadnap_pcap_detect.py *.pcap --json report.json
    python3 kadnap_pcap_detect.py cap.pcap --lookback-days 120
    python3 kadnap_pcap_detect.py --list-hashes            # dump current hashes
    python3 kadnap_pcap_detect.py cap.pcap --from 2026-03-14 --to 2026-03-15
"""

import argparse
import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import socket
import struct
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone

# ============================================================================
# KadNap constants (verified from binary analysis + live captures)
# ============================================================================

# 64-byte XOR keys, one per known build lineage. BOTH are live and used.
XOR_KEYS = [
    ("r1", b"6YL5aNSQv9hLJ42aDKqmnArjES4jxRbfPTnZDdBdpRhJkHJdxqMQmeyCrkg2CBQg"),
    ("r3", b"SfdHWRYy2fUd2WdH9MGvD4vtVDduAPrXxeDuwsxfa8T74FF4nXRDGKSgG6E57XnZ"),
]

WINDOW_SECONDS = 10800  # 3-hour rotation (0x2a30)

# Bencoded torrent-info template; name (8 hex chars) and pieces (20 bytes)
# are filled in at runtime.
TEMPLATE_HEAD = b"d6:lengthi64e4:name8:"
TEMPLATE_MID = b"12:piece lengthi32768e6:pieces20:"

BT_PROTOCOL = b"\x13BitTorrent protocol"   # peer-wire handshake magic

# KadNap derives its C2/callback port from the info_hash: first big-endian
# uint16 within this ephemeral range, scanning the 20-byte hash.
C2_PORT_LO, C2_PORT_HI = 0x4001, 0xFFFD    # 16385 - 65533


# ============================================================================
# Info_hash computation  (verified against live KadNap DHT traffic)
# ============================================================================

def compute_infohash(epoch_floor, xor_key):
    """KadNap deterministic info_hash for a 3-hour-floored epoch + XOR key."""
    epoch_be = struct.pack(">I", epoch_floor)              # big-endian uint32
    hex_epoch = ("%08x" % epoch_floor).encode()           # 8 lowercase hex
    xored = bytes(a ^ b for a, b in zip(xor_key, epoch_be * 16))  # all 64 bytes
    pieces = hashlib.sha1(xored).digest()                 # 20-byte pieces hash
    bencoded = TEMPLATE_HEAD + hex_epoch + TEMPLATE_MID + pieces + b"e"
    return hashlib.sha1(bencoded).digest()                # 20-byte info_hash


def build_infohash_table(start_ts, end_ts):
    """Map info_hash(bytes) -> (epoch_floor, variant) for every 3-hour window
    in [start_ts, end_ts], for every key lineage."""
    table = {}
    epoch = (int(start_ts) // WINDOW_SECONDS) * WINDOW_SECONDS
    last = (int(end_ts) // WINDOW_SECONDS) * WINDOW_SECONDS
    while epoch <= last:
        if epoch > 0:
            for variant, key in XOR_KEYS:
                table[compute_infohash(epoch, key)] = (epoch, variant)
        epoch += WINDOW_SECONDS
    return table


# ============================================================================
# Bencode (minimal, tolerant decoder)
# ============================================================================

def bencode(obj):
    """Encode a Python value to bencode (for building DHT queries)."""
    if isinstance(obj, int):
        return b"i" + str(obj).encode() + b"e"
    if isinstance(obj, bytes):
        return str(len(obj)).encode() + b":" + obj
    if isinstance(obj, str):
        return bencode(obj.encode())
    if isinstance(obj, list):
        return b"l" + b"".join(bencode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        items = sorted(obj.items(),
                       key=lambda kv: kv[0] if isinstance(kv[0], bytes) else kv[0].encode())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError("cannot bencode %r" % type(obj))


def bdecode(data, idx=0):
    """Decode one bencode value at idx. Returns (value, next_idx)."""
    c = data[idx:idx + 1]
    if c == b"d":
        idx += 1
        result = {}
        while data[idx:idx + 1] != b"e":
            key, idx = bdecode(data, idx)
            val, idx = bdecode(data, idx)
            result[key] = val
        return result, idx + 1
    if c == b"l":
        idx += 1
        result = []
        while data[idx:idx + 1] != b"e":
            val, idx = bdecode(data, idx)
            result.append(val)
        return result, idx + 1
    if c == b"i":
        end = data.index(b"e", idx)
        return int(data[idx + 1:end]), end + 1
    if c.isdigit():
        colon = data.index(b":", idx)
        length = int(data[idx:colon])
        start = colon + 1
        if length < 0 or start + length > len(data):
            raise ValueError("string length out of range")
        return data[start:start + length], start + length
    raise ValueError("invalid bencode token at %d" % idx)


# ============================================================================
# Capture readers — pure Python, no external dependencies
# ============================================================================

class Packet:
    __slots__ = ("ts", "proto", "src", "sport", "dst", "dport", "payload", "flags")

    def __init__(self, ts, proto, src, sport, dst, dport, payload, flags=0):
        self.ts, self.proto = ts, proto
        self.src, self.sport = src, sport
        self.dst, self.dport = dst, dport
        self.payload = payload
        self.flags = flags          # TCP flags byte (SYN=0x02, ACK=0x10); 0 for UDP


def open_capture(path):
    """Return a seekable binary file object, transparently decompressing
    gzip / bzip2 / xz inputs."""
    with open(path, "rb") as probe:
        head = probe.read(6)
    if head[:2] == b"\x1f\x8b":                       # gzip
        with gzip.open(path, "rb") as fh:
            return io.BytesIO(fh.read())
    if head[:3] == b"BZh":                            # bzip2
        with bz2.open(path, "rb") as fh:
            return io.BytesIO(fh.read())
    if head[:6] == b"\xfd7zXZ\x00":                   # xz
        with lzma.open(path, "rb") as fh:
            return io.BytesIO(fh.read())
    return open(path, "rb")


# ---- Link-layer + IP decoding ---------------------------------------------

def _ip_payload(ipver, data):
    """From an IPv4/IPv6 packet body, return
    (proto, src, sport, dst, dport, payload) or None."""
    if ipver == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])
        l4 = data[ihl:]
    elif ipver == 6:
        if len(data) < 40:
            return None
        proto = data[6]
        src = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
        l4 = data[40:]
        for _ in range(8):                            # walk extension headers
            if proto in (6, 17) or len(l4) < 8:
                break
            if proto in (0, 43, 60):                  # hop-by-hop / routing / dest
                proto, ext = l4[0], (l4[1] + 1) * 8
                l4 = l4[ext:]
            elif proto == 44:                         # fragment (fixed 8 bytes)
                proto, l4 = l4[0], l4[8:]
            else:
                break
    else:
        return None

    if proto == 17 and len(l4) >= 8:                  # UDP
        sport, dport = struct.unpack("!HH", l4[0:4])
        return ("udp", src, sport, dst, dport, l4[8:], 0)
    if proto == 6 and len(l4) >= 20:                  # TCP
        sport, dport = struct.unpack("!HH", l4[0:4])
        off = ((l4[12] >> 4) & 0x0F) * 4
        if off < 20 or len(l4) < off:
            return None
        return ("tcp", src, sport, dst, dport, l4[off:], l4[13])
    return None


def _decode_link(linktype, frame):
    """Return (ipver, ip_bytes) from a captured link-layer frame, or None.
    linktype uses libpcap LINKTYPE_* numbering."""
    if linktype == 1:                                 # EN10MB (Ethernet II)
        if len(frame) < 14:
            return None
        etype = struct.unpack("!H", frame[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:   # VLAN
            etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        if etype == 0x0800:
            return (4, frame[off:])
        if etype == 0x86DD:
            return (6, frame[off:])
        return None
    if linktype == 113:                               # LINUX_SLL
        if len(frame) < 16:
            return None
        etype = struct.unpack("!H", frame[14:16])[0]
        body = frame[16:]
    elif linktype == 276:                             # LINUX_SLL2
        if len(frame) < 20:
            return None
        etype = struct.unpack("!H", frame[0:2])[0]
        body = frame[20:]
    elif linktype in (12, 14, 101):                   # RAW IP
        return (frame[0] >> 4, frame) if frame else None
    elif linktype == 0:                               # NULL / loopback
        if len(frame) < 4:
            return None
        fam = struct.unpack("=I", frame[0:4])[0]
        if fam == 2:
            return (4, frame[4:])
        if fam in (24, 28, 30):
            return (6, frame[4:])
        return (frame[4] >> 4, frame[4:]) if len(frame) > 4 else None
    else:
        return None
    if etype == 0x0800:
        return (4, body)
    if etype == 0x86DD:
        return (6, body)
    return None


def _frame_to_packet(linktype, data, ts):
    dec = _decode_link(linktype, data)
    if not dec:
        return None
    res = _ip_payload(dec[0], dec[1])
    if not res:
        return None
    proto, src, sport, dst, dport, payload, flags = res
    return Packet(ts, proto, src, sport, dst, dport, payload, flags)


# ---- pcap / modified-pcap --------------------------------------------------

_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6, 16),   # std LE, microsecond
    b"\xa1\xb2\xc3\xd4": (">", 1e6, 16),   # std BE, microsecond
    b"\x4d\x3c\xb2\xa1": ("<", 1e9, 16),   # nsec LE
    b"\xa1\xb2\x3c\x4d": (">", 1e9, 16),   # nsec BE
    b"\x34\xcd\xb2\xa1": ("<", 1e6, 24),   # modified LE (extra per-record fields)
    b"\xa1\xb2\xcd\x34": (">", 1e6, 24),   # modified BE
}


def _iter_pcap(fh, magic):
    endian, tsdiv, rechdr = _PCAP_MAGICS[magic]
    rest = fh.read(20)                                # remainder of 24-byte header
    if len(rest) < 20:
        return
    linktype = struct.unpack(endian + "I", rest[16:20])[0]
    while True:
        rec = fh.read(rechdr)
        if len(rec) < rechdr:
            break
        ts_s, ts_frac, incl, _orig = struct.unpack(endian + "IIII", rec[:16])
        data = fh.read(incl)
        if len(data) < incl:
            break
        pkt = _frame_to_packet(linktype, data, ts_s + ts_frac / tsdiv)
        if pkt:
            yield pkt


# ---- pcapng ----------------------------------------------------------------

def _pcapng_tsresol(opts, endian):
    """if_tsresol (option code 9); returns ticks-per-second. Default 1e6."""
    i = 0
    while i + 4 <= len(opts):
        code, ln = struct.unpack(endian + "HH", opts[i:i + 4])
        i += 4
        if code == 0:
            break
        if code == 9 and ln >= 1:
            r = opts[i]
            return float(2 ** (r & 0x7F)) if (r & 0x80) else float(10 ** r)
        i += ln + ((4 - ln % 4) % 4)
    return 1e6


def _iter_pcapng(fh):
    fh.seek(0)
    endian = "<"
    if_link, if_div = [], []
    while True:
        head = fh.read(8)
        if len(head) < 8:
            break
        btype = struct.unpack(endian + "I", head[0:4])[0]
        if btype == 0x0A0D0D0A:                       # Section Header Block
            bom = fh.read(4)
            endian = ">" if bom == b"\x1a\x2b\x3c\x4d" else "<"
            blen = struct.unpack(endian + "I", head[4:8])[0]
            if blen < 16:
                break
            fh.read(blen - 12)                        # rest of SHB + trailing len
            if_link, if_div = [], []
            continue
        blen = struct.unpack(endian + "I", head[4:8])[0]
        if blen < 12:
            break
        body = fh.read(blen - 12)
        fh.read(4)                                    # trailing total length
        if btype == 0x00000001:                       # Interface Description Block
            if_link.append(struct.unpack(endian + "H", body[0:2])[0])
            if_div.append(_pcapng_tsresol(body[8:], endian))
        elif btype == 0x00000006:                     # Enhanced Packet Block
            ifid = struct.unpack(endian + "I", body[0:4])[0]
            tsh, tsl = struct.unpack(endian + "II", body[4:12])
            caplen = struct.unpack(endian + "I", body[12:16])[0]
            data = body[20:20 + caplen]
            lt = if_link[ifid] if ifid < len(if_link) else 1
            div = if_div[ifid] if ifid < len(if_div) else 1e6
            pkt = _frame_to_packet(lt, data, ((tsh << 32) | tsl) / div)
            if pkt:
                yield pkt
        elif btype == 0x00000003:                     # Simple Packet Block
            lt = if_link[0] if if_link else 1
            pkt = _frame_to_packet(lt, body[4:], 0.0)
            if pkt:
                yield pkt


# ---- snoop (RFC 1761) ------------------------------------------------------

# snoop datalink type -> libpcap LINKTYPE_*
_SNOOP_LINK = {0: 1, 4: 1, 8: -1}                     # 802.3 & Ethernet -> EN10MB


def _iter_snoop(fh):
    fh.seek(0)
    if fh.read(8) != b"snoop\x00\x00\x00":
        return
    fh.read(4)                                        # version
    dl = struct.unpack(">I", fh.read(4))[0]
    linktype = _SNOOP_LINK.get(dl, 1)
    if linktype < 0:
        return
    while True:
        rh = fh.read(24)
        if len(rh) < 24:
            break
        (_orig, incl, reclen, _drops, ts_s, ts_us) = struct.unpack(">IIIIII", rh)
        pad = reclen - 24 - incl
        data = fh.read(incl)
        if len(data) < incl:
            break
        if pad > 0:
            fh.read(pad)
        pkt = _frame_to_packet(linktype, data, ts_s + ts_us / 1e6)
        if pkt:
            yield pkt


def iter_packets(path):
    """Yield Packets from one capture file of any supported format."""
    fh = open_capture(path)
    try:
        magic = fh.read(4)
        fh.seek(0)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _iter_pcapng(fh)
        elif magic[:4] == b"snoo":
            yield from _iter_snoop(fh)
        elif magic in _PCAP_MAGICS:
            fh.read(4)
            yield from _iter_pcap(fh, magic)
        else:
            raise RuntimeError(
                "unsupported capture format (magic %s). Supported: pcap, "
                "modified-pcap, pcapng, snoop (optionally gz/bz2/xz)."
                % magic.hex())
    finally:
        fh.close()


# ============================================================================
# Analyzer — extract info_hashes from DHT + BitTorrent, match the table
# ============================================================================

class Device:
    """A confirmed-infected host on the monitored network."""
    def __init__(self, ip):
        self.ip = ip
        self.hashes = {}        # info_hash_hex -> [epoch, variant, vias:set, hits]
        self.dht_queries = 0


class Analyzer:
    def __init__(self, ih_table):
        self.ih_table = ih_table
        self.devices = {}                # ip -> Device  (infected, on-network)
        self.stats = defaultdict(int)

    def _device(self, ip):
        d = self.devices.get(ip)
        if d is None:
            d = self.devices[ip] = Device(ip)
        return d

    def _hit(self, ip, ih, via, ts):
        epoch, variant = self.ih_table[ih]
        d = self._device(ip)
        h = ih.hex()
        if h not in d.hashes:
            d.hashes[h] = [epoch, variant, set([via]), 0]
        d.hashes[h][2].add(via)
        d.hashes[h][3] += 1
        self.stats["hash_matches"] += 1

    def process(self, pkt):
        self.stats["packets"] += 1
        if pkt.proto == "udp":
            self._dht(pkt)
        elif pkt.proto == "tcp":
            self._bt(pkt)

    # ---- DHT: only count a host as infected if IT emitted the query ----
    def _dht(self, pkt):
        pay = pkt.payload
        if not pay or pay[:1] != b"d":
            return
        try:
            msg, _ = bdecode(pay)
        except (ValueError, IndexError):
            return
        if not isinstance(msg, dict) or b"y" not in msg:
            return
        self.stats["dht_messages"] += 1
        if msg.get(b"y") != b"q":
            return
        a = msg.get(b"a")
        if not isinstance(a, dict):
            return
        self.stats["dht_queries"] += 1
        qtype = (msg.get(b"q") or b"?").decode("latin1")
        for field in (b"info_hash", b"target"):
            ih = a.get(field)
            if isinstance(ih, bytes) and len(ih) == 20 and ih in self.ih_table:
                self._device(pkt.src).dht_queries += 1
                self._hit(pkt.src, ih, "DHT %s" % qtype, pkt.ts)

    # ---- BitTorrent handshake: the host offering a matched hash is infected ----
    def _bt(self, pkt):
        pay = pkt.payload
        if not pay or not pay.startswith(BT_PROTOCOL):
            return
        self.stats["bt_handshakes"] += 1
        if len(pay) >= 48:                            # 1+19 +8 reserved +20 hash
            ih = pay[28:48]
            if ih in self.ih_table:
                self._hit(pkt.src, ih, "BT handshake", pkt.ts)


# ============================================================================
# Phase 2 — live DHT walk + current-C2 discovery (silent connect → valid sig)
# ============================================================================

# Static AES-256-ECB keys used by the C2 to encrypt the FIRST auth packet.
AES_KEY_R1 = b"qFHV7xjr8XprzZsd26yUJ3vAYQUHprbG"
AES_KEY_R3 = b"jV9YUDanATgt9E8Sd39jPEFgSaxDWbmV"
STATIC_AES_KEYS = [("r3", AES_KEY_R3), ("r1", AES_KEY_R1)]

# DSA subgroup order (q) per lineage. A C2 auth signature is considered valid
# (same criterion as kadnap_r3_sig_harvest.py) when its r and s both fall in
# [1, q) — i.e. well-formed DSA signature components for that operator key.
R1_DSA_Q = 0xf83a979e356e7aa29d2283d5d07dfc0c0dd1aceb27758d53badde8a5
R3_DSA_Q = 0xc2a32c1c8b3790792da196312422c94b1472fe1e7ca7213bc94d60a3

DHT_BOOTSTRAP = [
    # --- the 5 bootstrap nodes hardcoded in the KadNap binaries ---
    ("router.bittorrent.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
    ("dht.libtorrent.org", 25401),
    ("bttracker.debian.org", 6881),
    # --- additional well-known public mainline-DHT routers (wider seeding) ---
    ("router.bitcomet.com", 6881),
    ("dht.aelitis.com", 6881),
    ("router.bittorrent.cloud", 6881),
    ("router.silotis.us", 6881),         # IPv6 router
    ("dht.libtorrent.org", 6881),
    # --- Russian / CIS seed: the de-facto ISP retracker convention. Resolves
    #     only inside RU/CIS ISP networks (skipped elsewhere). ---
    ("retracker.local", 6881),
    # NOTE: the KadNap binaries reference ONLY the first 5 hosts above; there
    # are no RU/EE bootstrap hostnames in the samples and the mainline DHT has
    # no canonical ones. Once bootstrapped, the iterative walk reaches the
    # target hash's swarm globally regardless of entry point. Append any
    # specific region bootstrap nodes (host/IP, port) here:
    # ("203.0.113.5", 6881),
]


def current_window_hashes(now=None):
    """info_hashes for the previous / current / next 3-hour windows, both keys.
    Returns list of (info_hash_bytes, epoch, variant)."""
    if now is None:
        now = time.time()
    cur = (int(now) // WINDOW_SECONDS) * WINDOW_SECONDS
    out = []
    for off in (-WINDOW_SECONDS, 0, WINDOW_SECONDS):
        epoch = cur + off
        if epoch <= 0:
            continue
        for variant, key in XOR_KEYS:
            out.append((compute_infohash(epoch, key), epoch, variant))
    return out


def derive_c2_port(info_hash):
    """KadNap's C2/callback port: first big-endian uint16 in the bot range,
    scanning the 20-byte info_hash (defaults to 0x4001)."""
    for off in range(0, len(info_hash) - 1):
        p = int.from_bytes(info_hash[off:off + 2], "big")
        if C2_PORT_LO <= p <= C2_PORT_HI:
            return p
    return C2_PORT_LO


def _parse_nodes(raw):
    """Compact node list -> [(node_id_20b, ip, port)]."""
    out = []
    for i in range(0, len(raw) - 25, 26):
        nid = raw[i:i + 20]
        ip = socket.inet_ntoa(raw[i + 20:i + 24])
        port = int.from_bytes(raw[i + 24:i + 26], "big")
        if port:
            out.append((nid, ip, port))
    return out


def _xor_dist(a, b):
    return int.from_bytes(bytes(x ^ y for x, y in zip(a, b)), "big")


def dht_walk(info_hashes, timeout=4.0, max_hops=20, k=8, log=lambda *_: None):
    """A fresh iterative Kademlia walk: bootstrap, then for each target
    info_hash repeatedly query the k closest *unqueried* nodes (by XOR distance
    to the full 20-byte hash), converging up to `max_hops` hops. Peers returned
    in `values` are members of the exact-hash swarm.

    Returns (bootstrapped_node_count, set_of_peer (ip, port))."""
    nid = os.urandom(20)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Short per-recv timeout: drain responses until a brief lull.
    sock.settimeout(min(timeout, 1.5))
    try:
        sock.bind(("0.0.0.0", 0))
    except OSError:
        pass
    peers = set()

    def drain(on_resp):
        while True:
            try:
                data, _ = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                break
            try:
                msg, _ = bdecode(data)
            except (ValueError, IndexError):
                continue
            if isinstance(msg, dict):
                on_resp(msg)

    # ---- Bootstrap: find_node toward each target hash to seed near it. ----
    seeds = []
    for host, port in DHT_BOOTSTRAP:
        try:
            seeds.append((socket.gethostbyname(host), port))
        except OSError:
            continue
    for ih, _e, _v in info_hashes:
        for s in seeds:
            try:
                sock.sendto(bencode({b"t": b"fn", b"y": b"q", b"q": b"find_node",
                                     b"a": {b"id": nid, b"target": ih}}), s)
            except OSError:
                pass
    initial = {}                                   # (ip,port) -> node_id
    def seed(msg):
        r = msg.get(b"r")
        if isinstance(r, dict) and isinstance(r.get(b"nodes"), bytes):
            for n, ip, p in _parse_nodes(r[b"nodes"]):
                initial[(ip, p)] = n
    drain(seed)
    log("bootstrapped %d nodes" % len(initial))
    if not initial:
        sock.close()
        return 0, peers

    # ---- Iterative closest-node walk per target hash. ----
    for ih, _e, variant in info_hashes:
        candidates = dict(initial)                 # (ip,port) -> node_id
        queried = set()
        best = None
        stale = 0
        hop = 0
        while hop < max_hops:
            hop += 1
            unqueried = [(kp, nd) for kp, nd in candidates.items()
                         if kp not in queried]
            if not unqueried:
                break
            unqueried.sort(key=lambda kn: _xor_dist(kn[1], ih))
            batch = unqueried[:k]                   # k closest still-unqueried
            for kp, _nd in batch:
                queried.add(kp)
                try:
                    sock.sendto(bencode({b"t": b"gp", b"y": b"q",
                                         b"q": b"get_peers",
                                         b"a": {b"id": nid, b"info_hash": ih}}), kp)
                except OSError:
                    pass
            before_nodes, before_peers = len(candidates), len(peers)

            def handle(msg):
                r = msg.get(b"r")
                if not isinstance(r, dict):
                    return
                for v in (r.get(b"values") or []):
                    if isinstance(v, bytes) and len(v) == 6:
                        peers.add((socket.inet_ntoa(v[:4]),
                                   int.from_bytes(v[4:6], "big")))
                if isinstance(r.get(b"nodes"), bytes):
                    for n, ip, p in _parse_nodes(r[b"nodes"]):
                        candidates.setdefault((ip, p), n)
            drain(handle)

            closest = min((_xor_dist(nd, ih) for nd in candidates.values()),
                          default=None)
            improved = best is None or (closest is not None and closest < best)
            if improved:
                best = closest
            # Converged: no closer node and nothing new discovered this hop.
            if (not improved and len(candidates) == before_nodes
                    and len(peers) == before_peers):
                stale += 1
                if stale >= 3:
                    break
            else:
                stale = 0
        log("%s: walked %d hop(s), %d peer(s) total" % (variant, hop, len(peers)))
    sock.close()
    return len(initial), peers


def _parse_dsa_sig(sig):
    """Parse a DER SEQUENCE{INTEGER r, INTEGER s}. Returns (r, s) or None."""
    try:
        if sig[0] != 0x30:
            return None
        r_len = sig[3]
        r = int.from_bytes(sig[4:4 + r_len], "big")
        s_off = 4 + r_len
        s_len = sig[s_off + 1]
        s = int.from_bytes(sig[s_off + 2:s_off + 2 + s_len], "big")
        return r, s
    except (IndexError, ValueError):
        return None


def confirm_c2(ip, port, timeout=8.0):
    """KadNap C2 handshake: connect SILENTLY (send nothing) and wait for the
    server to speak first. A genuine C2 sends a framed auth packet
    [total:2BE][plen:2BE][AES-256-ECB body] encrypted with the static key; the
    decrypted body is session_key(32) + DER DSA signature. We classify the
    signature exactly like the project's harvester: r and s must lie in [1, q)
    for the r3 or r1 operator key. Returns a dict on success, else None."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from Cryptodome.Cipher import AES
        except ImportError:
            return None

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        hdr = b""
        while len(hdr) < 4:                       # never send first — wait for C2
            c = s.recv(4 - len(hdr))
            if not c:
                return None
            hdr += c
        total = int.from_bytes(hdr[0:2], "big")
        plen = int.from_bytes(hdr[2:4], "big")
        if not (36 <= total <= 4096 and 34 <= plen <= total - 4):
            return None
        body = b""
        while len(body) < total - 4:
            c = s.recv(total - 4 - len(body))
            if not c:
                return None
            body += c
        blk = ((plen + 15) // 16) * 16
        if len(body) < blk:
            return None
        for tag, key in STATIC_AES_KEYS:
            dec = AES.new(key, AES.MODE_ECB).decrypt(body[:blk])
            if not (len(dec) > 34 and dec[32] == 0x30):
                continue
            sk = dec[:32]
            rs = _parse_dsa_sig(dec[32:plen])
            if not rs:
                continue
            r, sval = rs
            if 0 < r < R3_DSA_Q and 0 < sval < R3_DSA_Q:
                variant = "r3"
            elif 0 < r < R1_DSA_Q and 0 < sval < R1_DSA_Q:
                variant = "r1"
            else:
                continue                          # not a valid r1/r3 DSA sig
            return {"ip": ip, "port": port, "key_variant": variant,
                    "aes_key": tag, "session_key": sk.hex(),
                    "sig": dec[32:plen].hex(), "r_bits": r.bit_length(),
                    "s_bits": sval.bit_length()}
        return None
    except (OSError, socket.timeout):
        return None
    finally:
        s.close()


def discover_current_c2(timeout=4.0, max_hops=20, max_peers=40, c2_timeout=6.0,
                        log=lambda *_: None):
    """Live: fresh DHT walk (up to max_hops) for the current epoch's exact
    info_hash, then silently probe discovered peers to find the one that returns
    a valid auth signature = the current C2."""
    import concurrent.futures as cf

    hashes = current_window_hashes()
    cur_epoch = (int(time.time()) // WINDOW_SECONDS) * WINDOW_SECONDS
    result = {"epoch": cur_epoch, "hashes": hashes, "bootstrapped": 0,
              "peers": set(), "c2": [], "error": None}

    # Walk only the current 3-hour window's hashes (what the bot is querying now).
    current = [(h, e, v) for h, e, v in hashes if e == cur_epoch]
    boot, peers = dht_walk(current, timeout=timeout, max_hops=max_hops, log=log)
    result["bootstrapped"] = boot
    result["peers"] = peers
    if not peers:
        if boot == 0:
            result["error"] = "no DHT bootstrap response (no network egress?)"
        else:
            result["error"] = "no swarm peers found for current info_hash"
        return result

    log("found %d swarm peers; probing for C2..." % len(peers))
    # Candidate C2 ports = info_hash-derived ports for the current window.
    derived = sorted({derive_c2_port(h) for h, _, _ in current})
    targets = []
    for ip, ann_port in list(peers)[:max_peers]:
        seen = set()
        for p in derived + [ann_port]:
            if p not in seen:
                seen.add(p)
                targets.append((ip, p))

    confirmed = {}
    with cf.ThreadPoolExecutor(max_workers=min(32, len(targets) or 1)) as ex:
        futs = {ex.submit(confirm_c2, ip, p, c2_timeout): (ip, p)
                for ip, p in targets}
        for fut in cf.as_completed(futs):
            r = fut.result()
            if r:
                confirmed[(r["ip"], r["port"])] = r
    result["c2"] = list(confirmed.values())
    return result


# ============================================================================
# Pretty table rendering
# ============================================================================

COLOR = sys.stdout.isatty()


def _c(code, text):
    return "\x1b[%sm%s\x1b[0m" % (code, text) if COLOR else text


def render_table(headers, rows, colors=None):
    """rows: list of list[str]. colors: list of ANSI codes per column (or None)."""
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i])))

    def line(l, m, rr):
        return l + m.join("─" * (widths[i] + 2) for i in range(cols)) + rr

    out = [line("┌", "┬", "┐")]
    out.append("│ " + " │ ".join(_c("1", headers[i].ljust(widths[i]))
                                 for i in range(cols)) + " │")
    out.append(line("├", "┼", "┤"))
    for r in rows:
        cells = []
        for i in range(cols):
            plain = str(r[i])
            pad = " " * (widths[i] - len(plain))
            code = colors[i] if colors and colors[i] else None
            cells.append((_c(code, plain) if code else plain) + pad)
        out.append("│ " + " │ ".join(cells) + " │")
    out.append(line("└", "┴", "┘"))
    return "\n".join(out)


def _fmt(epoch):
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def _section(title):
    print()
    print(_c("1;37", title.upper()))
    print(_c("1;30", "-" * 14))


def print_report(analyzer, span_lo, span_hi, c2_result):
    s = analyzer.stats
    n_windows = len(analyzer.ih_table) // max(1, len(XOR_KEYS))

    print()
    print(_c("1;36", "  ╔═══════════════════════════════════════════════════════════════╗"))
    print(_c("1;36", "  ║            KadNap infection + live-C2 detection report         ║"))
    print(_c("1;36", "  ╚═══════════════════════════════════════════════════════════════╝"))
    print("  hash window : %s → %s UTC" % (_fmt(span_lo), _fmt(span_hi)))
    print("  precomputed : %s hashes  (%d windows × %d keys: %s)" % (
        _c("1", len(analyzer.ih_table)), n_windows, len(XOR_KEYS),
        ", ".join(k for k, _ in XOR_KEYS)))
    print("  traffic     : %d packets · %d DHT msgs (%d queries) · %d BT handshakes" % (
        s["packets"], s["dht_messages"], s["dht_queries"], s["bt_handshakes"]))

    # ================= Section 1 =================
    _section("Infected devices based on lookup hashes")
    devices = sorted(analyzer.devices.values(), key=lambda d: _ip_key(d.ip))
    if not devices:
        if s["dht_messages"] or s["bt_handshakes"]:
            print(_c("1;32", "  ✓ DHT/BitTorrent traffic present, but NO device matched a KadNap hash."))
        else:
            print(_c("33", "  · No DHT or BitTorrent traffic found in the capture(s)."))
    else:
        rows = [[d.ip, "+".join(sorted({v[1] for v in d.hashes.values()})),
                 str(len(d.hashes)), str(d.dht_queries)] for d in devices]
        print(render_table(["Device IP", "Keys", "#Hashes", "DHT queries"], rows,
                           ["1;31", "33", None, None]))
        # per-device matched hashes (the lookup hashes that flagged them)
        hrows = []
        for d in devices:
            for h, v in sorted(d.hashes.items(), key=lambda kv: kv[1][0]):
                hrows.append([d.ip, h, v[1], _fmt(v[0]) + " UTC",
                              ", ".join(sorted(v[2]))])
        print()
        print(render_table(
            ["Device IP", "Matched info_hash", "Key", "Window", "Seen via"], hrows,
            ["1;31", "1;33", "33", None, None]))
        print("\n  %s infected device(s)." % _c("1;31", len(devices)))

    # ================= Section 2 =================
    _section("Current C2 server discovered via live DHT walk")
    if c2_result is None:
        print(_c("33", "  · Live DHT walk skipped (--offline)."))
        return
    epoch = c2_result["epoch"]
    print("  current 3h epoch : %d  (%s UTC)" % (epoch, _fmt(epoch)))
    cur = [(h, v) for h, e, v in c2_result["hashes"] if e == epoch]
    for h, v in cur:
        print("    %s info_hash %s → C2 port %d" % (
            v, _c("1;33", h.hex()), derive_c2_port(h)))
    print("  DHT walk : bootstrapped %d nodes, found %d swarm peer(s)" % (
        c2_result["bootstrapped"], len(c2_result["peers"])))

    if not c2_result["c2"]:
        print(_c("33", "  · No current C2 confirmed%s" % (
            " — " + c2_result["error"] if c2_result.get("error") else
            " (no peer returned a valid auth signature)")))
        return

    rows = []
    for c in sorted(c2_result["c2"], key=lambda x: _ip_key(x["ip"])):
        sig = "valid %s DSA sig (r=%d-bit, s=%d-bit, r,s∈[1,q))" % (
            c["key_variant"], c.get("r_bits", 0), c.get("s_bits", 0))
        rows.append(["%s:%d" % (c["ip"], c["port"]), c["key_variant"], sig])
    print()
    print(_c("1;31", "  CONFIRMED CURRENT C2:"))
    print(render_table(["C2 server", "Key", "Auth signature"], rows,
                       ["1;31", "33", "1;32"]))


def to_json(analyzer, span_lo, span_hi, c2_result):
    devices = []
    for d in sorted(analyzer.devices.values(), key=lambda d: _ip_key(d.ip)):
        devices.append({
            "ip": d.ip,
            "keys": sorted({v[1] for v in d.hashes.values()}),
            "dht_queries": d.dht_queries,
            "matched_hashes": [
                {"info_hash": h, "key": v[1], "window_epoch": v[0],
                 "window_utc": _fmt(v[0]), "seen_via": sorted(v[2]), "hits": v[3]}
                for h, v in sorted(d.hashes.items(), key=lambda kv: kv[1][0])],
        })
    out = {
        "window": {"from": int(span_lo), "to": int(span_hi),
                   "from_utc": _fmt(span_lo), "to_utc": _fmt(span_hi)},
        "precomputed_hashes": len(analyzer.ih_table),
        "stats": dict(analyzer.stats),
        "infected_devices": devices,
    }
    if c2_result is not None:
        confirmed = [{"ip": c["ip"], "port": c["port"], "key": c["key_variant"],
                      "aes_key": c.get("aes_key"),
                      "session_key": c.get("session_key"), "sig": c.get("sig"),
                      "r_bits": c.get("r_bits"), "s_bits": c.get("s_bits")}
                     for c in c2_result["c2"]]
        out["live_dht_walk"] = {
            "epoch": c2_result["epoch"], "epoch_utc": _fmt(c2_result["epoch"]),
            "bootstrapped_nodes": c2_result["bootstrapped"],
            "swarm_peers": len(c2_result["peers"]),
            "error": c2_result.get("error"),
            "confirmed_c2": confirmed,
        }
    return out


def _ip_key(ip):
    """Sort IPv4 numerically, IPv6 lexically after IPv4."""
    try:
        return (0,) + tuple(int(o) for o in ip.split("."))
    except ValueError:
        return (1, ip)


# ============================================================================
# CLI
# ============================================================================

def parse_dt(s):
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise argparse.ArgumentTypeError("bad datetime %r (use YYYY-MM-DD[THH:MM])" % s)


def determine_time_span(paths):
    """First pass over the capture(s): return (min_ts, max_ts) of valid packet
    timestamps, or (None, None) if the capture carries no usable timestamps."""
    lo = hi = None
    for path in paths:
        try:
            for pkt in iter_packets(path):
                if pkt.ts and pkt.ts > 0:
                    lo = pkt.ts if lo is None else min(lo, pkt.ts)
                    hi = pkt.ts if hi is None else max(hi, pkt.ts)
        except (RuntimeError, OSError, EOFError, struct.error):
            continue
    return lo, hi


def prompt_timeframe():
    """Ask the user for the capture timeframe when none is in the file."""
    if not sys.stdin.isatty():
        return None
    print("[?] No timestamps found in the capture. Enter the capture timeframe "
          "(UTC); blank to abort.", file=sys.stderr)
    try:
        s = input("    start (YYYY-MM-DD[THH:MM]): ").strip()
        e = input("    end   (YYYY-MM-DD[THH:MM]): ").strip()
    except EOFError:
        return None
    if not s or not e:
        return None
    try:
        return parse_dt(s), parse_dt(e)
    except argparse.ArgumentTypeError as ex:
        print("    %s" % ex, file=sys.stderr)
        return prompt_timeframe()


def resolve_window(args, captures, ap):
    """Compute the (lo, hi) info_hash window.

    Default: from (capture start − pre-days) to (capture end + post-hours).
    --from / --to override either edge exactly. If the capture has no
    timestamps and no override is given, prompt the user (or error)."""
    cap_lo = cap_hi = None
    if args.t_from is None or args.t_to is None:        # need capture-derived span
        if captures:
            print("[*] Determining capture timeframe...", file=sys.stderr)
            cap_lo, cap_hi = determine_time_span(captures)
        if cap_lo is None and (args.t_from is None or args.t_to is None):
            tf = prompt_timeframe()
            if tf is None:
                ap.error("no timestamps in capture; specify --from and --to "
                         "(UTC) to set the window manually")
            cap_lo, cap_hi = tf

    lo = args.t_from if args.t_from is not None else cap_lo - args.pre_days * 86400
    hi = args.t_to if args.t_to is not None else cap_hi + args.post_hours * 3600
    if hi < lo:
        ap.error("window end is before window start")
    return lo, hi


def main():
    ap = argparse.ArgumentParser(
        description="Detect KadNap DHT/BitTorrent info_hashes in packet captures.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("captures", nargs="*",
                    help="capture files: pcap/pcapng/snoop, optionally gz/bz2/xz")
    ap.add_argument("--pre-days", type=float, default=7.0,
                    help="days BEFORE the capture's start to begin the hash "
                         "window (default 7 = one week)")
    ap.add_argument("--post-hours", type=float, default=24.0,
                    help="hours AFTER the capture's end to extend the hash "
                         "window (default 24)")
    ap.add_argument("--from", dest="t_from", type=parse_dt,
                    help="override hash window start exactly (YYYY-MM-DD[THH:MM], UTC)")
    ap.add_argument("--to", dest="t_to", type=parse_dt,
                    help="override hash window end exactly (YYYY-MM-DD[THH:MM], UTC)")
    ap.add_argument("--list-hashes", action="store_true",
                    help="print the precomputed info_hashes and exit")
    ap.add_argument("--offline", action="store_true",
                    help="skip the live DHT walk / current-C2 discovery (Phase 2)")
    ap.add_argument("--dht-timeout", type=float, default=8.0,
                    help="per-step UDP timeout for the live DHT walk (default 4s)")
    ap.add_argument("--max-hops", type=int, default=20,
                    help="max hops for the iterative DHT walk toward the C2 hash (default 20)")
    ap.add_argument("--json", metavar="FILE", help="write a JSON report")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = ap.parse_args()

    global COLOR
    if args.no_color:
        COLOR = False

    for p in args.captures:
        if not os.path.isfile(p):
            ap.error("not a file: %s" % p)
    if not args.captures and not (args.t_from is not None and args.t_to is not None):
        ap.error("give capture file(s) to derive the timeframe, or --from/--to")

    span_lo, span_hi = resolve_window(args, args.captures, ap)
    table = build_infohash_table(span_lo, span_hi)

    if args.list_hashes:
        for ih, (epoch, variant) in sorted(table.items(), key=lambda kv: kv[1]):
            print("%s  %s  %s UTC" % (ih.hex(), variant, _fmt(epoch)))
        print("# %d hashes  (%s → %s UTC)" % (len(table), _fmt(span_lo), _fmt(span_hi)),
              file=sys.stderr)
        return 0

    if not args.captures:
        ap.error("no capture files given (or use --list-hashes)")

    print("[*] Precomputed %d KadNap info_hashes (%s → %s UTC)" % (
        len(table), _fmt(span_lo), _fmt(span_hi)), file=sys.stderr)

    analyzer = Analyzer(table)
    for path in args.captures:
        print("[*] Scanning %s ..." % path, file=sys.stderr)
        try:
            for pkt in iter_packets(path):
                analyzer.process(pkt)
        except (RuntimeError, OSError, EOFError, struct.error) as e:
            print("[!] %s: %s" % (path, e), file=sys.stderr)

    # Phase 2: live DHT walk → confirm current C2 (silent connect + valid sig).
    c2_result = None
    if not args.offline:
        print("[*] Live DHT walk for current 3h epoch info_hash...", file=sys.stderr)
        try:
            c2_result = discover_current_c2(
                timeout=args.dht_timeout, max_hops=args.max_hops,
                log=lambda m: print("    " + m, file=sys.stderr))
        except Exception as e:                       # never let the live phase kill the report
            c2_result = {"epoch": (int(time.time()) // WINDOW_SECONDS) * WINDOW_SECONDS,
                         "hashes": current_window_hashes(), "bootstrapped": 0,
                         "peers": set(), "c2": [], "error": "live walk failed: %s" % e}

    print_report(analyzer, span_lo, span_hi, c2_result)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(to_json(analyzer, span_lo, span_hi, c2_result), fh, indent=2)
        print("\n[*] JSON report written to %s" % args.json, file=sys.stderr)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        os._exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
