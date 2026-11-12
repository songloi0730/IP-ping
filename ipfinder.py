#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Finder - dò IP thiết bị công nghiệp (đầu đọc mã vạch, RFID, camera, PLC, I/O...)
khi KHÔNG biết IP và KHÔNG reset được thiết bị.

Nguyên lý: làm việc ở tầng Ethernet (L2) trên đúng card mạng (NIC) cắm thiết bị,
nên KHÔNG cần máy tính và thiết bị cùng lớp mạng (subnet):

  1. Nghe thụ động (passive): ARP, gratuitous ARP, ARP probe, DHCP/BOOTP, LLDP,
     PROFINET DCP Hello, mọi gói IPv4... -> lấy IP + MAC của thiết bị.
     Mẹo: TẮT/BẬT NGUỒN hoặc RÚT/CẮM LẠI CÁP thiết bị trong lúc nghe.
  2. Hỏi chủ động (active), đều là broadcast/multicast L2, không cần cùng subnet:
       - PROFINET DCP Identify All  (Siemens, SICK, Balluff, Turck, P+F, ...)
       - EtherNet/IP ListIdentity    (Cognex, Keyence, Datalogic, Rockwell, ...)
       - ICMP ping broadcast
       - Quét ARP qua các dải IP mặc định phổ biến / dải tự chọn
  3. Hỗ trợ truy cập: thêm IP phụ tạm thời lên NIC (không phá kết nối khác),
     đổi IP qua PROFINET DCP, nháy đèn thiết bị PROFINET để nhận diện.

An toàn cho máy đang chạy sản xuất:
  - Không bao giờ giả mạo IP của thiết bị khác (ARP chỉ dùng IP thật của NIC
    hoặc 0.0.0.0 kiểu "ARP probe"), nên không làm hỏng bảng ARP của PLC/thiết bị khác.
  - Giới hạn tốc độ gửi (mặc định 500 gói/giây).
  - Chỉ chạy trên NIC bạn chọn.

Yêu cầu: Python 3.8+, scapy (pip install scapy). Windows: cài Npcap (https://npcap.com).
Chạy bằng quyền Administrator (Windows) hoặc root/sudo (Linux).
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

__version__ = "1.0.0"

IS_WINDOWS = platform.system() == "Windows"

# Cho phép in tiếng Việt trên console Windows cũ
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

# --------------------------------------------------------------------------------------
# Import scapy (thông báo lỗi dễ hiểu)
# --------------------------------------------------------------------------------------
try:
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.config import conf
    from scapy.interfaces import get_working_ifaces, resolve_iface
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.inet import ICMP, IP, UDP
    from scapy.packet import Raw
    from scapy.sendrecv import AsyncSniffer
except ImportError:  # pragma: no cover
    print("LỖI: chưa cài scapy. Chạy:  pip install scapy")
    if IS_WINDOWS:
        print("Trên Windows cần cài thêm Npcap: https://npcap.com  (tick 'WinPcap API-compatible Mode')")
    sys.exit(2)

conf.verb = 0

BROADCAST = "ff:ff:ff:ff:ff:ff"
DCP_MCAST = "01:0e:cf:00:00:00"
ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_VLAN = 0x8100
ETH_PNIO = 0x8892
ETH_LLDP = 0x88CC
ENIP_PORT = 44818

# Các dải IP mặc định hay gặp trên thiết bị công nghiệp / thiết bị xuất xưởng.
# Dùng cho quét ARP "quick". Có thể thêm dải bằng --range.
QUICK_NETS = [
    "192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24",
    "192.168.4.0/24", "192.168.5.0/24", "192.168.10.0/24", "192.168.11.0/24",
    "192.168.20.0/24", "192.168.50.0/24", "192.168.100.0/24", "192.168.101.0/24",
    "192.168.123.0/24", "192.168.125.0/24", "192.168.127.0/24", "192.168.150.0/24",
    "192.168.200.0/24", "192.168.250.0/24", "192.168.254.0/24", "192.168.255.0/24",
    "10.0.0.0/24", "10.0.1.0/24", "10.1.1.0/24", "10.10.10.0/24", "10.10.0.0/24",
    "172.16.0.0/24", "172.16.1.0/24", "172.20.0.0/24",
]
PRESETS = {
    "quick": QUICK_NETS,
    "192": ["192.168.0.0/16"],
    "wide": ["192.168.0.0/16", "10.0.0.0/16", "10.1.0.0/16", "10.10.0.0/16",
             "172.16.0.0/16", "169.254.0.0/16"],
    "none": [],
}


# --------------------------------------------------------------------------------------
# Tiện ích
# --------------------------------------------------------------------------------------
def die(msg: str, code: int = 1) -> None:
    print("LỖI: " + msg)
    sys.exit(code)


def is_admin() -> bool:
    try:
        if IS_WINDOWS:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0
    except Exception:
        return True


def mac_norm(mac: str) -> str:
    m = mac.strip().lower().replace("-", ":").replace(".", "")
    if ":" not in m and len(m) == 12:
        m = ":".join(m[i:i + 2] for i in range(0, 12, 2))
    return m


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac_norm(mac).split(":"))


def bytes_mac(b: bytes) -> str:
    return ":".join("%02x" % x for x in b)


def vendor_of(mac: str) -> str:
    try:
        v = conf.manufdb._get_manuf(mac)  # type: ignore[attr-defined]
        if v and v.lower() != mac.lower() and not v.lower().startswith(mac[:8].lower()):
            return str(v)
    except Exception:
        pass
    try:
        if int(mac.split(":")[0], 16) & 0x02:
            return "(MAC cục bộ/ngẫu nhiên)"
    except Exception:
        pass
    return ""


def ip_valid_host(ip: str) -> bool:
    try:
        a = ipaddress.IPv4Address(ip)
    except Exception:
        return False
    return not (a.is_unspecified or a.is_multicast or a.is_loopback or ip == "255.255.255.255")


def parse_ranges(items: Iterable[str]) -> List[ipaddress.IPv4Network]:
    """Nhận '192.168.1.0/24', '10.0.0.5', '192.168.1.10-192.168.1.50', '192.168.1.10-50'."""
    nets: List[ipaddress.IPv4Network] = []
    for raw in items:
        for item in raw.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                if "-" in item:
                    a, b = item.split("-", 1)
                    start = ipaddress.IPv4Address(a.strip())
                    b = b.strip()
                    if "." not in b:
                        b = ".".join(str(start).split(".")[:3] + [b])
                    end = ipaddress.IPv4Address(b)
                    if int(end) < int(start):
                        die(f"dải IP '{item}': IP cuối nhỏ hơn IP đầu")
                    if int(end) - int(start) > 1_000_000:
                        die(f"dải IP '{item}' quá lớn")
                    # từng IP /32 để không bỏ sót địa chỉ đầu/cuối của các khối CIDR
                    nets.extend(ipaddress.IPv4Network(v) for v in range(int(start), int(end) + 1))
                else:
                    nets.append(ipaddress.IPv4Network(item, strict=False))
            except ValueError as e:
                die(f"dải IP không hợp lệ '{item}': {e}")
    return nets


def hosts_of(nets: Iterable[ipaddress.IPv4Network]) -> List[str]:
    seen: Set[int] = set()
    out: List[str] = []
    for n in nets:
        it = n.hosts() if n.prefixlen < 31 else iter(n)
        for h in it:
            v = int(h)
            if v not in seen:
                seen.add(v)
                out.append(str(h))
    return out


# --------------------------------------------------------------------------------------
# Card mạng (NIC)
# --------------------------------------------------------------------------------------
@dataclass
class Nic:
    iface: object  # scapy NetworkInterface
    name: str
    description: str
    mac: str
    index: int
    ipv4: List[Tuple[str, int]]  # (ip, prefixlen)

    @property
    def networks(self) -> List[ipaddress.IPv4Network]:
        return [ipaddress.IPv4Network(f"{ip}/{p}", strict=False) for ip, p in self.ipv4]

    @property
    def first_ip(self) -> Optional[str]:
        for ip, _ in self.ipv4:
            if not ip.startswith("169.254."):
                return ip
        return self.ipv4[0][0] if self.ipv4 else None

    def label(self) -> str:
        ips = ", ".join(f"{ip}/{p}" for ip, p in self.ipv4) or "(chưa có IPv4)"
        desc = f" - {self.description}" if self.description and self.description != self.name else ""
        return f"{self.name}{desc}  MAC {self.mac}  IP {ips}"


def _route_iface_name(r_iface: object) -> str:
    try:
        return resolve_iface(r_iface).network_name  # type: ignore[arg-type]
    except Exception:
        return str(r_iface)


def get_nics() -> List[Nic]:
    try:
        conf.route.resync()
    except Exception:
        pass
    routes = list(getattr(conf.route, "routes", []))
    nics: List[Nic] = []
    for i in get_working_ifaces():
        mac = (getattr(i, "mac", "") or "").lower()
        ips4 = list(getattr(i, "ips", {}).get(4, []) or [])
        if not mac or mac == "00:00:00:00:00:00":
            continue
        if ips4 and all(ip.startswith("127.") for ip in ips4):
            continue
        prefixes: List[Tuple[str, int]] = []
        for ip in ips4:
            best = None
            for r in routes:
                try:
                    net, mask, _gw, r_if, addr = r[0], r[1], r[2], r[3], r[4]
                except Exception:
                    continue
                if addr != ip or mask in (0, 0xFFFFFFFF):
                    continue
                if _route_iface_name(r_if) != i.network_name:
                    continue
                if (net >> 28) == 0xE:  # multicast
                    continue
                pl = bin(mask).count("1")
                if (int(ipaddress.IPv4Address(ip)) & mask) == net and (best is None or pl > best):
                    best = pl
            prefixes.append((ip, best if best is not None else 24))
        nics.append(Nic(i, str(i.name), str(getattr(i, "description", "") or ""), mac,
                        int(getattr(i, "index", 0) or 0), prefixes))
    nics.sort(key=lambda n: n.index)
    return nics


def find_nic(nics: List[Nic], key: str) -> Nic:
    k = key.strip().lower()
    if k.isdigit():
        for n in nics:
            if n.index == int(k):
                return n
    for n in nics:
        if k in (n.name.lower(), n.mac, n.description.lower(), str(getattr(n.iface, "network_name", "")).lower()):
            return n
    cands = [n for n in nics if k in n.name.lower() or k in n.description.lower()]
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        die(f"tên card '{key}' khớp nhiều card: " + "; ".join(c.name for c in cands))
    die(f"không tìm thấy card mạng '{key}'. Chạy 'ipfinder ifaces' để xem danh sách.")
    raise SystemExit  # for type checkers


def print_nics(nics: List[Nic]) -> None:
    print("Các card mạng (NIC) đang hoạt động:")
    for n in nics:
        print(f"  [{n.index:>3}] {n.label()}")
    # Cảnh báo các subnet trùng giữa các NIC
    seen: List[Tuple[ipaddress.IPv4Network, str]] = []
    for n in nics:
        for net in n.networks:
            for onet, oname in seen:
                if net.overlaps(onet) and oname != n.name:
                    print(f"  ! CẢNH BÁO: subnet {net} của '{n.name}' trùng với {onet} của '{oname}'")
            seen.append((net, n.name))


# --------------------------------------------------------------------------------------
# Lưu kết quả thiết bị
# --------------------------------------------------------------------------------------
@dataclass
class Device:
    nic: str
    mac: str
    vendor: str = ""
    ips: Dict[str, Set[str]] = field(default_factory=dict)   # ip -> nguồn phát hiện
    probes: Set[str] = field(default_factory=set)           # IP thiết bị đang "thử" (ARP probe)
    asked: Set[str] = field(default_factory=set)            # IP thiết bị đang tìm (gateway/server)
    names: Set[str] = field(default_factory=set)
    info: Dict[str, str] = field(default_factory=dict)
    dhcp: bool = False
    ipv6_only: bool = False
    first: float = field(default_factory=time.time)
    last: float = field(default_factory=time.time)
    packets: int = 0

    def best_ips(self) -> List[str]:
        return sorted(self.ips, key=lambda ip: -len(self.ips[ip]))

    def to_dict(self) -> dict:
        return {
            "nic": self.nic, "mac": self.mac, "vendor": self.vendor,
            "ips": {ip: sorted(src) for ip, src in self.ips.items()},
            "probing_ips": sorted(self.probes), "asking_for": sorted(self.asked),
            "names": sorted(self.names), "info": self.info, "dhcp_mode": self.dhcp,
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last)),
            "packets": self.packets,
        }


class Registry:
    def __init__(self, verbose: bool = True, mac_filter: Optional[List[str]] = None):
        self.devs: Dict[Tuple[str, str], Device] = {}
        self.lock = threading.Lock()
        self.verbose = verbose
        self.mac_filter = [mac_norm(m) for m in (mac_filter or [])]

    def _match(self, mac: str) -> bool:
        return not self.mac_filter or any(mac.startswith(f) for f in self.mac_filter)

    def _get(self, nic: str, mac: str) -> Optional[Device]:
        if not self._match(mac):
            return None
        key = (nic, mac)
        d = self.devs.get(key)
        if d is None:
            d = Device(nic=nic, mac=mac, vendor=vendor_of(mac))
            self.devs[key] = d
            self._log(f"[{nic}] Thiết bị mới MAC {mac} {d.vendor}")
        d.last = time.time()
        d.packets += 1
        return d

    def _log(self, s: str) -> None:
        if self.verbose:
            print(time.strftime("%H:%M:%S ") + s, flush=True)

    def seen(self, nic: str, mac: str) -> None:
        with self.lock:
            self._get(nic, mac)

    def add_ip(self, nic: str, mac: str, ip: str, source: str) -> None:
        if not ip_valid_host(ip):
            return
        with self.lock:
            d = self._get(nic, mac)
            if d is None:
                return
            if ip not in d.ips:
                d.ips[ip] = set()
                self._log(f"[{nic}]   {mac} có IP {ip}  (qua {source})")
            d.ips[ip].add(source)
            d.ipv6_only = False

    def add_probe(self, nic: str, mac: str, ip: str) -> None:
        if not ip_valid_host(ip):
            return
        with self.lock:
            d = self._get(nic, mac)
            if d and ip not in d.probes:
                d.probes.add(ip)
                self._log(f"[{nic}]   {mac} đang khởi động, thử nhận IP {ip} (ARP probe)")

    def add_asked(self, nic: str, mac: str, ip: str) -> None:
        if not ip_valid_host(ip):
            return
        with self.lock:
            d = self._get(nic, mac)
            if d and ip not in d.asked and len(d.asked) < 20:
                d.asked.add(ip)

    def add_name(self, nic: str, mac: str, name: str) -> None:
        name = name.strip().strip("\x00")
        if not name:
            return
        with self.lock:
            d = self._get(nic, mac)
            if d and name not in d.names:
                d.names.add(name)
                self._log(f"[{nic}]   {mac} tên: {name}")

    def add_info(self, nic: str, mac: str, key: str, value: str) -> None:
        with self.lock:
            d = self._get(nic, mac)
            if d and value and d.info.get(key) != value:
                d.info[key] = value

    def set_dhcp(self, nic: str, mac: str) -> None:
        with self.lock:
            d = self._get(nic, mac)
            if d and not d.dhcp:
                d.dhcp = True
                self._log(f"[{nic}]   {mac} đang xin IP qua DHCP/BOOTP (thiết bị ở chế độ DHCP)")

    def mark_ipv6(self, nic: str, mac: str) -> None:
        with self.lock:
            d = self._get(nic, mac)
            if d and not d.ips:
                d.ipv6_only = True

    def list(self) -> List[Device]:
        with self.lock:
            return sorted(self.devs.values(), key=lambda d: (d.nic, d.mac))


# --------------------------------------------------------------------------------------
# Giải mã các giao thức
# --------------------------------------------------------------------------------------
def parse_dcp_blocks(data: bytes) -> List[Tuple[int, int, bytes]]:
    blocks = []
    i = 0
    while i + 4 <= len(data):
        opt, sub, ln = data[i], data[i + 1], struct.unpack("!H", data[i + 2:i + 4])[0]
        blocks.append((opt, sub, data[i + 4:i + 4 + ln]))
        i += 4 + ln + (ln & 1)
    return blocks


def handle_dcp(reg: Registry, nic: str, src: str, payload: bytes) -> None:
    if len(payload) < 12:
        return
    frame_id = struct.unpack("!H", payload[0:2])[0]
    service_id, service_type = payload[2], payload[3]
    # 0xFEFF Identify response, 0xFEFC Hello (thiết bị tự quảng bá)
    if not (frame_id == 0xFEFF or frame_id == 0xFEFC or (frame_id == 0xFEFD and service_type == 1)):
        return
    dlen = struct.unpack("!H", payload[10:12])[0]
    blocks = parse_dcp_blocks(payload[12:12 + dlen])
    reg.seen(nic, src)
    for opt, sub, val in blocks:
        body = val[2:]  # bỏ BlockInfo
        if opt == 1 and sub == 2 and len(body) >= 12:
            ip = socket.inet_ntoa(body[0:4])
            mask = socket.inet_ntoa(body[4:8])
            gw = socket.inet_ntoa(body[8:12])
            if ip != "0.0.0.0":
                reg.add_ip(nic, src, ip, "PROFINET DCP")
            reg.add_info(nic, src, "dcp_ip", f"{ip}/{mask} gw {gw}")
        elif opt == 2 and sub == 2:
            reg.add_name(nic, src, "PN:" + body.decode("ascii", "replace"))
            reg.add_info(nic, src, "pn_name_of_station", body.decode("ascii", "replace"))
        elif opt == 2 and sub == 1:
            reg.add_info(nic, src, "pn_type", body.decode("ascii", "replace").strip())
        elif opt == 2 and sub == 3 and len(body) >= 4:
            vid, did = struct.unpack("!HH", body[0:4])
            reg.add_info(nic, src, "pn_vendor_device_id", f"0x{vid:04X}/0x{did:04X}")
        elif opt == 1 and sub == 3 and len(body) >= 12:
            ip = socket.inet_ntoa(body[0:4])
            if ip != "0.0.0.0":
                reg.add_ip(nic, src, ip, "PROFINET DCP")
        elif opt == 1 and sub == 1 and len(val) >= 6:
            pass
    if frame_id == 0xFEFF and not any(o == 1 and s == 2 for o, s, _ in blocks):
        reg.add_info(nic, src, "dcp", "trả lời DCP (không kèm IP)")


def handle_lldp(reg: Registry, nic: str, src: str, payload: bytes) -> None:
    i = 0
    reg.seen(nic, src)
    while i + 2 <= len(payload):
        hdr = struct.unpack("!H", payload[i:i + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = payload[i + 2:i + 2 + ln]
        i += 2 + ln
        if t == 0:
            break
        if t == 5:
            reg.add_name(nic, src, "LLDP:" + v.decode("utf-8", "replace"))
        elif t == 6:
            reg.add_info(nic, src, "lldp_description", v.decode("utf-8", "replace")[:120])
        elif t == 2 and len(v) > 1:
            reg.add_info(nic, src, "lldp_port", v[1:].decode("utf-8", "replace")[:60])
        elif t == 8 and len(v) >= 6:
            alen, sub = v[0], v[1]
            if sub == 1 and alen == 5:
                reg.add_ip(nic, src, socket.inet_ntoa(v[2:6]), "LLDP")


def handle_enip(reg: Registry, nic: str, src: str, ip_src: str, data: bytes) -> None:
    # Encapsulation header 24 byte, command 0x0063 = ListIdentity
    if len(data) < 26:
        return
    cmd = struct.unpack("<H", data[0:2])[0]
    if cmd != 0x0063:
        return
    p = data[24:]
    count = struct.unpack("<H", p[0:2])[0]
    off = 2
    for _ in range(count):
        if off + 4 > len(p):
            break
        typ, ln = struct.unpack("<HH", p[off:off + 4])
        item = p[off + 4:off + 4 + ln]
        off += 4 + ln
        if typ != 0x000C or len(item) < 33:
            continue
        sin_addr = socket.inet_ntoa(item[6:10])  # sockaddr (big-endian) bắt đầu ở byte 2
        vendor_id, dev_type, prod_code = struct.unpack("<HHH", item[18:24])
        rev_major, rev_minor = item[24], item[25]
        serial = struct.unpack("<I", item[28:32])[0]
        nlen = item[32]
        name = item[33:33 + nlen].decode("ascii", "replace")
        reg.add_ip(nic, src, sin_addr if ip_valid_host(sin_addr) else ip_src, "EtherNet/IP")
        if ip_valid_host(ip_src):
            reg.add_ip(nic, src, ip_src, "EtherNet/IP")
        reg.add_name(nic, src, "EIP:" + name)
        reg.add_info(nic, src, "eip_identity",
                     f"vendor={vendor_id} type={dev_type} product={prod_code} "
                     f"rev={rev_major}.{rev_minor} serial=0x{serial:08X}")


def handle_bootp(reg: Registry, nic: str, src: str, data: bytes) -> None:
    if len(data) < 240 or data[0] != 1:
        return
    reg.set_dhcp(nic, src)
    ciaddr = socket.inet_ntoa(data[12:16])
    if ip_valid_host(ciaddr):
        reg.add_ip(nic, src, ciaddr, "DHCP ciaddr")
    if data[236:240] != b"\x63\x82\x53\x63":
        return
    i = 240
    while i < len(data):
        o = data[i]
        if o == 255:
            break
        if o == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        v = data[i + 2:i + 2 + ln]
        i += 2 + ln
        if o == 12:
            reg.add_name(nic, src, "DHCP:" + v.decode("ascii", "replace"))
        elif o == 60:
            reg.add_info(nic, src, "dhcp_vendor_class", v.decode("ascii", "replace"))
        elif o == 50 and ln == 4:
            reg.add_info(nic, src, "dhcp_requested_ip", socket.inet_ntoa(v))
            reg.add_probe(nic, src, socket.inet_ntoa(v))


class PacketHandler:
    def __init__(self, reg: Registry, nic: Nic):
        self.reg = reg
        self.nic = nic
        self.own = {nic.mac}

    def __call__(self, pkt) -> None:
        try:
            self._handle(pkt)
        except Exception:
            pass

    def _handle(self, pkt) -> None:
        raw = bytes(pkt)
        if len(raw) < 14:
            return
        src = bytes_mac(raw[6:12])
        if src in self.own or src == "00:00:00:00:00:00" or (raw[6] & 1):
            return
        etype = struct.unpack("!H", raw[12:14])[0]
        off = 14
        while etype in (ETH_VLAN, 0x88A8) and len(raw) >= off + 4:
            etype = struct.unpack("!H", raw[off + 2:off + 4])[0]
            off += 4
        payload = raw[off:]
        r, n = self.reg, self.nic.name
        if etype == ETH_ARP and len(payload) >= 28:
            op = struct.unpack("!H", payload[6:8])[0]
            shw = bytes_mac(payload[8:14])
            spa = socket.inet_ntoa(payload[14:18])
            tpa = socket.inet_ntoa(payload[24:28])
            if shw != src and shw not in self.own and shw != "00:00:00:00:00:00":
                src = shw  # dùng MAC trong ARP (trường hợp qua bridge)
            if spa == "0.0.0.0":
                if op == 1:
                    r.add_probe(n, src, tpa)
                return
            if op == 1 and spa == tpa:
                r.add_ip(n, src, spa, "Gratuitous ARP")
            elif op == 1:
                r.add_ip(n, src, spa, "ARP request")
                r.add_asked(n, src, tpa)
            elif op == 2:
                r.add_ip(n, src, spa, "ARP reply")
        elif etype == ETH_IPV4 and len(payload) >= 20:
            ihl = (payload[0] & 0x0F) * 4
            proto = payload[9]
            ip_src = socket.inet_ntoa(payload[12:16])
            l4 = payload[ihl:]
            if proto == 17 and len(l4) >= 8:
                sport, dport = struct.unpack("!HH", l4[0:4])
                udp_data = l4[8:]
                if sport == 68 and dport == 67:
                    handle_bootp(r, n, src, udp_data)
                    if ip_src != "0.0.0.0":
                        r.add_ip(n, src, ip_src, "IPv4")
                    return
                if sport == ENIP_PORT:
                    handle_enip(r, n, src, ip_src, udp_data)
            if ip_src != "0.0.0.0":
                r.add_ip(n, src, ip_src, "IPv4")
            else:
                r.seen(n, src)
        elif etype == ETH_PNIO:
            handle_dcp(r, n, src, payload)
        elif etype == ETH_LLDP:
            handle_lldp(r, n, src, payload)
        elif etype == ETH_IPV6:
            r.mark_ipv6(n, src)
        # Các loại khung khác: bỏ qua (không ghi nhận để tránh nhiễu)


# --------------------------------------------------------------------------------------
# Gửi gói dò chủ động
# --------------------------------------------------------------------------------------
class Prober:
    def __init__(self, nic: Nic, rate: int = 500):
        self.nic = nic
        self.rate = max(10, int(rate))
        self.sock = conf.L2socket(iface=nic.iface)
        self.mymac = mac_bytes(nic.mac)
        self.stop = threading.Event()

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass

    def _send(self, frame: bytes) -> None:
        if len(frame) < 60:
            frame = frame + b"\x00" * (60 - len(frame))
        self.sock.send(Raw(frame))

    def dcp_identify(self) -> None:
        xid = random.randint(1, 0xFFFFFFFF)
        # FrameID FEFE, Identify(5) Request(0), Xid, ResponseDelay=0x0080, len=4, block All/All
        pn = struct.pack("!HBBIHH", 0xFEFE, 5, 0, xid, 0x0080, 4) + b"\xff\xff\x00\x00"
        self._send(mac_bytes(DCP_MCAST) + self.mymac + struct.pack("!H", ETH_PNIO) + pn)

    def enip_list_identity(self) -> None:
        payload = struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"IPFINDER", 0)
        src = self.nic.first_ip or "0.0.0.0"
        pkt = (Ether(dst=BROADCAST, src=self.nic.mac) /
               IP(src=src, dst="255.255.255.255", ttl=64) /
               UDP(sport=random.randint(40000, 60000), dport=ENIP_PORT) / Raw(payload))
        self._send(bytes(pkt))
        # Thêm bản gửi tới broadcast của từng subnet trên NIC
        for net in self.nic.networks:
            pkt[IP].dst = str(net.broadcast_address)
            pkt[IP].src = src
            del pkt[IP].chksum
            del pkt[UDP].chksum
            self._send(bytes(pkt))

    def icmp_broadcast(self) -> None:
        src = self.nic.first_ip or "0.0.0.0"
        pkt = (Ether(dst=BROADCAST, src=self.nic.mac) /
               IP(src=src, dst="255.255.255.255") / ICMP(id=0x1F1F, seq=1) / Raw(b"ipfinder"))
        self._send(bytes(pkt))

    def arp_sweep(self, targets: List[str], src_mode: str = "own", label: str = "") -> None:
        own = {ip for ip, _ in self.nic.ipv4}
        sources: List[str] = []
        if src_mode in ("own", "both"):
            sources.append(self.nic.first_ip or "0.0.0.0")
        if src_mode in ("probe", "both") or not sources:
            sources.append("0.0.0.0")
        sources = list(dict.fromkeys(sources))
        hdr = mac_bytes(BROADCAST) + self.mymac + struct.pack("!H", ETH_ARP)
        total = len(targets) * len(sources)
        if total == 0:
            return
        print(f"[{self.nic.name}] Quét ARP {len(targets)} IP{label} "
              f"(IP nguồn: {', '.join(sources)}), ~{total / self.rate:.0f}s ...", flush=True)
        interval = 1.0 / self.rate
        t_next = time.perf_counter()
        sent = 0
        last_report = time.time()
        for src_ip in sources:
            spa = socket.inet_aton(src_ip)
            for t in targets:
                if self.stop.is_set():
                    return
                if t in own:
                    continue
                arp = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 1) + self.mymac + spa + b"\x00" * 6 + socket.inet_aton(t)
                self._send(hdr + arp)
                sent += 1
                t_next += interval
                d = t_next - time.perf_counter()
                if d > 0:
                    time.sleep(d)
                elif d < -1:
                    t_next = time.perf_counter()
                if time.time() - last_report > 10:
                    last_report = time.time()
                    print(f"[{self.nic.name}]   ... đã gửi {sent}/{total}", flush=True)

    def arp_probe_one(self, ip: str, src_ip: str = "0.0.0.0") -> None:
        hdr = mac_bytes(BROADCAST) + self.mymac + struct.pack("!H", ETH_ARP)
        arp = struct.pack("!HHBBH", 1, ETH_IPV4, 6, 4, 1) + self.mymac + socket.inet_aton(src_ip) + b"\x00" * 6 + socket.inet_aton(ip)
        self._send(hdr + arp)


# --------------------------------------------------------------------------------------
# Lệnh: find
# --------------------------------------------------------------------------------------
def start_sniffer(nic: Nic, reg: Registry) -> AsyncSniffer:
    handler = PacketHandler(reg, nic)
    sn = AsyncSniffer(iface=nic.iface, prn=handler, store=False, promisc=True)
    sn.start()
    time.sleep(0.5)
    return sn


def build_targets(args) -> List[str]:
    nets = list(PRESETS[args.preset]) + list(args.range or [])
    targets = hosts_of(parse_ranges(nets))
    if args.limit and len(targets) > args.limit:
        die(f"dải quét có {len(targets)} IP, vượt giới hạn --limit {args.limit}. Tăng --limit nếu chắc chắn.")
    return targets


def active_round(prober: Prober, args, targets: List[str], first: bool) -> None:
    if not args.no_dcp:
        prober.dcp_identify()
    if not args.no_enip:
        prober.enip_list_identity()
    if not args.no_icmp:
        prober.icmp_broadcast()
    if first and not args.no_arp:
        # Quét subnet của chính NIC trước (để thấy cả thiết bị đang chạy bình thường)
        own_targets: List[str] = []
        if not args.no_own_subnet:
            own_targets = hosts_of([n for n in prober.nic.networks if n.prefixlen >= 22])
        if own_targets:
            prober.arp_sweep(own_targets, "own", " trong subnet của NIC")
        own_set = set(own_targets)
        prober.arp_sweep([t for t in targets if t not in own_set], args.arp_src, " (dải mặc định/tự chọn)")
        if not prober.stop.is_set():
            print(f"[{prober.nic.name}] Quét ARP xong, tiếp tục nghe...", flush=True)


def classify(dev: Device, nic: Optional[Nic]) -> str:
    if not dev.ips:
        if dev.dhcp:
            return "DHCP - CHƯA CÓ IP"
        if dev.probes:
            return "ĐANG KHỞI ĐỘNG"
        return "CHƯA THẤY IPv4"
    if nic is None:
        return ""
    if any(ipaddress.IPv4Address(ip) in net for ip in dev.ips for net in nic.networks):
        return "cùng subnet"
    return "KHÁC SUBNET"


def print_results(reg: Registry, nics: List[Nic], baseline: Optional[Set[str]] = None) -> List[Device]:
    devs = reg.list()
    by_name = {n.name: n for n in nics}
    print()
    print("=" * 100)
    print(f"KẾT QUẢ: {len(devs)} thiết bị")
    print("=" * 100)
    if not devs:
        print("Không thấy thiết bị nào. Kiểm tra: cáp/đèn link, đúng card mạng, chạy quyền Admin, Npcap.")
        return devs
    hdr = f"{'NIC':<12} {'MAC':<17} {'IP':<34} {'TRẠNG THÁI':<18} HÃNG / TÊN"
    print(hdr)
    print("-" * 100)
    order = {"KHÁC SUBNET": 0, "DHCP - CHƯA CÓ IP": 1, "ĐANG KHỞI ĐỘNG": 2, "cùng subnet": 3}
    devs.sort(key=lambda d: (order.get(classify(d, by_name.get(d.nic)), 4), d.nic, d.mac))
    for d in devs:
        st = classify(d, by_name.get(d.nic))
        ips = ", ".join(d.best_ips()) or (("thử " + ", ".join(sorted(d.probes))) if d.probes else "-")
        new = ""
        if baseline is not None and d.mac not in baseline:
            new = " [MỚI]"
        name = " | ".join(sorted(d.names))
        extra = d.vendor + ((" | " + name) if name else "")
        print(f"{d.nic[:12]:<12} {d.mac:<17} {ips[:34]:<34} {st:<18} {extra}{new}")
        if len(ips) > 34:
            print(f"{'':<31}{ips}")
        if d.asked and st == "KHÁC SUBNET":
            print(f"{'':<31}-> thiết bị đang tìm IP: {', '.join(sorted(d.asked)[:5])} (thường là gateway/máy chủ)")
        for k in ("dcp_ip", "eip_identity", "pn_type", "dhcp_vendor_class"):
            if k in d.info:
                print(f"{'':<31}{k}: {d.info[k]}")
    print("-" * 100)
    others = [d for d in devs if classify(d, by_name.get(d.nic)) == "KHÁC SUBNET"]
    if others:
        print("Thiết bị KHÁC SUBNET (thường là thiết bị cần tìm). Để truy cập web/tool cấu hình của nó:")
        for d in others:
            ip = d.best_ips()[0]
            print(f"   ipfinder access --iface \"{d.nic}\" --ip {ip}")
            if "PROFINET DCP" in d.ips.get(ip, set()) or "dcp_ip" in d.info:
                print(f"   (hoặc đổi IP trực tiếp) ipfinder dcp-setip --iface \"{d.nic}\" --mac {d.mac} "
                      f"--ip <IP_MỚI> --mask 255.255.255.0")
    if any(d.dhcp and not d.ips for d in devs):
        print("Thiết bị ở chế độ DHCP chưa có IP: cần một DHCP/BOOTP server trên NIC đó "
              "(VD tool BOOTP của hãng, hoặc Tftpd64/dnsmasq) để cấp IP cho nó.")
    return devs


def cmd_find(args) -> int:
    nics = get_nics()
    if not nics:
        die("không thấy card mạng nào (Windows: đã cài Npcap chưa?).")
    if not args.iface:
        print_nics(nics)
        die("hãy chọn card bằng --iface <tên hoặc số> (hoặc --iface all).")
    sel: List[Nic] = []
    for key in args.iface:
        if key.lower() == "all":
            sel = nics
            break
        sel.append(find_nic(nics, key))
    sel = list({n.name: n for n in sel}.values())

    baseline: Optional[Set[str]] = None
    if args.diff:
        try:
            with open(args.diff, encoding="utf-8") as f:
                baseline = {d["mac"] for d in json.load(f)["devices"]}
        except Exception as e:
            die(f"không đọc được file baseline '{args.diff}': {e}")

    targets = [] if (args.passive or args.no_arp) else build_targets(args)
    reg = Registry(verbose=not args.quiet, mac_filter=args.mac)
    print(f"IP Finder {__version__} - dò trong {args.time}s trên: " + ", ".join(n.name for n in sel))
    for n in sel:
        print("  " + n.label())
    print(">>> MẸO: trong lúc dò hãy TẮT/BẬT NGUỒN hoặc RÚT/CẮM LẠI CÁP thiết bị cần tìm.")
    print(">>> Nhấn Ctrl+C để dừng sớm.\n")

    sniffers = []
    for n in sel:
        try:
            sniffers.append(start_sniffer(n, reg))
        except Exception as e:
            print(f"[{n.name}] Không mở được card để nghe: {e}")
    if not sniffers:
        die("không nghe được trên card nào. Chạy bằng quyền Administrator/root, Windows cần Npcap.")

    probers: List[Prober] = []
    threads: List[threading.Thread] = []
    stop_all = threading.Event()

    def active_loop(p: Prober) -> None:
        first = True
        while not stop_all.is_set():
            try:
                active_round(p, args, targets, first)
            except Exception as e:
                print(f"[{p.nic.name}] lỗi khi gửi gói dò: {e}")
                return
            first = False
            stop_all.wait(args.interval)

    if not args.passive:
        for n in sel:
            try:
                p = Prober(n, args.rate)
            except Exception as e:
                print(f"[{n.name}] Không gửi được gói trên card này: {e}")
                continue
            probers.append(p)
            th = threading.Thread(target=active_loop, args=(p,), daemon=True)
            th.start()
            threads.append(th)

    t_end = time.time() + args.time
    try:
        while time.time() < t_end:
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nĐã dừng theo yêu cầu.")
    stop_all.set()
    for p in probers:
        p.stop.set()
    time.sleep(1.0)  # chờ trả lời muộn
    for s in sniffers:
        try:
            s.stop()
        except Exception:
            pass
    for p in probers:
        p.close()

    devs = print_results(reg, nics, baseline)
    data = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "nics": [n.label() for n in sel],
            "devices": [d.to_dict() for d in devs]}
    if args.save:
        with open(args.save, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Đã lưu danh sách (baseline) vào {args.save}")
    if args.out:
        if args.out.lower().endswith(".csv"):
            with open(args.out, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["nic", "mac", "vendor", "ips", "status", "names", "dhcp", "info"])
                by_name = {n.name: n for n in nics}
                for d in devs:
                    w.writerow([d.nic, d.mac, d.vendor, " ".join(d.best_ips()), classify(d, by_name.get(d.nic)),
                                " | ".join(sorted(d.names)), d.dhcp, json.dumps(d.info, ensure_ascii=False)])
        else:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"Đã xuất kết quả ra {args.out}")
    return 0 if devs else 3


# --------------------------------------------------------------------------------------
# Lệnh: access - thêm IP phụ tạm thời để vào được thiết bị
# --------------------------------------------------------------------------------------
def arp_check_used(nic: Nic, ips: List[str], wait: float = 1.5) -> Set[str]:
    """Trả về tập IP đang có máy dùng (có trả lời ARP probe)."""
    reg = Registry(verbose=False)
    sn = start_sniffer(nic, reg)
    p = Prober(nic, 200)
    try:
        for _ in range(2):
            for ip in ips:
                p.arp_probe_one(ip, "0.0.0.0")
            time.sleep(wait / 2)
    finally:
        time.sleep(0.3)
        sn.stop()
        p.close()
    used: Set[str] = set()
    for d in reg.list():
        used.update(d.ips)
    return used & set(ips)


def run_cmd(cmd: List[str]) -> int:
    print("  > " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError as e:
        print(f"    lỗi: {e}")
        return 1
    out = (r.stdout or "") + (r.stderr or "")
    if out.strip():
        print("    " + out.strip().replace("\n", "\n    "))
    return r.returncode


def nic_os_name(nic: Nic) -> str:
    return nic.name


def cmd_access(args) -> int:
    nics = get_nics()
    nic = find_nic(nics, args.iface)
    dev_ip = ipaddress.IPv4Address(args.ip)
    net = ipaddress.IPv4Network(f"{dev_ip}/{args.prefix}", strict=False)
    mask = str(net.netmask)
    osname = nic_os_name(nic)

    if args.remove:
        ip = args.remove
        print(f"Gỡ IP phụ {ip} khỏi card '{osname}':")
        cmds = ([["netsh", "interface", "ipv4", "delete", "address", f"name={osname}", f"address={ip}"]]
                if IS_WINDOWS else [["ip", "addr", "del", f"{ip}/{args.prefix}", "dev", osname]])
        return max(run_cmd(c) for c in cmds) if args.apply else (print_cmds(cmds) or 0)

    if any(dev_ip in n for n in nic.networks):
        print(f"IP {dev_ip} đã cùng subnet với card '{osname}' -> truy cập trực tiếp được, không cần thêm IP.")
        return 0

    conflict = []
    for other in nics:
        for onet in other.networks:
            if onet.overlaps(net):
                conflict.append(f"'{other.name}' ({onet})")
    if conflict:
        print("CẢNH BÁO: subnet " + str(net) + " TRÙNG với: " + ", ".join(conflict))
        print("  Thêm IP này có thể làm Windows/Linux định tuyến SAI và mất kết nối với thiết bị khác!")
        print("  Cách an toàn: rút cáp NIC kia tạm thời, hoặc dùng prefix nhỏ hơn (VD --prefix 30 / 29).")
        if args.apply and not args.force:
            die("đã dừng. Thêm --force nếu bạn hiểu rủi ro.")

    # Chọn IP trống trong subnet của thiết bị
    if args.my_ip:
        cands = [args.my_ip]
    else:
        hosts = [str(h) for h in net.hosts()] if net.prefixlen < 31 else [str(h) for h in net]
        prefer = [h for h in reversed(hosts) if h != str(dev_ip)][:8]
        cands = prefer
    print(f"Kiểm tra IP trống trên card '{osname}' (ARP probe): {', '.join(cands)} ...")
    try:
        used = arp_check_used(nic, cands)
    except Exception as e:
        print(f"  (không kiểm tra được: {e})")
        used = set()
    free = [c for c in cands if c not in used and c != str(dev_ip)]
    if used:
        print("  Đang có thiết bị dùng: " + ", ".join(sorted(used)))
    if not free:
        die("không tìm được IP trống. Dùng --my-ip để chỉ định.")
    my_ip = free[0]

    if IS_WINDOWS:
        add = [["netsh", "interface", "ipv4", "add", "address", f"name={osname}", f"address={my_ip}", f"mask={mask}"]]
        rem = [["netsh", "interface", "ipv4", "delete", "address", f"name={osname}", f"address={my_ip}"]]
    else:
        add = [["ip", "addr", "add", f"{my_ip}/{net.prefixlen}", "dev", osname]]
        rem = [["ip", "addr", "del", f"{my_ip}/{net.prefixlen}", "dev", osname]]

    print(f"\nThêm IP phụ {my_ip}/{net.prefixlen} lên card '{osname}' để truy cập thiết bị {dev_ip}.")
    print("IP chính và các kết nối hiện tại của card KHÔNG bị thay đổi.")
    if IS_WINDOWS:
        print("Lưu ý Windows: nếu card đang để DHCP (Obtain IP automatically) thì netsh sẽ báo lỗi;"
              " khi đó cần đặt IP tĩnh cho card trước.")
    if args.apply:
        if not is_admin():
            die("cần quyền Administrator/root để thêm IP.")
        rc = max(run_cmd(c) for c in add)
        if rc != 0:
            die("thêm IP thất bại (xem thông báo ở trên).")
        print(f"\nXONG. Mở trình duyệt / tool của hãng tới: {dev_ip}")
        print("Sau khi đổi IP thiết bị xong, gỡ IP phụ bằng:")
        print(f"   ipfinder access --iface \"{osname}\" --ip {dev_ip} --prefix {net.prefixlen} --remove {my_ip} --apply")
        time.sleep(2 if IS_WINDOWS else 0.5)  # chờ hệ điều hành áp dụng IP
        try:
            ok = str(dev_ip) in arp_check_used(nic, [str(dev_ip)])
            print(f"Kiểm tra: thiết bị {dev_ip} " + ("TRẢ LỜI ARP -> đã truy cập được." if ok else
                  "chưa trả lời ARP (có thể thiết bị chặn/đang khởi động; thử mở web/tool hãng)."))
        except Exception:
            pass
        if args.ping:
            run_cmd(["ping", "-n" if IS_WINDOWS else "-c", "3", str(dev_ip)])
    else:
        print("\nLệnh thêm (chạy với quyền Admin, hoặc thêm --apply để tool tự chạy):")
        print_cmds(add)
        print("Lệnh gỡ sau khi xong:")
        print_cmds(rem)
    return 0


def print_cmds(cmds: List[List[str]]) -> None:
    for c in cmds:
        print("   " + " ".join(f'"{x}"' if " " in x else x for x in c))


# --------------------------------------------------------------------------------------
# Lệnh: PROFINET DCP set IP / blink
# --------------------------------------------------------------------------------------
def dcp_request(nic: Nic, dst_mac: str, service_id: int, blocks: bytes, wait: float = 2.0) -> Optional[List[Tuple[int, int, bytes]]]:
    xid = random.randint(1, 0xFFFFFFFF)
    pn = struct.pack("!HBBIHH", 0xFEFD, service_id, 0, xid, 0, len(blocks)) + blocks
    frame = mac_bytes(dst_mac) + mac_bytes(nic.mac) + struct.pack("!H", ETH_PNIO) + pn
    result: List[List[Tuple[int, int, bytes]]] = []
    dst = mac_norm(dst_mac)

    def on_pkt(pkt):
        raw = bytes(pkt)
        if len(raw) < 26 or bytes_mac(raw[6:12]) != dst:
            return
        off = 14
        et = struct.unpack("!H", raw[12:14])[0]
        if et == ETH_VLAN:
            et = struct.unpack("!H", raw[16:18])[0]
            off = 18
        if et != ETH_PNIO:
            return
        p = raw[off:]
        fid, sid, styp, rx = struct.unpack("!HBBI", p[0:8])
        if fid == 0xFEFD and sid == service_id and styp in (1, 5) and rx == xid:
            dlen = struct.unpack("!H", p[10:12])[0]
            result.append(parse_dcp_blocks(p[12:12 + dlen]))

    sn = AsyncSniffer(iface=nic.iface, prn=on_pkt, store=False)
    sn.start()
    time.sleep(0.4)
    s = conf.L2socket(iface=nic.iface)
    try:
        s.send(Raw(frame + b"\x00" * max(0, 60 - len(frame))))
        t_end = time.time() + wait
        while time.time() < t_end and not result:
            time.sleep(0.05)
    finally:
        s.close()
        sn.stop()
    return result[0] if result else None


def dcp_result_ok(blocks: Optional[List[Tuple[int, int, bytes]]]) -> Tuple[bool, str]:
    if blocks is None:
        return False, "thiết bị không trả lời (có thể không hỗ trợ PROFINET DCP, hoặc sai MAC/card)"
    for opt, sub, val in blocks:
        if opt == 5 and sub == 4 and len(val) >= 3:
            err = val[2]
            names = {0: "OK", 1: "Option không hỗ trợ", 2: "Suboption không hỗ trợ / không có",
                     3: "Suboption chưa set được", 4: "Lỗi tài nguyên", 5: "Không thể set (thiết bị đang chạy / bị khoá)",
                     6: "Không được phép (đang kết nối với PLC?)"}
            return err == 0, names.get(err, f"mã lỗi {err}")
    return True, "OK (không có mã phản hồi)"


def cmd_dcp_setip(args) -> int:
    nics = get_nics()
    nic = find_nic(nics, args.iface)
    mac = mac_norm(args.mac)
    ip = str(ipaddress.IPv4Address(args.ip))
    mask = str(ipaddress.IPv4Address(args.mask))
    gw = str(ipaddress.IPv4Address(args.gw)) if args.gw else "0.0.0.0"
    perm = not args.temp
    print(f"Đổi IP thiết bị PROFINET MAC {mac} trên card '{nic.name}' -> {ip} / {mask} gw {gw} "
          f"({'lưu vĩnh viễn' if perm else 'tạm thời, mất khi tắt nguồn'})")
    print("CẢNH BÁO: chỉ làm khi thiết bị KHÔNG đang chạy sản xuất / không kết nối PLC.")
    if not args.yes:
        ans = input(f"Gõ lại MAC ({mac}) để xác nhận: ").strip()
        if mac_norm(ans) != mac:
            print("Huỷ.")
            return 1
    qual = 0x0001 if perm else 0x0000
    body = struct.pack("!H", qual) + socket.inet_aton(ip) + socket.inet_aton(mask) + socket.inet_aton(gw)
    blocks = struct.pack("!BBH", 1, 2, len(body)) + body
    ok, msg = dcp_result_ok(dcp_request(nic, mac, 4, blocks))
    print(("THÀNH CÔNG: " if ok else "THẤT BẠI: ") + msg)
    if ok:
        print("Chạy lại 'ipfinder find' để xác nhận IP mới.")
    return 0 if ok else 1


def cmd_dcp_blink(args) -> int:
    nics = get_nics()
    nic = find_nic(nics, args.iface)
    mac = mac_norm(args.mac)
    body = struct.pack("!HH", 0, 0x0100)
    blocks = struct.pack("!BBH", 5, 3, len(body)) + body
    ok, msg = dcp_result_ok(dcp_request(nic, mac, 4, blocks))
    print(("Đã gửi lệnh nháy đèn: " if ok else "THẤT BẠI: ") + msg)
    return 0 if ok else 1


def cmd_ifaces(_args) -> int:
    nics = get_nics()
    if not nics:
        die("không thấy card mạng nào (Windows: đã cài Npcap chưa?).")
    print_nics(nics)
    return 0


# --------------------------------------------------------------------------------------
# Chế độ hỏi-đáp (khi chạy không tham số, VD double-click file .exe)
# --------------------------------------------------------------------------------------
def wizard() -> int:
    print(f"=== IP Finder {__version__} - dò IP thiết bị công nghiệp ===")
    if not is_admin():
        print("! Nên chạy bằng quyền Administrator (chuột phải > Run as administrator).")
    nics = get_nics()
    if not nics:
        die("không thấy card mạng nào (Windows: đã cài Npcap chưa? https://npcap.com)")
    print_nics(nics)
    valid = {str(n.index) for n in nics} | {n.name.lower() for n in nics}
    while True:
        key = input("\nNhập SỐ card đang cắm thiết bị cần tìm (Enter = tất cả): ").strip() or "all"
        if key.lower() == "all" or key.lower() in valid:
            break
        print(f"  Không có card '{key}'. Nhập số trong ngoặc [ ] ở danh sách trên.")
    t = input("Thời gian dò (giây, Enter = 60): ").strip()
    preset = input("Dải quét ARP: [1] nhanh (mặc định)  [2] toàn bộ 192.168.x.x  [3] rộng  [4] không quét: ").strip()
    preset = {"2": "192", "3": "wide", "4": "none"}.get(preset, "quick")
    extra = input("Dải IP thêm (VD 192.168.7.0/24, Enter = bỏ qua): ").strip()
    argv = ["find", "--iface", key, "--time", t if t.isdigit() else "60", "--preset", preset]
    if extra:
        argv += ["--range", extra]
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        pass
    input("\nNhấn Enter để thoát...")
    return 0


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ipfinder",
        description="Dò IP thiết bị công nghiệp (mã vạch, RFID, camera, PLC...) không cần biết subnet.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ví dụ:\n"
            "  ipfinder ifaces\n"
            "  ipfinder find --iface 12 --time 60\n"
            "  ipfinder find --iface \"Ethernet 2\" --preset 192 --range 10.20.0.0/16\n"
            "  ipfinder find --iface all --passive --time 120\n"
            "  ipfinder find --iface 12 --mac 00:d0:24          (chỉ hiện MAC bắt đầu bằng ...)\n"
            "  ipfinder access --iface 12 --ip 192.168.100.100 --apply\n"
            "  ipfinder dcp-setip --iface 12 --mac 00:1b:1b:aa:bb:cc --ip 10.0.0.50 --mask 255.255.255.0\n"
        ),
    )
    p.add_argument("--version", action="version", version=__version__)
    sp = p.add_subparsers(dest="cmd")

    s = sp.add_parser("ifaces", help="liệt kê card mạng")
    s.set_defaults(func=cmd_ifaces)

    s = sp.add_parser("find", help="dò thiết bị (nghe thụ động + hỏi chủ động)")
    s.add_argument("--iface", "-i", action="append", help="card mạng (tên/số/MAC). Lặp lại nhiều lần, hoặc 'all'")
    s.add_argument("--time", "-t", type=int, default=60, help="thời gian dò, giây (mặc định 60)")
    s.add_argument("--passive", action="store_true", help="chỉ nghe, không gửi gói nào")
    s.add_argument("--preset", choices=sorted(PRESETS), default="quick",
                   help="dải quét ARP: quick (mặc định), 192 (192.168.0.0/16), wide, none")
    s.add_argument("--range", "-r", action="append",
                   help="dải IP quét ARP thêm: CIDR, a.b.c.d-e.f.g.h, a.b.c.d-N (lặp lại được)")
    s.add_argument("--arp-src", choices=["own", "probe", "both"], default="both",
                   help="IP nguồn khi quét ARP: both (mặc định) = gửi cả IP của NIC lẫn 0.0.0.0; "
                        "own = chỉ IP của NIC; probe = chỉ 0.0.0.0. Thiết bị Linux có rp_filter "
                        "bỏ qua ARP từ subnet lạ nhưng vẫn trả lời ARP probe 0.0.0.0")
    s.add_argument("--rate", type=int, default=500, help="số gói/giây tối đa (mặc định 500)")
    s.add_argument("--limit", type=int, default=500000, help="giới hạn số IP quét ARP")
    s.add_argument("--interval", type=float, default=10.0, help="chu kỳ lặp lại DCP/EtherNet-IP/ICMP (giây)")
    s.add_argument("--no-arp", action="store_true", help="không quét ARP")
    s.add_argument("--no-own-subnet", action="store_true", help="không quét ARP subnet hiện tại của NIC")
    s.add_argument("--no-dcp", action="store_true", help="không gửi PROFINET DCP")
    s.add_argument("--no-enip", action="store_true", help="không gửi EtherNet/IP ListIdentity")
    s.add_argument("--no-icmp", action="store_true", help="không gửi ping broadcast")
    s.add_argument("--mac", action="append", help="chỉ hiện thiết bị có MAC bắt đầu bằng ... (lặp lại được)")
    s.add_argument("--save", help="lưu kết quả làm baseline (JSON)")
    s.add_argument("--diff", help="so với baseline: đánh dấu [MỚI] thiết bị chưa có trong file")
    s.add_argument("--out", help="xuất kết quả ra file .json hoặc .csv")
    s.add_argument("--quiet", "-q", action="store_true", help="không in sự kiện trong lúc dò")
    s.set_defaults(func=cmd_find)

    s = sp.add_parser("access", help="thêm IP phụ tạm thời lên NIC để vào được thiết bị khác subnet")
    s.add_argument("--iface", "-i", required=True)
    s.add_argument("--ip", required=True, help="IP thiết bị tìm được")
    s.add_argument("--prefix", type=int, default=24, help="độ dài subnet, mặc định 24 (255.255.255.0)")
    s.add_argument("--my-ip", help="IP muốn gán cho PC (mặc định tự chọn IP trống cuối dải)")
    s.add_argument("--apply", action="store_true", help="thực thi lệnh (mặc định chỉ in lệnh)")
    s.add_argument("--remove", metavar="MY_IP", help="gỡ IP phụ đã thêm")
    s.add_argument("--force", action="store_true", help="vẫn thêm dù trùng subnet NIC khác")
    s.add_argument("--ping", action="store_true", help="ping thử thiết bị sau khi thêm")
    s.set_defaults(func=cmd_access)

    s = sp.add_parser("dcp-setip", help="đổi IP thiết bị PROFINET qua DCP (không cần cùng subnet)")
    s.add_argument("--iface", "-i", required=True)
    s.add_argument("--mac", required=True)
    s.add_argument("--ip", required=True)
    s.add_argument("--mask", default="255.255.255.0")
    s.add_argument("--gw", default=None)
    s.add_argument("--temp", action="store_true", help="chỉ đổi tạm (mất khi tắt nguồn)")
    s.add_argument("--yes", "-y", action="store_true", help="không hỏi xác nhận")
    s.set_defaults(func=cmd_dcp_setip)

    s = sp.add_parser("dcp-blink", help="nháy đèn thiết bị PROFINET để nhận diện")
    s.add_argument("--iface", "-i", required=True)
    s.add_argument("--mac", required=True)
    s.set_defaults(func=cmd_dcp_blink)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return wizard()
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        build_parser().print_help()
        return 0
    if args.cmd in ("find", "dcp-setip", "dcp-blink") and not is_admin():
        print("! Cảnh báo: không chạy bằng quyền Administrator/root, có thể không nghe/gửi được gói.")
    try:
        return int(args.func(args) or 0)
    except PermissionError:
        die("không đủ quyền. Chạy bằng Administrator (Windows) hoặc sudo (Linux).")
    except OSError as e:
        if IS_WINDOWS and ("Npcap" in str(e) or "winpcap" in str(e).lower() or "pcap" in str(e).lower()):
            die(f"{e}\nCần cài Npcap: https://npcap.com")
        raise
    return 0


if __name__ == "__main__":
    sys.exit(main())
