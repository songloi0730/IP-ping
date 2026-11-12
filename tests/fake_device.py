#!/usr/bin/env python3
"""
Thiết bị giả lập để kiểm thử ipfinder (chạy trong Linux network namespace).

Trả lời: PROFINET DCP Identify / Set IP / Signal, EtherNet/IP ListIdentity (trả lời
ở tầng L2 về đúng MAC người hỏi), và gửi gratuitous ARP khi khởi động.
ARP thường do kernel Linux tự trả lời.

Ví dụ:
  ip netns exec dev2 python3 tests/fake_device.py --iface v2d --ip 172.31.77.9 --name rfid-02
"""
import argparse
import socket
import struct
import subprocess
import sys
import time

from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import sniff

conf.verb = 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--ip", required=True)
    ap.add_argument("--mask", default="255.255.255.0")
    ap.add_argument("--name", default="fake-device")
    ap.add_argument("--no-dcp", action="store_true")
    ap.add_argument("--no-enip", action="store_true")
    ap.add_argument("--garp-delay", type=float, default=0.0,
                    help="gửi gratuitous ARP sau N giây (giả lập bật nguồn)")
    a = ap.parse_args()

    state = {"ip": a.ip, "mask": a.mask, "gw": "0.0.0.0"}
    with open(f"/sys/class/net/{a.iface}/address") as f:
        mymac = f.read().strip()
    sock = conf.L2socket(iface=a.iface)

    def garp():
        sock.send(Ether(dst="ff:ff:ff:ff:ff:ff", src=mymac) /
                  ARP(op=1, hwsrc=mymac, psrc=state["ip"], hwdst="00:00:00:00:00:00", pdst=state["ip"]))

    if a.garp_delay:
        time.sleep(a.garp_delay)
        garp()

    def dcp_blocks():
        ipb = struct.pack("!H", 1) + socket.inet_aton(state["ip"]) + socket.inet_aton(state["mask"]) + socket.inet_aton(state["gw"])
        nos = struct.pack("!H", 0) + a.name.encode()
        typ = struct.pack("!H", 0) + b"FAKE RFID"
        did = struct.pack("!HHH", 0, 0x002A, 0x0101)
        out = b""
        for opt, sub, body in ((1, 2, ipb), (2, 2, nos), (2, 1, typ), (2, 3, did)):
            out += struct.pack("!BBH", opt, sub, len(body)) + body
            if len(body) & 1:
                out += b"\x00"
        return out

    def on_pkt(p):
        raw = bytes(p)
        if len(raw) < 14 or raw[6:12] == bytes.fromhex(mymac.replace(":", "")):
            return
        src = ":".join("%02x" % b for b in raw[6:12])
        et = struct.unpack("!H", raw[12:14])[0]
        if et == 0x8892 and not a.no_dcp:
            pn = raw[14:]
            fid, sid, styp, xid = struct.unpack("!HBBI", pn[0:8])
            if fid == 0xFEFE and sid == 5 and styp == 0:
                blocks = dcp_blocks()
                hdr = struct.pack("!HBBIHH", 0xFEFF, 5, 1, xid, 0, len(blocks))
                sock.send(Raw(bytes.fromhex(src.replace(":", "")) + bytes.fromhex(mymac.replace(":", "")) +
                              b"\x88\x92" + hdr + blocks))
            elif fid == 0xFEFD and sid == 4 and styp == 0:
                dlen = struct.unpack("!H", pn[10:12])[0]
                data = pn[12:12 + dlen]
                opt, sub = data[0], data[1]
                err = 0
                if opt == 1 and sub == 2:
                    body = data[4:]
                    new_ip = socket.inet_ntoa(body[2:6])
                    new_mask = socket.inet_ntoa(body[6:10])
                    prefix = bin(struct.unpack("!I", body[6:10])[0]).count("1")
                    old = state["ip"]
                    subprocess.run(["ip", "addr", "flush", "dev", a.iface])
                    subprocess.run(["ip", "addr", "add", f"{new_ip}/{prefix}", "dev", a.iface])
                    state.update(ip=new_ip, mask=new_mask, gw=socket.inet_ntoa(body[10:14]))
                    print(f"[fake] DCP set IP {old} -> {new_ip}/{new_mask}", flush=True)
                elif opt == 5 and sub == 3:
                    print("[fake] DCP blink!", flush=True)
                else:
                    err = 1
                resp = struct.pack("!BBHBBB", 5, 4, 3, opt, sub, err) + b"\x00"
                hdr = struct.pack("!HBBIHH", 0xFEFD, 4, 1, xid, 0, len(resp))
                sock.send(Raw(bytes.fromhex(src.replace(":", "")) + bytes.fromhex(mymac.replace(":", "")) +
                              b"\x88\x92" + hdr + resp))
        elif et == 0x0800 and not a.no_enip and p.haslayer(UDP) and p[UDP].dport == 44818:
            data = bytes(p[UDP].payload)
            if len(data) >= 24 and struct.unpack("<H", data[0:2])[0] == 0x0063:
                name = a.name.encode()
                item = (struct.pack("<H", 1) +
                        struct.pack("!HH4s8s", 2, 44818, socket.inet_aton(state["ip"]), b"\x00" * 8) +
                        struct.pack("<HHHBBHI", 1234, 12, 77, 3, 5, 0, 0xCAFE01) +
                        bytes([len(name)]) + name + b"\x03")
                cpf = struct.pack("<HHH", 1, 0x000C, len(item)) + item
                enc = struct.pack("<HHII8sI", 0x0063, len(cpf), 0, 0, data[12:20], 0) + cpf
                sock.send(Ether(dst=src, src=mymac) / IP(src=state["ip"], dst=p[IP].src) /
                          UDP(sport=44818, dport=p[UDP].sport) / Raw(enc))

    print(f"[fake] {a.name} MAC {mymac} IP {a.ip} trên {a.iface}", flush=True)
    sniff(iface=a.iface, prn=on_pkt, store=False)


if __name__ == "__main__":
    sys.exit(main())
