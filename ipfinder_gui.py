#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Finder - giao diện đồ hoạ (Tkinter).

Dùng chung lõi với ipfinder.py. Chạy bằng quyền Administrator. Windows cần Npcap.
"""

from __future__ import annotations

import ipaddress
import os
import queue
import sys
import threading
import time
import traceback
import webbrowser

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk

import ipfinder as core

APP_TITLE = f"IP Finder {core.__version__} – Dò IP thiết bị công nghiệp"

PRESETS = [
    ("quick", "Nhanh – các dải IP mặc định phổ biến (~7.000 IP, ~30 giây)"),
    ("192", "Toàn bộ 192.168.x.x (~65.000 IP, ~4–5 phút)"),
    ("wide", "Rộng – 192.168 / 10.x / 172.16 / 169.254 (~26 phút)"),
    ("none", "Không quét ARP (chỉ nghe + PROFINET/EtherNet-IP)"),
]

STATUS_TAGS = {
    "KHÁC SUBNET": "other",
    "DHCP - CHƯA CÓ IP": "dhcp",
    "ĐANG KHỞI ĐỘNG": "dhcp",
    "CHƯA THẤY IPv4": "noip",
    "cùng subnet": "same",
}
STATUS_ORDER = {"KHÁC SUBNET": 0, "DHCP - CHƯA CÓ IP": 1, "ĐANG KHỞI ĐỘNG": 2, "cùng subnet": 3, "CHƯA THẤY IPv4": 4}

NPCAP_HELP = (
    "Chưa cài Npcap – thư viện bắt gói tin mà IP Finder cần để dò thiết bị.\n\n"
    "Cách cài KHÔNG cần Internet trên máy này:\n"
    "  1. Trên máy có Internet, tải npcap-x.yz.exe tại https://npcap.com\n"
    "     (hoặc dùng bộ cài Wireshark – đã kèm sẵn Npcap).\n"
    "  2. Chép qua USB, chạy file đó (tick 'WinPcap API-compatible Mode').\n"
    "  3. Mở lại IP Finder.\n\n"
    "Mẹo: đặt file npcap-x.yz.exe cùng thư mục với bộ cài IP Finder,\n"
    "bộ cài sẽ tự cài Npcap luôn."
)


def resource(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for cand in (os.path.join(base, name), os.path.join(base, "installer", name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(base, name)


def enable_dpi_awareness() -> None:
    if not core.IS_WINDOWS:
        return
    try:
        import ctypes

        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # Windows 8.1+
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()  # Windows 7
    except Exception:
        pass


class DcpDialog(simpledialog.Dialog):
    """Hộp thoại nhập IP mới cho thiết bị PROFINET."""

    def __init__(self, parent, mac: str, cur_ip: str = ""):
        self.mac = mac
        self.cur_ip = cur_ip
        self.result = None
        super().__init__(parent, title="Đổi IP thiết bị PROFINET")

    def body(self, master):
        ttk.Label(master, text=f"Thiết bị MAC: {self.mac}").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        if self.cur_ip:
            ttk.Label(master, text=f"IP hiện tại: {self.cur_ip}").grid(row=1, column=0, columnspan=2, sticky="w")
        self.v_ip = tk.StringVar(value=self.cur_ip)
        self.v_mask = tk.StringVar(value="255.255.255.0")
        self.v_gw = tk.StringVar(value="0.0.0.0")
        self.v_perm = tk.BooleanVar(value=True)
        for r, (lbl, var) in enumerate((("IP mới:", self.v_ip), ("Subnet mask:", self.v_mask), ("Gateway:", self.v_gw)), 2):
            ttk.Label(master, text=lbl).grid(row=r, column=0, sticky="e", padx=4, pady=2)
            e = ttk.Entry(master, textvariable=var, width=22)
            e.grid(row=r, column=1, sticky="w", pady=2)
            if r == 2:
                first = e
        ttk.Checkbutton(master, text="Lưu vĩnh viễn (bỏ chọn = tạm thời, mất khi tắt nguồn)",
                        variable=self.v_perm).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(master, text="Chỉ làm khi thiết bị KHÔNG đang chạy sản xuất / không kết nối PLC.",
                  foreground="#b00020").grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 0))
        return first

    def validate(self):
        try:
            ip = str(ipaddress.IPv4Address(self.v_ip.get().strip()))
            mask = str(ipaddress.IPv4Address(self.v_mask.get().strip()))
            ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            gw = str(ipaddress.IPv4Address(self.v_gw.get().strip() or "0.0.0.0"))
        except ValueError as e:
            messagebox.showerror("Sai định dạng", f"IP / mask / gateway không hợp lệ:\n{e}", parent=self)
            return False
        self.result = (ip, mask, gw, self.v_perm.get())
        return True


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: "queue.Queue" = queue.Queue()
        core.set_logger(lambda m: self.q.put(("log", m)))
        self.nics = []
        self.reg = None
        self.scanner = None
        self.scan_nics = []
        self.state = "idle"  # idle | starting | running | stopping
        self.t_start = 0.0
        self.t_end = 0.0
        self.iids = {}  # (nic, mac) -> iid
        self.added_ips = []  # (Nic, my_ip, prefix)
        self.busy = 0

        root.title(APP_TITLE)
        if core.IS_WINDOWS:
            try:
                root.iconbitmap(resource("ipfinder.ico"))
            except Exception:
                pass
        root.geometry("1180x780")
        root.minsize(900, 600)
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self.poll)
        self.refresh_nics()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        r = self.root
        style = ttk.Style(r)
        try:
            if core.IS_WINDOWS:
                style.theme_use("vista")
        except Exception:
            pass
        if not core.IS_WINDOWS:
            # Linux: dùng font có đủ dấu tiếng Việt
            from tkinter import font as tkfont
            if "DejaVu Sans" in tkfont.families(r):
                for nm in ("TkDefaultFont", "TkTextFont", "TkHeadingFont", "TkMenuFont"):
                    tkfont.nametofont(nm).configure(family="DejaVu Sans", size=9)
                tkfont.nametofont("TkFixedFont").configure(family="DejaVu Sans Mono", size=9)
        style.configure("Big.TButton", padding=(14, 6))
        style.configure("Treeview", rowheight=24)

        main = ttk.Frame(r, padding=8)
        main.pack(fill="both", expand=True)

        # 1. NIC
        f1 = ttk.LabelFrame(main, text=" 1. Chọn card mạng đang cắm thiết bị (giữ Ctrl để chọn nhiều card) ", padding=6)
        f1.pack(fill="x")
        self.nic_tree = ttk.Treeview(f1, columns=("idx", "name", "ip", "mac", "desc"), show="headings",
                                     height=4, selectmode="extended")
        for col, txt, w in (("idx", "Số", 50), ("name", "Card", 170), ("ip", "IP / subnet hiện tại", 260),
                            ("mac", "MAC", 140), ("desc", "Mô tả", 420)):
            self.nic_tree.heading(col, text=txt)
            self.nic_tree.column(col, width=w, stretch=(col == "desc"), anchor="w")
        self.nic_tree.pack(side="left", fill="x", expand=True)
        ttk.Button(f1, text="Làm mới", command=self.refresh_nics).pack(side="left", padx=(6, 0), anchor="n")

        # 2. Options
        f2 = ttk.LabelFrame(main, text=" 2. Tuỳ chọn ", padding=6)
        f2.pack(fill="x", pady=(6, 0))
        self.v_time = tk.StringVar(value="60")
        self.v_preset = tk.StringVar(value=PRESETS[0][1])
        self.v_range = tk.StringVar()
        self.v_mac = tk.StringVar()
        self.v_passive = tk.BooleanVar(value=False)
        ttk.Label(f2, text="Thời gian dò (giây):").grid(row=0, column=0, sticky="e")
        ttk.Spinbox(f2, from_=10, to=3600, increment=10, textvariable=self.v_time, width=7).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(f2, text="Dải quét ARP:").grid(row=0, column=2, sticky="e", padx=(16, 0))
        ttk.Combobox(f2, textvariable=self.v_preset, values=[p[1] for p in PRESETS], state="readonly",
                     width=58).grid(row=0, column=3, sticky="w", padx=4)
        ttk.Label(f2, text="Dải IP thêm:").grid(row=1, column=0, sticky="e", pady=(4, 0))
        ttk.Entry(f2, textvariable=self.v_range, width=34).grid(row=1, column=1, columnspan=2, sticky="w", padx=4, pady=(4, 0))
        ttk.Label(f2, text="VD: 192.168.7.0/24, 10.0.0.1-50", foreground="#666").grid(row=1, column=3, sticky="w", padx=4)
        ttk.Label(f2, text="Lọc MAC:").grid(row=2, column=0, sticky="e", pady=(4, 0))
        ttk.Entry(f2, textvariable=self.v_mac, width=20).grid(row=2, column=1, columnspan=2, sticky="w", padx=4, pady=(4, 0))
        ttk.Label(f2, text="(phần đầu MAC in trên tem thiết bị, để trống = tất cả)", foreground="#666").grid(row=2, column=3, sticky="w", padx=4)
        ttk.Checkbutton(f2, text="Chỉ nghe – không gửi gói nào (an toàn tuyệt đối cho mạng đang sản xuất)",
                        variable=self.v_passive).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        # Run controls
        f3 = ttk.Frame(main, padding=(0, 8, 0, 4))
        f3.pack(fill="x")
        self.btn_start = ttk.Button(f3, text="▶  Bắt đầu dò", style="Big.TButton", command=self.start_scan)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(f3, text="■  Dừng", style="Big.TButton", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(f3, mode="determinate", length=240, maximum=1000)
        self.progress.pack(side="left", padx=6)
        self.lbl_status = ttk.Label(f3, text="Sẵn sàng.")
        self.lbl_status.pack(side="left", padx=6)
        tip = ttk.Label(main, foreground="#0b5394",
                        text="MẸO: trong lúc dò, hãy TẮT/BẬT NGUỒN hoặc RÚT/CẮM LẠI CÁP thiết bị cần tìm – "
                             "thiết bị sẽ tự báo IP dù ở lớp mạng nào.")
        tip.pack(fill="x")

        # 3. Results + log
        pw = ttk.PanedWindow(main, orient="vertical")
        pw.pack(fill="both", expand=True, pady=(6, 0))
        f4 = ttk.LabelFrame(pw, text=" 3. Kết quả (dòng màu cam = KHÁC SUBNET, thường là thiết bị cần tìm; nhấp đúp để mở web) ", padding=6)
        cols = (("nic", "Card", 110), ("mac", "MAC", 135), ("ip", "IP", 150), ("status", "Trạng thái", 130),
                ("vendor", "Hãng", 170), ("name", "Tên thiết bị", 220), ("via", "Phát hiện qua", 220))
        tf = ttk.Frame(f4)
        tf.pack(fill="both", expand=True)
        self.res = ttk.Treeview(tf, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for col, txt, w in cols:
            self.res.heading(col, text=txt)
            self.res.column(col, width=w, anchor="w", stretch=col in ("name", "via"))
        vs = ttk.Scrollbar(tf, orient="vertical", command=self.res.yview)
        self.res.configure(yscrollcommand=vs.set)
        self.res.pack(side="left", fill="both", expand=True)
        vs.pack(side="left", fill="y")
        self.res.tag_configure("other", background="#ffe0b2")
        self.res.tag_configure("dhcp", background="#d6eaff")
        self.res.tag_configure("noip", foreground="#777")
        self.res.bind("<Double-1>", lambda e: self.open_web())
        self.res.bind("<Button-3>", self._popup)

        fb = ttk.Frame(f4, padding=(0, 6, 0, 0))
        fb.pack(fill="x")
        self.dev_buttons = []
        for txt, cmd in (("Truy cập (thêm IP phụ)…", self.access), ("Mở web", self.open_web), ("Copy IP", self.copy_ip),
                         ("Đổi IP (PROFINET)…", self.dcp_setip), ("Nháy đèn (PROFINET)", self.dcp_blink)):
            b = ttk.Button(fb, text=txt, command=cmd)
            b.pack(side="left", padx=(0, 4))
            self.dev_buttons.append(b)
        ttk.Button(fb, text="Xuất CSV…", command=self.export).pack(side="right")
        self.btn_remove = ttk.Button(fb, text="Gỡ IP phụ đã thêm", command=self.remove_added, state="disabled")
        self.btn_remove.pack(side="right", padx=4)
        pw.add(f4, weight=4)

        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Truy cập (thêm IP phụ)…", command=self.access)
        self.menu.add_command(label="Mở web", command=self.open_web)
        self.menu.add_command(label="Copy IP", command=self.copy_ip)
        self.menu.add_command(label="Copy MAC", command=self.copy_mac)
        self.menu.add_separator()
        self.menu.add_command(label="Đổi IP (PROFINET)…", command=self.dcp_setip)
        self.menu.add_command(label="Nháy đèn (PROFINET)", command=self.dcp_blink)

        f5 = ttk.LabelFrame(pw, text=" Nhật ký ", padding=4)
        self.log_txt = scrolledtext.ScrolledText(f5, height=8, font=("Consolas", 9) if core.IS_WINDOWS else None)
        self.log_txt.pack(fill="both", expand=True)
        self.log_txt.configure(state="disabled")
        pw.add(f5, weight=1)

    # ------------------------------------------------------------------ helpers
    def log(self, msg: str) -> None:
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", msg + "\n")
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")

    def run_bg(self, fn, on_done=None) -> None:
        """Chạy fn ở luồng nền; on_done(result, error) được gọi lại trên luồng giao diện."""
        self.busy += 1
        self.root.configure(cursor="watch")

        def worker():
            res, err = None, None
            try:
                res = fn()
            except core.IPFinderError as e:
                err = str(e)
            except Exception as e:  # pragma: no cover
                err = f"{type(e).__name__}: {e}"
                self.q.put(("log", traceback.format_exc()))
            self.q.put(("done", on_done, res, err))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self) -> None:
        try:
            while True:
                item = self.q.get_nowait()
                if item[0] == "log":
                    self.log(item[1])
                elif item[0] == "done":
                    _, cb, res, err = item
                    self.busy -= 1
                    if self.busy <= 0:
                        self.busy = 0
                        self.root.configure(cursor="")
                    if cb:
                        cb(res, err)
                    elif err:
                        messagebox.showerror("Lỗi", err)
        except queue.Empty:
            pass
        self.refresh_results()
        if self.state == "running":
            now = time.time()
            total = max(1.0, self.t_end - self.t_start)
            self.progress["value"] = min(1000, (now - self.t_start) / total * 1000)
            n = len(self.reg.devs) if self.reg else 0
            self.lbl_status.configure(text=f"Đang dò… còn {max(0, int(self.t_end - now))} giây – đã thấy {n} thiết bị")
            if now >= self.t_end:
                self.stop_scan()
        self.root.after(250, self.poll)

    def nic_by_name(self, name: str):
        for n in self.nics:
            if n.name == name:
                return n
        return None

    # ------------------------------------------------------------------ NIC
    def refresh_nics(self) -> None:
        def done(res, err):
            if err:
                messagebox.showerror("Lỗi", f"Không đọc được danh sách card mạng:\n{err}")
                return
            self.nics = res or []
            sel = {self.nic_tree.item(i, "values")[1] for i in self.nic_tree.selection()}
            self.nic_tree.delete(*self.nic_tree.get_children())
            for n in self.nics:
                ips = ", ".join(f"{ip}/{p}" for ip, p in n.ipv4) or "(chưa có IPv4)"
                iid = self.nic_tree.insert("", "end", values=(n.index, n.name, ips, n.mac, n.description))
                if n.name in sel:
                    self.nic_tree.selection_add(iid)
            if len(self.nics) == 1:
                self.nic_tree.selection_set(self.nic_tree.get_children()[0])
            self.log(f"Tìm thấy {len(self.nics)} card mạng.")
            for w in self._overlap_warnings():
                self.log("! " + w)

        self.run_bg(core.get_nics, done)

    def _overlap_warnings(self):
        out, seen = [], []
        for n in self.nics:
            for net in n.networks:
                for onet, oname in seen:
                    if net.overlaps(onet) and oname != n.name:
                        out.append(f"CẢNH BÁO: subnet {net} của '{n.name}' trùng với {onet} của '{oname}'")
                seen.append((net, n.name))
        return out

    # ------------------------------------------------------------------ scan
    def set_state(self, st: str) -> None:
        self.state = st
        self.btn_start.configure(state="normal" if st == "idle" else "disabled")
        self.btn_stop.configure(state="normal" if st == "running" else "disabled")
        if st == "idle":
            self.progress["value"] = 0

    def start_scan(self) -> None:
        if self.state != "idle":
            return
        names = [self.nic_tree.item(i, "values")[1] for i in self.nic_tree.selection()]
        if not names:
            messagebox.showwarning("Chưa chọn card", "Hãy chọn card mạng đang cắm thiết bị cần tìm (bảng số 1).")
            return
        argv = ["find"]
        for nm in names:
            argv += ["--iface", nm]
        t = self.v_time.get().strip()
        argv += ["--time", t if t.isdigit() and int(t) > 0 else "60"]
        key = next((k for k, lbl in PRESETS if lbl == self.v_preset.get()), "quick")
        argv += ["--preset", key]
        if self.v_range.get().strip():
            argv += ["--range", self.v_range.get().strip()]
        if self.v_mac.get().strip():
            argv += ["--mac", self.v_mac.get().strip()]
        if self.v_passive.get():
            argv += ["--passive"]
        try:
            args = core.build_parser().parse_args(argv)
            sel = [self.nic_by_name(nm) for nm in names]
            sel = [n for n in sel if n is not None]
            reg = core.Registry(verbose=True, mac_filter=args.mac)
            scanner = core.Scanner(sel, args, reg)
        except core.IPFinderError as e:
            messagebox.showerror("Lỗi", str(e))
            return
        except SystemExit:
            messagebox.showerror("Lỗi", "Tuỳ chọn không hợp lệ.")
            return
        est = scanner.estimate_arp_seconds()
        if est + 5 > args.time:
            new_t = int(est) + 15
            self.log(f"Quét ARP cần khoảng {est:.0f} giây nên tự kéo dài thời gian dò lên {new_t} giây.")
            args.time = new_t
            self.v_time.set(str(new_t))
        self.reg, self.scanner, self.scan_nics = reg, scanner, sel
        self.res.delete(*self.res.get_children())
        self.iids.clear()
        self.set_state("starting")
        self.lbl_status.configure(text="Đang khởi động…")
        self.log(f"=== Bắt đầu dò {args.time}s trên: {', '.join(names)} ===")

        def done(_res, err):
            if err:
                self.set_state("idle")
                self.lbl_status.configure(text="Lỗi.")
                messagebox.showerror("Không dò được", err)
                return
            self.t_start = time.time()
            self.t_end = self.t_start + args.time
            self.set_state("running")

        self.run_bg(scanner.start, done)

    def stop_scan(self) -> None:
        if self.state != "running" or not self.scanner:
            return
        self.set_state("stopping")
        self.lbl_status.configure(text="Đang dừng…")

        def done(_res, err):
            self.set_state("idle")
            devs = self.reg.list() if self.reg else []
            other = sum(1 for d in devs if self.status_of(d) == "KHÁC SUBNET")
            self.lbl_status.configure(text=f"Xong: {len(devs)} thiết bị, {other} thiết bị KHÁC SUBNET.")
            self.log(f"=== Xong: {len(devs)} thiết bị ===")
            if not devs:
                messagebox.showinfo("Không thấy thiết bị",
                                    "Không thấy thiết bị nào.\n\nKiểm tra: đèn link trên card/thiết bị, đúng card mạng, "
                                    "và thử dò lại trong lúc TẮT/BẬT NGUỒN thiết bị.")

        self.run_bg(self.scanner.stop, done)

    # ------------------------------------------------------------------ results
    def status_of(self, d) -> str:
        return core.classify(d, self.nic_by_name(d.nic))

    def refresh_results(self) -> None:
        if not self.reg:
            return
        devs = self.reg.list()
        devs.sort(key=lambda d: (STATUS_ORDER.get(self.status_of(d), 9), d.nic, d.mac))
        for pos, d in enumerate(devs):
            st = self.status_of(d)
            ips = ", ".join(d.best_ips()) or (("thử " + ", ".join(sorted(d.probes))) if d.probes else "-")
            via = set()
            for src in d.ips.values():
                via |= src
            if d.dhcp:
                via.add("DHCP")
            vals = (d.nic, d.mac, ips, st, d.vendor, " | ".join(sorted(d.names)), ", ".join(sorted(via)))
            key = (d.nic, d.mac)
            iid = self.iids.get(key)
            tag = (STATUS_TAGS.get(st, ""),)
            if iid is None:
                iid = self.res.insert("", pos, values=vals, tags=tag)
                self.iids[key] = iid
            else:
                if tuple(self.res.item(iid, "values")) != tuple(str(v) for v in vals):
                    self.res.item(iid, values=vals, tags=tag)
                if self.res.index(iid) != pos:
                    self.res.move(iid, "", pos)

    def selected_device(self, need_ip: bool = True):
        sel = self.res.selection()
        if not sel or not self.reg:
            messagebox.showinfo("Chọn thiết bị", "Hãy chọn một thiết bị trong bảng kết quả.")
            return None
        key = next((k for k, v in self.iids.items() if v == sel[0]), None)
        d = self.reg.devs.get(key) if key else None
        if d is None:
            return None
        if need_ip and not d.ips:
            messagebox.showinfo("Chưa có IP", "Thiết bị này chưa có IPv4. Hãy dò lại trong lúc tắt/bật nguồn thiết bị.")
            return None
        return d

    def _popup(self, ev) -> None:
        iid = self.res.identify_row(ev.y)
        if iid:
            self.res.selection_set(iid)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def copy_ip(self) -> None:
        d = self.selected_device()
        if d:
            self.root.clipboard_clear()
            self.root.clipboard_append(d.best_ips()[0])

    def copy_mac(self) -> None:
        d = self.selected_device(need_ip=False)
        if d:
            self.root.clipboard_clear()
            self.root.clipboard_append(d.mac)

    def open_web(self) -> None:
        d = self.selected_device()
        if not d:
            return
        nic = self.nic_by_name(d.nic)
        ip = d.best_ips()[0]
        if nic and self.status_of(d) == "KHÁC SUBNET" and not any(
                ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{a}/{p}", strict=False)
                for n in self.nics for a, p in n.ipv4):
            if not messagebox.askyesno("Khác subnet", f"Thiết bị {ip} khác subnet nên trình duyệt chưa vào được.\n\n"
                                                      "Bấm 'Truy cập (thêm IP phụ)' trước. Vẫn mở trình duyệt?"):
                return
        webbrowser.open(f"http://{ip}")

    def export(self) -> None:
        if not self.reg:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("JSON", "*.json")],
                                            initialfile=time.strftime("ipfinder_%Y%m%d_%H%M.csv"))
        if path:
            try:
                core.export_results(self.reg.list(), self.nics, path)
                self.log(f"Đã xuất: {path}")
            except Exception as e:
                messagebox.showerror("Lỗi", str(e))

    # ------------------------------------------------------------------ access
    def access(self) -> None:
        d = self.selected_device()
        if not d:
            return
        nic = self.nic_by_name(d.nic)
        if nic is None:
            return
        ip = d.best_ips()[0]
        mask = simpledialog.askstring("Subnet mask", f"Subnet mask của thiết bị {ip}\n(không rõ thì giữ 255.255.255.0):",
                                      initialvalue="255.255.255.0", parent=self.root)
        if not mask:
            return
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask.strip()}").prefixlen
        except ValueError:
            messagebox.showerror("Sai mask", f"Subnet mask không hợp lệ: {mask}")
            return

        def planned(plan, err):
            if err:
                messagebox.showerror("Lỗi", err)
                return
            if plan.my_ip is None:
                if messagebox.askyesno("Đã cùng subnet", f"{ip} đã cùng subnet với card '{nic.name}'. Mở trình duyệt?"):
                    webbrowser.open(f"http://{ip}")
                return
            msg = (f"Thêm IP phụ {plan.my_ip}/{plan.net.prefixlen} lên card '{nic.name}'\n"
                   f"để truy cập thiết bị {ip}.\n\nIP chính và các kết nối hiện tại của card KHÔNG thay đổi.")
            if plan.conflicts:
                msg += ("\n\n⚠ CẢNH BÁO: subnet " + str(plan.net) + " TRÙNG với " + ", ".join(plan.conflicts) +
                        ".\nThêm IP có thể làm mất kết nối với thiết bị trên card đó!\n"
                        "Nên rút tạm cáp card kia, hoặc dùng mask 255.255.255.252.")
                if not messagebox.askyesno("Cảnh báo trùng subnet", msg + "\n\nVẫn tiếp tục?", icon="warning", default="no"):
                    return
            elif not messagebox.askyesno("Truy cập thiết bị", msg + "\n\nTiếp tục?"):
                return

            def applied(res, err2):
                ok, out = res if res else (False, err2 or "")
                if not ok:
                    hint = ("\n\nWindows chỉ cho thêm IP phụ khi card đặt IP TĨNH. Nếu card đang để DHCP "
                            "(Obtain an IP address automatically), hãy đặt IP tĩnh cho card trước.") if core.IS_WINDOWS else ""
                    messagebox.showerror("Thêm IP thất bại", (out or err2 or "Lỗi không rõ") + hint)
                    return
                self.added_ips.append((nic, plan.my_ip, plan.net.prefixlen))
                self.btn_remove.configure(state="normal")
                self.log(f"Đã thêm IP phụ {plan.my_ip}/{plan.net.prefixlen} lên '{nic.name}'. Đang kiểm tra thiết bị…")

                def verified(ok2, _e):
                    if ok2:
                        if messagebox.askyesno("Đã truy cập được",
                                               f"Thiết bị {ip} đã trả lời.\n\nMở trình duyệt tới http://{ip} ?\n"
                                               "(hoặc dùng phần mềm cấu hình của hãng)\n\n"
                                               "Đổi IP thiết bị xong nhớ bấm 'Gỡ IP phụ đã thêm'."):
                            webbrowser.open(f"http://{ip}")
                    else:
                        messagebox.showwarning("Chưa thấy trả lời",
                                               f"Đã thêm IP nhưng thiết bị {ip} chưa trả lời ARP.\n"
                                               "Có thể thiết bị đang khởi động hoặc mask khác. Thử mở web/tool hãng.")

                self.run_bg(lambda: core.verify_device(nic, ip), verified)

            self.run_bg(lambda: core.apply_cmds(plan.add), applied)

        self.log(f"Chuẩn bị truy cập {ip} qua card '{nic.name}'…")
        self.run_bg(lambda: core.plan_access(self.nics, nic, ip, prefix), planned)

    def remove_added(self, silent: bool = False) -> None:
        items = list(self.added_ips)
        if not items:
            return

        def work():
            fails = []
            for nic, my_ip, prefix in items:
                _, rem = core.access_cmds(nic, my_ip, prefix)
                ok, out = core.apply_cmds(rem)
                if not ok:
                    fails.append(f"{my_ip}: {out}")
            return fails

        def done(fails, err):
            self.added_ips = [x for x in self.added_ips if x not in items]
            self.btn_remove.configure(state="normal" if self.added_ips else "disabled")
            if (fails or err) and not silent:
                messagebox.showwarning("Gỡ IP", "Một số IP chưa gỡ được:\n" + "\n".join(fails or [err]))
            elif not silent:
                self.log("Đã gỡ các IP phụ.")
            self.refresh_nics()

        self.run_bg(work, done)

    # ------------------------------------------------------------------ PROFINET
    def dcp_setip(self) -> None:
        d = self.selected_device(need_ip=False)
        if not d:
            return
        nic = self.nic_by_name(d.nic)
        dlg = DcpDialog(self.root, d.mac, d.best_ips()[0] if d.ips else "")
        if not dlg.result:
            return
        ip, mask, gw, perm = dlg.result
        if not messagebox.askyesno("Xác nhận", f"Đổi IP thiết bị {d.mac}\nthành {ip} / {mask}, gateway {gw}\n"
                                                f"({'lưu vĩnh viễn' if perm else 'tạm thời'}) ?", icon="warning"):
            return

        def done(res, err):
            ok, msg = res if res else (False, err)
            if ok:
                messagebox.showinfo("Thành công", f"Đã đổi IP thành {ip}.\nBấm 'Bắt đầu dò' lại để xác nhận.")
            else:
                messagebox.showerror("Thất bại", msg or "Lỗi không rõ")
            self.log(f"Đổi IP PROFINET {d.mac} -> {ip}: {msg}")

        self.run_bg(lambda: core.dcp_set_ip(nic, d.mac, ip, mask, gw, perm), done)

    def dcp_blink(self) -> None:
        d = self.selected_device(need_ip=False)
        if not d:
            return
        nic = self.nic_by_name(d.nic)

        def done(res, err):
            ok, msg = res if res else (False, err)
            (messagebox.showinfo if ok else messagebox.showerror)("Nháy đèn", ("Đã gửi lệnh nháy đèn: " if ok else "") + (msg or ""))

        self.run_bg(lambda: core.dcp_blink(nic, d.mac), done)

    # ------------------------------------------------------------------ close
    def on_close(self) -> None:
        if self.added_ips:
            ans = messagebox.askyesnocancel("Thoát", "Gỡ các IP phụ đã thêm lên card mạng trước khi thoát?\n"
                                                    "(Yes = gỡ, No = giữ lại, Cancel = không thoát)")
            if ans is None:
                return
            if ans:
                for nic, my_ip, prefix in self.added_ips:
                    _, rem = core.access_cmds(nic, my_ip, prefix)
                    core.apply_cmds(rem)
        if self.scanner and self.state in ("running", "starting"):
            try:
                self.scanner.stop_all.set()
            except Exception:
                pass
        self.root.destroy()


def selftest(out_path: str) -> int:
    """Kiểm tra bản đóng gói: dựng giao diện, chạy vài hàm lõi, rồi thoát (dùng trong CI)."""
    lines = []
    try:
        root = tk.Tk()
        root.withdraw()
        app = App(root)
        lines.append("ui ok")
        lines.append("vendor 00:d0:24 = " + core.vendor_of("00:d0:24:00:00:01"))
        lines.append("hosts quick = %d" % len(core.hosts_of(core.parse_ranges(core.PRESETS["quick"]))))
        lines.append("npcap = %s" % core.npcap_installed())
        app.on_close()
        lines.append("OK")
        rc = 0
    except Exception:
        lines.append(traceback.format_exc())
        rc = 1
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return rc


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        return selftest(sys.argv[2])
    enable_dpi_awareness()
    root = tk.Tk()
    App(root)
    if not core.npcap_installed():
        root.after(300, lambda: messagebox.showerror("Thiếu Npcap", NPCAP_HELP))
    elif not core.is_admin():
        root.after(300, lambda: messagebox.showwarning(
            "Cần quyền Administrator", "IP Finder cần chạy bằng quyền Administrator để bắt/gửi gói tin.\n"
                                       "Đóng chương trình, chuột phải > Run as administrator."))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
