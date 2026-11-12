#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP Finder - giao diện đồ hoạ (Tkinter), 3 ngôn ngữ: Tiếng Việt / English / 中文.

Dùng chung lõi với ipfinder.py. Chạy bằng quyền Administrator. Windows cần Npcap.
"""

from __future__ import annotations

import configparser
import ipaddress
import json
import os
import queue
import sys
import threading
import time
import traceback
import webbrowser

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from tkinter import font as tkfont

import i18n
import ipfinder as core
from i18n import t

PRESET_KEYS = ["quick", "192", "wide", "none"]
STATUS_TAGS = {"other": "other", "dhcp": "dhcp", "booting": "dhcp", "noip": "noip", "same": "same"}

# Font ưu tiên theo ngôn ngữ (lấy font đầu tiên có trên máy)
FONTS = {
    "zh": ["Microsoft YaHei UI", "Microsoft YaHei", "SimSun", "Noto Sans CJK SC", "WenQuanYi Zen Hei"],
    "default_win": ["Segoe UI", "Tahoma"],
    "default_other": ["DejaVu Sans", "Noto Sans", "Liberation Sans"],
    "mono": ["Consolas", "DejaVu Sans Mono", "Noto Sans Mono", "Courier New"],
}


# ---------------------------------------------------------------------------- tiện ích
def resource(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    for cand in (os.path.join(base, name), os.path.join(base, "installer", name)):
        if os.path.exists(cand):
            return cand
    return os.path.join(base, name)


def app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def settings_path() -> str:
    if core.IS_WINDOWS:
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "IPFinder", "settings.json")
    return os.path.join(os.path.expanduser("~"), ".config", "ipfinder", "settings.json")


def load_settings() -> dict:
    try:
        with open(settings_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(data: dict) -> None:
    try:
        os.makedirs(os.path.dirname(settings_path()), exist_ok=True)
        with open(settings_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def initial_lang() -> str:
    """Thứ tự: lựa chọn đã lưu -> ngôn ngữ chọn lúc cài (ipfinder.ini) -> ngôn ngữ Windows."""
    lang = load_settings().get("lang")
    if lang in i18n.T_ALL_CODES:
        return lang
    try:
        cp = configparser.ConfigParser()
        cp.read(os.path.join(app_dir(), "ipfinder.ini"), encoding="utf-8")
        lang = cp.get("ui", "lang", fallback="")
        if lang in i18n.T_ALL_CODES:
            return lang
    except Exception:
        pass
    return i18n.detect_lang()


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


# ---------------------------------------------------------------------------- hộp thoại PROFINET
class DcpDialog(simpledialog.Dialog):
    def __init__(self, parent, mac: str, cur_ip: str = ""):
        self.mac = mac
        self.cur_ip = cur_ip
        self.result = None
        super().__init__(parent, title=t("dcp_title"))

    def body(self, master):
        ttk.Label(master, text=t("dcp_mac", mac=self.mac)).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        if self.cur_ip:
            ttk.Label(master, text=t("dcp_cur", ip=self.cur_ip)).grid(row=1, column=0, columnspan=2, sticky="w")
        self.v_ip = tk.StringVar(value=self.cur_ip)
        self.v_mask = tk.StringVar(value="255.255.255.0")
        self.v_gw = tk.StringVar(value="0.0.0.0")
        self.v_perm = tk.BooleanVar(value=True)
        first = None
        for r, (key, var) in enumerate((("dcp_new_ip", self.v_ip), ("dcp_mask", self.v_mask), ("dcp_gw", self.v_gw)), 2):
            ttk.Label(master, text=t(key)).grid(row=r, column=0, sticky="e", padx=4, pady=2)
            e = ttk.Entry(master, textvariable=var, width=22)
            e.grid(row=r, column=1, sticky="w", pady=2)
            first = first or e
        ttk.Checkbutton(master, text=t("dcp_perm"), variable=self.v_perm).grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(master, text=t("dcp_warn"), foreground="#b00020").grid(row=6, column=0, columnspan=2, sticky="w", pady=(6, 0))
        return first

    def validate(self):
        try:
            ip = str(ipaddress.IPv4Address(self.v_ip.get().strip()))
            mask = str(ipaddress.IPv4Address(self.v_mask.get().strip()))
            ipaddress.IPv4Network(f"0.0.0.0/{mask}")
            gw = str(ipaddress.IPv4Address(self.v_gw.get().strip() or "0.0.0.0"))
        except ValueError as e:
            messagebox.showerror(t("dcp_bad_title"), t("dcp_bad", err=e), parent=self)
            return False
        self.result = (ip, mask, gw, self.v_perm.get())
        return True


# ---------------------------------------------------------------------------- cửa sổ chính
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: "queue.Queue" = queue.Queue()
        core.set_logger(lambda m: self.q.put(("log", m)))
        self.nics = []
        self.reg = None
        self.scanner = None
        self.state = "idle"  # idle | starting | running | stopping
        self.t_start = 0.0
        self.t_end = 0.0
        self.iids = {}  # (nic, mac) -> iid
        self.added_ips = []  # (Nic, my_ip, prefix)
        self.busy = 0
        self.status_msg = ("ready", {})
        self.main = None

        # biến giữ nguyên khi đổi ngôn ngữ
        self.v_time = tk.StringVar(value="60")
        self.preset_idx = 0
        self.v_range = tk.StringVar()
        self.v_mac = tk.StringVar()
        self.v_passive = tk.BooleanVar(value=False)

        root.geometry("1180x800")
        root.minsize(900, 600)
        if core.IS_WINDOWS:
            try:
                root.iconbitmap(resource("ipfinder.ico"))
            except Exception:
                pass
        self.style = ttk.Style(root)
        try:
            if core.IS_WINDOWS:
                self.style.theme_use("vista")
        except Exception:
            pass
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        root.after(150, self.poll)
        self.refresh_nics()

    # ------------------------------------------------------------------ font / ngôn ngữ
    def _pick(self, names):
        fams = set(tkfont.families(self.root))
        return next((n for n in names if n in fams), None)

    def _apply_fonts(self) -> None:
        if i18n.get_lang() == "zh":
            fam = self._pick(FONTS["zh"])
        else:
            fam = self._pick(FONTS["default_win"] if core.IS_WINDOWS else FONTS["default_other"])
        size = 9
        for nm in ("TkDefaultFont", "TkTextFont", "TkHeadingFont", "TkMenuFont", "TkCaptionFont", "TkSmallCaptionFont"):
            try:
                f = tkfont.nametofont(nm)
                if fam:
                    f.configure(family=fam)
                f.configure(size=size)
            except tk.TclError:
                pass
        mono = self._pick(FONTS["mono"])
        try:
            if mono:
                tkfont.nametofont("TkFixedFont").configure(family=mono, size=size)
        except tk.TclError:
            pass
        self.style.configure("Treeview", rowheight=26 if i18n.get_lang() == "zh" else 24)
        self.style.configure("Big.TButton", padding=(14, 6))

    def change_lang(self, code: str) -> None:
        if code == i18n.get_lang():
            return
        i18n.set_lang(code)
        s = load_settings()
        s["lang"] = code
        save_settings(s)
        log_text = self.log_txt.get("1.0", "end-1c")
        self.preset_idx = max(0, self.cb_preset.current())
        self._build()
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", log_text + ("\n" if log_text else ""))
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")
        self._fill_nics()
        self.set_state(self.state)
        self._set_status(*self.status_msg)
        self.btn_remove.configure(state="normal" if self.added_ips else "disabled")

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        if self.main is not None:
            self.main.destroy()
        self.iids = {}
        self._apply_fonts()
        r = self.root
        r.title(t("app_title", ver=core.__version__))
        main = self.main = ttk.Frame(r, padding=8)
        main.pack(fill="both", expand=True)

        # thanh ngôn ngữ
        top = ttk.Frame(main)
        top.pack(fill="x")
        names = [n for _, n in i18n.LANGS]
        self.cb_lang = ttk.Combobox(top, values=names, state="readonly", width=12)
        self.cb_lang.current([c for c, _ in i18n.LANGS].index(i18n.get_lang()))
        self.cb_lang.pack(side="right")
        self.cb_lang.bind("<<ComboboxSelected>>", lambda e: self.change_lang(i18n.LANGS[self.cb_lang.current()][0]))
        ttk.Label(top, text="🌐 " + t("language")).pack(side="right", padx=4)

        # 1. NIC
        f1 = ttk.LabelFrame(main, text=t("f_nic"), padding=6)
        f1.pack(fill="x")
        self.nic_tree = ttk.Treeview(f1, columns=("idx", "name", "ip", "mac", "desc"), show="headings",
                                     height=4, selectmode="extended")
        for col, key, w in (("idx", "c_idx", 50), ("name", "c_card", 170), ("ip", "c_cur_ip", 260),
                            ("mac", "c_mac", 140), ("desc", "c_desc", 420)):
            self.nic_tree.heading(col, text=t(key))
            self.nic_tree.column(col, width=w, stretch=(col == "desc"), anchor="w")
        self.nic_tree.pack(side="left", fill="x", expand=True)
        ttk.Button(f1, text=t("refresh"), command=self.refresh_nics).pack(side="left", padx=(6, 0), anchor="n")

        # 2. Options
        f2 = ttk.LabelFrame(main, text=t("f_opt"), padding=6)
        f2.pack(fill="x", pady=(6, 0))
        ttk.Label(f2, text=t("o_time")).grid(row=0, column=0, sticky="e")
        ttk.Spinbox(f2, from_=10, to=3600, increment=10, textvariable=self.v_time, width=7).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Label(f2, text=t("o_preset")).grid(row=0, column=2, sticky="e", padx=(16, 0))
        self.cb_preset = ttk.Combobox(f2, values=[t("p_" + k) for k in PRESET_KEYS], state="readonly", width=58)
        self.cb_preset.current(self.preset_idx)
        self.cb_preset.grid(row=0, column=3, sticky="w", padx=4)
        ttk.Label(f2, text=t("o_range")).grid(row=1, column=0, sticky="e", pady=(4, 0))
        ttk.Entry(f2, textvariable=self.v_range, width=34).grid(row=1, column=1, columnspan=2, sticky="w", padx=4, pady=(4, 0))
        ttk.Label(f2, text=t("o_range_hint"), foreground="#666").grid(row=1, column=3, sticky="w", padx=4)
        ttk.Label(f2, text=t("o_mac")).grid(row=2, column=0, sticky="e", pady=(4, 0))
        ttk.Entry(f2, textvariable=self.v_mac, width=20).grid(row=2, column=1, columnspan=2, sticky="w", padx=4, pady=(4, 0))
        ttk.Label(f2, text=t("o_mac_hint"), foreground="#666").grid(row=2, column=3, sticky="w", padx=4)
        ttk.Checkbutton(f2, text=t("o_passive"), variable=self.v_passive).grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))

        # Run controls
        f3 = ttk.Frame(main, padding=(0, 8, 0, 4))
        f3.pack(fill="x")
        self.btn_start = ttk.Button(f3, text=t("start"), style="Big.TButton", command=self.start_scan)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(f3, text=t("stop"), style="Big.TButton", command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(f3, mode="determinate", length=240, maximum=1000)
        self.progress.pack(side="left", padx=6)
        self.lbl_status = ttk.Label(f3, text=t("ready"))
        self.lbl_status.pack(side="left", padx=6)
        ttk.Label(main, foreground="#0b5394", text=t("tip"), wraplength=1100).pack(fill="x")

        # 3. Results + log
        pw = ttk.PanedWindow(main, orient="vertical")
        pw.pack(fill="both", expand=True, pady=(6, 0))
        f4 = ttk.LabelFrame(pw, text=t("f_res"), padding=6)
        cols = (("nic", "c_card", 110), ("mac", "c_mac", 135), ("ip", "c_ip", 150), ("status", "c_status", 130),
                ("vendor", "c_vendor", 170), ("name", "c_name", 220), ("via", "c_via", 220))
        tf = ttk.Frame(f4)
        tf.pack(fill="both", expand=True)
        self.res = ttk.Treeview(tf, columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for col, key, w in cols:
            self.res.heading(col, text=t(key))
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
        for key, cmd in (("b_access", self.access), ("b_web", self.open_web), ("b_copy_ip", self.copy_ip),
                         ("b_dcp_ip", self.dcp_setip), ("b_blink", self.dcp_blink)):
            ttk.Button(fb, text=t(key), command=cmd).pack(side="left", padx=(0, 4))
        ttk.Button(fb, text=t("b_export"), command=self.export).pack(side="right")
        self.btn_remove = ttk.Button(fb, text=t("b_remove"), command=self.remove_added,
                                     state="normal" if self.added_ips else "disabled")
        self.btn_remove.pack(side="right", padx=4)
        pw.add(f4, weight=4)

        self.menu = tk.Menu(self.root, tearoff=0)
        for key, cmd in (("b_access", self.access), ("b_web", self.open_web), ("b_copy_ip", self.copy_ip),
                         ("b_copy_mac", self.copy_mac), (None, None), ("b_dcp_ip", self.dcp_setip), ("b_blink", self.dcp_blink)):
            if key is None:
                self.menu.add_separator()
            else:
                self.menu.add_command(label=t(key), command=cmd)

        f5 = ttk.LabelFrame(pw, text=t("f_log"), padding=4)
        self.log_txt = scrolledtext.ScrolledText(f5, height=8, font="TkFixedFont")
        self.log_txt.pack(fill="both", expand=True)
        self.log_txt.configure(state="disabled")
        pw.add(f5, weight=1)

    # ------------------------------------------------------------------ helpers
    def log(self, msg: str) -> None:
        self.log_txt.configure(state="normal")
        self.log_txt.insert("end", msg + "\n")
        self.log_txt.see("end")
        self.log_txt.configure(state="disabled")

    def _set_status(self, key: str, kw: dict) -> None:
        self.status_msg = (key, kw)
        self.lbl_status.configure(text=t(key, **kw))

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
                    self.busy = max(0, self.busy - 1)
                    if self.busy == 0:
                        self.root.configure(cursor="")
                    if cb:
                        cb(res, err)
                    elif err:
                        messagebox.showerror(t("err"), err)
        except queue.Empty:
            pass
        self.refresh_results()
        if self.state == "running":
            now = time.time()
            total = max(1.0, self.t_end - self.t_start)
            self.progress["value"] = min(1000, (now - self.t_start) / total * 1000)
            n = len(self.reg.devs) if self.reg else 0
            self._set_status("scanning", {"left": max(0, int(self.t_end - now)), "n": n})
            if now >= self.t_end:
                self.stop_scan()
        self.root.after(250, self.poll)

    def nic_by_name(self, name: str):
        return next((n for n in self.nics if n.name == name), None)

    # ------------------------------------------------------------------ NIC
    def _fill_nics(self, keep=None) -> None:
        keep = keep or set()
        self.nic_tree.delete(*self.nic_tree.get_children())
        for n in self.nics:
            ips = ", ".join(f"{ip}/{p}" for ip, p in n.ipv4) or t("no_ipv4")
            iid = self.nic_tree.insert("", "end", values=(n.index, n.name, ips, n.mac, n.description))
            if n.name in keep:
                self.nic_tree.selection_add(iid)
        if len(self.nics) == 1:
            self.nic_tree.selection_set(self.nic_tree.get_children()[0])

    def refresh_nics(self) -> None:
        def done(res, err):
            if err:
                messagebox.showerror(t("err"), t("nics_err", err=err))
                return
            keep = {self.nic_tree.item(i, "values")[1] for i in self.nic_tree.selection()}
            self.nics = res or []
            self._fill_nics(keep)
            self.log(t("nics_found", n=len(self.nics)))
            seen = []
            for n in self.nics:
                for net in n.networks:
                    for onet, oname in seen:
                        if net.overlaps(onet) and oname != n.name:
                            self.log("! " + t("overlap", net=net, a=n.name, onet=onet, b=oname))
                    seen.append((net, n.name))

        self.run_bg(core.get_nics, done)

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
            messagebox.showwarning(t("no_nic_title"), t("no_nic"))
            return
        argv = ["find"]
        for nm in names:
            argv += ["--iface", nm]
        tv = self.v_time.get().strip()
        argv += ["--time", tv if tv.isdigit() and int(tv) > 0 else "60"]
        argv += ["--preset", PRESET_KEYS[max(0, self.cb_preset.current())]]
        if self.v_range.get().strip():
            argv += ["--range", self.v_range.get().strip()]
        if self.v_mac.get().strip():
            argv += ["--mac", self.v_mac.get().strip()]
        if self.v_passive.get():
            argv += ["--passive"]
        try:
            args = core.build_parser().parse_args(argv)
            sel = [n for n in (self.nic_by_name(nm) for nm in names) if n is not None]
            reg = core.Registry(verbose=True, mac_filter=args.mac)
            scanner = core.Scanner(sel, args, reg)
        except core.IPFinderError as e:
            messagebox.showerror(t("err"), str(e))
            return
        except SystemExit:
            messagebox.showerror(t("err"), t("bad_opt"))
            return
        est = scanner.estimate_arp_seconds()
        if est + 5 > args.time:
            new_t = int(est) + 15
            self.log(t("extend", sec=f"{est:.0f}", new=new_t))
            args.time = new_t
            self.v_time.set(str(new_t))
        self.reg, self.scanner = reg, scanner
        self.res.delete(*self.res.get_children())
        self.iids.clear()
        self.set_state("starting")
        self._set_status("starting", {})
        self.log(t("scan_begin", sec=args.time, nics=", ".join(names)))

        def done(_res, err):
            if err:
                self.set_state("idle")
                self._set_status("err", {})
                messagebox.showerror(t("scan_fail_title"), err)
                return
            self.t_start = time.time()
            self.t_end = self.t_start + args.time
            self.set_state("running")

        self.run_bg(scanner.start, done)

    def stop_scan(self) -> None:
        if self.state != "running" or not self.scanner:
            return
        self.set_state("stopping")
        self._set_status("stopping", {})

        def done(_res, _err):
            self.set_state("idle")
            devs = self.reg.list() if self.reg else []
            other = sum(1 for d in devs if self.code_of(d) == "other")
            self._set_status("done_status", {"n": len(devs), "o": other})
            self.log(t("done_log", n=len(devs)))
            if not devs:
                messagebox.showinfo(t("none_title"), t("none_msg"))

        self.run_bg(self.scanner.stop, done)

    # ------------------------------------------------------------------ results
    def code_of(self, d) -> str:
        return core.classify(d, self.nic_by_name(d.nic))

    def refresh_results(self) -> None:
        if not self.reg:
            return
        devs = self.reg.list()
        devs.sort(key=lambda d: (core.STATUS_ORDER.get(self.code_of(d), 9), d.nic, d.mac))
        for pos, d in enumerate(devs):
            code = self.code_of(d)
            ips = ", ".join(d.best_ips()) or ((t("trying") + " " + ", ".join(sorted(d.probes))) if d.probes else "-")
            via = set()
            for src in d.ips.values():
                via |= src
            if d.dhcp:
                via.add("DHCP")
            vendor = core.vendor_of(d.mac)  # tra lại để theo đúng ngôn ngữ đang chọn
            vals = (d.nic, d.mac, ips, core.status_text(code), vendor, " | ".join(sorted(d.names)), ", ".join(sorted(via)))
            key = (d.nic, d.mac)
            iid = self.iids.get(key)
            tag = (STATUS_TAGS.get(code, ""),)
            if iid is None or not self.res.exists(iid):
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
            messagebox.showinfo(t("sel_title"), t("sel_msg"))
            return None
        key = next((k for k, v in self.iids.items() if v == sel[0]), None)
        d = self.reg.devs.get(key) if key else None
        if d is None:
            return None
        if need_ip and not d.ips:
            messagebox.showinfo(t("noip_title"), t("noip_msg"))
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
        ip = d.best_ips()[0]
        reachable = any(ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{a}/{p}", strict=False)
                        for n in self.nics for a, p in n.ipv4)
        if self.code_of(d) == "other" and not reachable:
            if not messagebox.askyesno(t("web_other_title"), t("web_other", ip=ip)):
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
                self.log(t("exported", path=path))
            except Exception as e:
                messagebox.showerror(t("err"), str(e))

    # ------------------------------------------------------------------ access
    def access(self) -> None:
        d = self.selected_device()
        if not d:
            return
        nic = self.nic_by_name(d.nic)
        if nic is None:
            return
        ip = d.best_ips()[0]
        mask = simpledialog.askstring(t("mask_title"), t("mask_ask", ip=ip), initialvalue="255.255.255.0", parent=self.root)
        if not mask:
            return
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask.strip()}").prefixlen
        except ValueError:
            messagebox.showerror(t("mask_bad_title"), t("mask_bad", mask=mask))
            return

        def planned(plan, err):
            if err:
                messagebox.showerror(t("err"), err)
                return
            if plan.my_ip is None:
                if messagebox.askyesno(t("same_title"), t("same_msg", ip=ip, nic=nic.name)):
                    webbrowser.open(f"http://{ip}")
                return
            msg = t("access_msg", my=plan.my_ip, p=plan.net.prefixlen, nic=nic.name, ip=ip)
            if plan.conflicts:
                msg += t("access_conflict", net=plan.net, other=", ".join(plan.conflicts))
                if not messagebox.askyesno(t("conflict_title"), msg + t("continue_q"), icon="warning", default="no"):
                    return
            elif not messagebox.askyesno(t("access_title"), msg + t("continue_q")):
                return

            def applied(res, err2):
                ok, out = res if res else (False, err2 or "")
                if not ok:
                    hint = t("add_fail_dhcp") if core.IS_WINDOWS else ""
                    messagebox.showerror(t("add_fail_title"), (out or err2 or t("unknown_err")) + hint)
                    return
                self.added_ips.append((nic, plan.my_ip, plan.net.prefixlen))
                self.btn_remove.configure(state="normal")
                self.log(t("added_log", my=plan.my_ip, p=plan.net.prefixlen, nic=nic.name))

                def verified(ok2, _e):
                    if ok2:
                        if messagebox.askyesno(t("reach_title"), t("reach_msg", ip=ip)):
                            webbrowser.open(f"http://{ip}")
                    else:
                        messagebox.showwarning(t("noreach_title"), t("noreach_msg", ip=ip))

                self.run_bg(lambda: core.verify_device(nic, ip), verified)

            self.run_bg(lambda: core.apply_cmds(plan.add), applied)

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
                messagebox.showwarning(t("remove_title"), t("remove_fail", list="\n".join(fails or [err])))
            elif not silent:
                self.log(t("removed"))
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
        mode = t("mode_perm") if perm else t("mode_temp")
        if not messagebox.askyesno(t("confirm_title"), t("dcp_confirm", mac=d.mac, ip=ip, mask=mask, gw=gw, mode=mode),
                                   icon="warning"):
            return

        def done(res, err):
            ok, msg = res if res else (False, err)
            if ok:
                messagebox.showinfo(t("ok_title"), t("dcp_ok", ip=ip))
            else:
                messagebox.showerror(t("fail_title"), msg or t("unknown_err"))
            self.log(t("dcp_log", mac=d.mac, ip=ip, msg=msg))

        self.run_bg(lambda: core.dcp_set_ip(nic, d.mac, ip, mask, gw, perm), done)

    def dcp_blink(self) -> None:
        d = self.selected_device(need_ip=False)
        if not d:
            return
        nic = self.nic_by_name(d.nic)

        def done(res, err):
            ok, msg = res if res else (False, err)
            if ok:
                messagebox.showinfo(t("blink_title"), t("blink_ok") + (msg or ""))
            else:
                messagebox.showerror(t("blink_title"), msg or t("unknown_err"))

        self.run_bg(lambda: core.dcp_blink(nic, d.mac), done)

    # ------------------------------------------------------------------ close
    def on_close(self) -> None:
        if self.added_ips:
            ans = messagebox.askyesnocancel(t("exit_title"), t("exit_ask"))
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


# ---------------------------------------------------------------------------- self-test / main
def selftest(out_path: str) -> int:
    """Kiểm tra bản đóng gói: dựng giao diện ở cả 3 ngôn ngữ, chạy vài hàm lõi, rồi thoát (dùng trong CI)."""
    lines = []
    try:
        root = tk.Tk()
        root.withdraw()
        i18n.set_lang("vi")
        app = App(root)
        for code, _ in i18n.LANGS:
            app.change_lang(code)
            lines.append(f"ui {code} ok: {root.title()}")
        lines.append("vendor 00:d0:24 = " + core.vendor_of("00:d0:24:00:00:01"))
        lines.append("hosts quick = %d" % len(core.hosts_of(core.parse_ranges(core.PRESETS["quick"]))))
        lines.append("npcap = %s" % core.npcap_installed())
        missing = [k for k, v in i18n.TEXTS.items() for c, _ in i18n.LANGS if not v.get(c)]
        lines.append("missing translations = %s" % missing)
        app.on_close()
        lines.append("OK" if not missing else "FAIL")
        rc = 0 if not missing else 1
    except Exception:
        lines.append(traceback.format_exc())
        rc = 1
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return rc


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
        return selftest(sys.argv[2])
    i18n.set_lang(initial_lang())
    enable_dpi_awareness()
    root = tk.Tk()
    App(root)
    if not core.npcap_installed():
        root.after(300, lambda: messagebox.showerror(t("npcap_title"), t("npcap_help")))
    elif not core.is_admin():
        root.after(300, lambda: messagebox.showwarning(t("admin_title"), t("admin_msg")))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
