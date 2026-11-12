# -*- coding: utf-8 -*-
"""
Đa ngôn ngữ cho IP Finder: Tiếng Việt (vi), English (en), 中文简体 (zh).

    from i18n import t, set_lang
    set_lang("en")
    t("st_other")          -> "OTHER SUBNET"
    t("new_dev", nic="Ethernet 2", mac="00:11:..", vendor="Cognex")
"""
from __future__ import annotations

import locale
import os

LANGS = [("vi", "Tiếng Việt"), ("en", "English"), ("zh", "中文")]
_lang = "vi"


def set_lang(code: str) -> None:
    global _lang
    _lang = code if code in T_ALL_CODES else "en"


def get_lang() -> str:
    return _lang


def detect_lang() -> str:
    """Ngôn ngữ giao diện Windows / locale hệ thống."""
    try:
        if os.name == "nt":
            import ctypes

            lid = ctypes.windll.kernel32.GetUserDefaultUILanguage() & 0x3FF  # primary language id
            return {0x2A: "vi", 0x04: "zh"}.get(lid, "en")
    except Exception:
        pass
    try:
        loc = (locale.getlocale()[0] or os.environ.get("LANG", "")).lower()
    except Exception:
        loc = os.environ.get("LANG", "").lower()
    if loc.startswith("vi"):
        return "vi"
    if loc.startswith("zh") or loc.startswith("chinese"):
        return "zh"
    return "en"


def t(key: str, **kw) -> str:
    entry = TEXTS.get(key)
    if entry is None:
        s = key
    else:
        s = entry.get(_lang) or entry.get("en") or entry.get("vi") or key
    if kw:
        try:
            s = s.format(**kw)
        except (KeyError, IndexError, ValueError):
            pass
    return s


T_ALL_CODES = {c for c, _ in LANGS}

# Mỗi mục: key -> {vi, en, zh}
TEXTS = {
    # ------------------------------------------------------------------ trạng thái thiết bị
    "st_other": {"vi": "KHÁC SUBNET", "en": "OTHER SUBNET", "zh": "不同网段"},
    "st_same": {"vi": "cùng subnet", "en": "same subnet", "zh": "同网段"},
    "st_dhcp": {"vi": "DHCP - CHƯA CÓ IP", "en": "DHCP - NO IP YET", "zh": "DHCP - 尚无IP"},
    "st_booting": {"vi": "ĐANG KHỞI ĐỘNG", "en": "BOOTING", "zh": "正在启动"},
    "st_noip": {"vi": "CHƯA THẤY IPv4", "en": "NO IPv4 SEEN", "zh": "未发现IPv4"},
    "mac_local": {"vi": "(MAC cục bộ/ngẫu nhiên)", "en": "(locally administered MAC)", "zh": "(本地/随机MAC)"},
    "trying": {"vi": "thử", "en": "trying", "zh": "尝试"},

    # ------------------------------------------------------------------ log của lõi
    "new_dev": {"vi": "[{nic}] Thiết bị mới MAC {mac} {vendor}", "en": "[{nic}] New device MAC {mac} {vendor}",
                "zh": "[{nic}] 新设备 MAC {mac} {vendor}"},
    "dev_ip": {"vi": "[{nic}]   {mac} có IP {ip}  (qua {src})", "en": "[{nic}]   {mac} has IP {ip}  (via {src})",
               "zh": "[{nic}]   {mac} 的IP为 {ip}  (来源 {src})"},
    "dev_probe": {"vi": "[{nic}]   {mac} đang khởi động, thử nhận IP {ip} (ARP probe)",
                  "en": "[{nic}]   {mac} is booting, probing for IP {ip} (ARP probe)",
                  "zh": "[{nic}]   {mac} 正在启动，尝试使用IP {ip} (ARP探测)"},
    "dev_name": {"vi": "[{nic}]   {mac} tên: {name}", "en": "[{nic}]   {mac} name: {name}", "zh": "[{nic}]   {mac} 名称: {name}"},
    "dev_dhcp": {"vi": "[{nic}]   {mac} đang xin IP qua DHCP/BOOTP (thiết bị ở chế độ DHCP)",
                 "en": "[{nic}]   {mac} is requesting an IP via DHCP/BOOTP (device in DHCP mode)",
                 "zh": "[{nic}]   {mac} 正通过DHCP/BOOTP请求IP (设备处于DHCP模式)"},
    "arp_start": {"vi": "[{nic}] Quét ARP {n} IP{label} (IP nguồn: {src}), ~{sec}s ...",
                  "en": "[{nic}] ARP sweep of {n} IPs{label} (source IP: {src}), ~{sec}s ...",
                  "zh": "[{nic}] ARP扫描 {n} 个IP{label} (源IP: {src})，约 {sec} 秒 ..."},
    "arp_label_own": {"vi": " trong subnet của NIC", "en": " in the NIC's subnet", "zh": "（网卡所在网段）"},
    "arp_label_ranges": {"vi": " (dải mặc định/tự chọn)", "en": " (default/custom ranges)", "zh": "（默认/自定义网段）"},
    "arp_progress": {"vi": "[{nic}]   ... đã gửi {sent}/{total}", "en": "[{nic}]   ... sent {sent}/{total}",
                     "zh": "[{nic}]   ... 已发送 {sent}/{total}"},
    "arp_done": {"vi": "[{nic}] Quét ARP xong, tiếp tục nghe...", "en": "[{nic}] ARP sweep done, still listening...",
                 "zh": "[{nic}] ARP扫描完成，继续监听..."},
    "sniff_fail": {"vi": "[{nic}] Không mở được card để nghe: {err}", "en": "[{nic}] Cannot capture on this adapter: {err}",
                   "zh": "[{nic}] 无法在此网卡上抓包: {err}"},
    "send_fail": {"vi": "[{nic}] Không gửi được gói trên card này: {err}", "en": "[{nic}] Cannot send on this adapter: {err}",
                  "zh": "[{nic}] 无法在此网卡上发包: {err}"},
    "probe_err": {"vi": "[{nic}] lỗi khi gửi gói dò: {err}", "en": "[{nic}] error while sending probes: {err}",
                  "zh": "[{nic}] 发送探测包出错: {err}"},
    "no_sniffer": {"vi": "không nghe được trên card nào. Chạy bằng quyền Administrator/root; Windows cần cài Npcap.",
                   "en": "cannot capture on any adapter. Run as Administrator/root; Windows needs Npcap installed.",
                   "zh": "无法在任何网卡上抓包。请以管理员/root身份运行；Windows需安装Npcap。"},
    "range_bad": {"vi": "dải IP không hợp lệ '{item}': {err}", "en": "invalid IP range '{item}': {err}",
                  "zh": "无效的IP范围 '{item}': {err}"},
    "range_order": {"vi": "dải IP '{item}': IP cuối nhỏ hơn IP đầu", "en": "IP range '{item}': end is lower than start",
                    "zh": "IP范围 '{item}': 结束IP小于起始IP"},
    "range_big": {"vi": "dải IP '{item}' quá lớn", "en": "IP range '{item}' is too large", "zh": "IP范围 '{item}' 过大"},
    "limit": {"vi": "dải quét có {n} IP, vượt giới hạn {limit}.", "en": "the sweep has {n} IPs, over the limit of {limit}.",
              "zh": "扫描范围有 {n} 个IP，超过上限 {limit}。"},
    "check_free": {"vi": "Kiểm tra IP trống trên card '{nic}' (ARP probe): {ips} ...",
                   "en": "Checking free IPs on adapter '{nic}' (ARP probe): {ips} ...",
                   "zh": "在网卡 '{nic}' 上检查空闲IP (ARP探测): {ips} ..."},
    "check_fail": {"vi": "  (không kiểm tra được: {err})", "en": "  (check failed: {err})", "zh": "  (检查失败: {err})"},
    "ip_in_use": {"vi": "  Đang có thiết bị dùng: {ips}", "en": "  Already in use: {ips}", "zh": "  已被占用: {ips}"},
    "no_free_ip": {"vi": "không tìm được IP trống trong subnet của thiết bị. Hãy tự chỉ định IP cho máy tính.",
                   "en": "no free IP found in the device's subnet. Please specify the PC's IP manually.",
                   "zh": "在设备网段内找不到空闲IP。请手动指定电脑的IP。"},
    "cmd_err": {"vi": "    lỗi: {err}", "en": "    error: {err}", "zh": "    错误: {err}"},
    "dcp_noreply": {"vi": "thiết bị không trả lời (có thể không hỗ trợ PROFINET DCP, hoặc sai MAC/card)",
                    "en": "no reply (device may not support PROFINET DCP, or wrong MAC/adapter)",
                    "zh": "设备无应答（可能不支持PROFINET DCP，或MAC/网卡错误）"},
    "dcp_e0": {"vi": "OK", "en": "OK", "zh": "成功"},
    "dcp_e1": {"vi": "Option không hỗ trợ", "en": "Option not supported", "zh": "不支持该选项"},
    "dcp_e2": {"vi": "Suboption không hỗ trợ / không có", "en": "Suboption not supported / not set", "zh": "不支持该子选项"},
    "dcp_e3": {"vi": "Suboption chưa set được", "en": "Suboption not set", "zh": "子选项未设置"},
    "dcp_e4": {"vi": "Lỗi tài nguyên", "en": "Resource error", "zh": "资源错误"},
    "dcp_e5": {"vi": "Không thể set (thiết bị đang chạy / bị khoá)", "en": "Set not possible (device running / locked)",
               "zh": "无法设置（设备运行中/已锁定）"},
    "dcp_e6": {"vi": "Không được phép (đang kết nối với PLC?)", "en": "Not allowed (connected to a PLC?)",
               "zh": "不允许（是否已与PLC连接？）"},
    "dcp_ecode": {"vi": "mã lỗi {code}", "en": "error code {code}", "zh": "错误码 {code}"},
    "dcp_ok_nocode": {"vi": "OK (không có mã phản hồi)", "en": "OK (no response code)", "zh": "成功（无响应码）"},

    # ------------------------------------------------------------------ giao diện
    "app_title": {"vi": "IP Finder {ver} – Dò IP thiết bị công nghiệp", "en": "IP Finder {ver} – Industrial device IP discovery",
                  "zh": "IP Finder {ver} – 工业设备IP查找工具"},
    "language": {"vi": "Ngôn ngữ:", "en": "Language:", "zh": "语言:"},
    "f_nic": {"vi": " 1. Chọn card mạng đang cắm thiết bị (giữ Ctrl để chọn nhiều card) ",
              "en": " 1. Select the adapter the device is connected to (hold Ctrl to select several) ",
              "zh": " 1. 选择连接设备的网卡（按住Ctrl可多选） "},
    "c_idx": {"vi": "Số", "en": "No.", "zh": "序号"},
    "c_card": {"vi": "Card", "en": "Adapter", "zh": "网卡"},
    "c_cur_ip": {"vi": "IP / subnet hiện tại", "en": "Current IP / subnet", "zh": "当前IP/网段"},
    "c_desc": {"vi": "Mô tả", "en": "Description", "zh": "描述"},
    "no_ipv4": {"vi": "(chưa có IPv4)", "en": "(no IPv4)", "zh": "(无IPv4)"},
    "refresh": {"vi": "Làm mới", "en": "Refresh", "zh": "刷新"},
    "f_opt": {"vi": " 2. Tuỳ chọn ", "en": " 2. Options ", "zh": " 2. 选项 "},
    "o_time": {"vi": "Thời gian dò (giây):", "en": "Scan time (s):", "zh": "扫描时间(秒):"},
    "o_preset": {"vi": "Dải quét ARP:", "en": "ARP sweep:", "zh": "ARP扫描范围:"},
    "p_quick": {"vi": "Nhanh – các dải IP mặc định phổ biến (~7.000 IP, ~30 giây)",
                "en": "Quick – common factory-default ranges (~7,000 IPs, ~30 s)",
                "zh": "快速 – 常见出厂默认网段（约7000个IP，约30秒）"},
    "p_192": {"vi": "Toàn bộ 192.168.x.x (~65.000 IP, ~4–5 phút)", "en": "All of 192.168.x.x (~65,000 IPs, ~4–5 min)",
              "zh": "全部 192.168.x.x（约65000个IP，约4–5分钟）"},
    "p_wide": {"vi": "Rộng – 192.168 / 10.x / 172.16 / 169.254 (~26 phút)",
               "en": "Wide – 192.168 / 10.x / 172.16 / 169.254 (~26 min)",
               "zh": "广泛 – 192.168 / 10.x / 172.16 / 169.254（约26分钟）"},
    "p_none": {"vi": "Không quét ARP (chỉ nghe + PROFINET/EtherNet-IP)", "en": "No ARP sweep (listen + PROFINET/EtherNet-IP only)",
               "zh": "不进行ARP扫描（仅监听 + PROFINET/EtherNet-IP）"},
    "o_range": {"vi": "Dải IP thêm:", "en": "Extra IP ranges:", "zh": "附加IP范围:"},
    "o_range_hint": {"vi": "VD: 192.168.7.0/24, 10.0.0.1-50", "en": "e.g. 192.168.7.0/24, 10.0.0.1-50", "zh": "例: 192.168.7.0/24, 10.0.0.1-50"},
    "o_mac": {"vi": "Lọc MAC:", "en": "MAC filter:", "zh": "MAC过滤:"},
    "o_mac_hint": {"vi": "(phần đầu MAC in trên tem thiết bị, để trống = tất cả)",
                   "en": "(start of the MAC printed on the device label; empty = all)",
                   "zh": "（设备标签上MAC的开头部分，留空=全部）"},
    "o_passive": {"vi": "Chỉ nghe – không gửi gói nào (an toàn tuyệt đối cho mạng đang sản xuất)",
                  "en": "Listen only – send nothing (completely safe for a running production network)",
                  "zh": "仅监听 – 不发送任何数据包（对生产网络绝对安全）"},
    "start": {"vi": "▶  Bắt đầu dò", "en": "▶  Start scan", "zh": "▶  开始扫描"},
    "stop": {"vi": "■  Dừng", "en": "■  Stop", "zh": "■  停止"},
    "ready": {"vi": "Sẵn sàng.", "en": "Ready.", "zh": "就绪。"},
    "tip": {"vi": "MẸO: trong lúc dò, hãy TẮT/BẬT NGUỒN hoặc RÚT/CẮM LẠI CÁP thiết bị cần tìm – "
                  "thiết bị sẽ tự báo IP dù ở lớp mạng nào.",
            "en": "TIP: while scanning, POWER-CYCLE the device or UNPLUG/REPLUG its cable – "
                  "it will announce its IP whatever subnet it is in.",
            "zh": "提示：扫描时请给目标设备断电重启或拔插网线——无论在哪个网段，设备都会自动通告其IP。"},
    "f_res": {"vi": " 3. Kết quả (dòng màu cam = KHÁC SUBNET, thường là thiết bị cần tìm; nhấp đúp để mở web) ",
              "en": " 3. Results (orange = OTHER SUBNET, usually the device you are looking for; double-click to open web) ",
              "zh": " 3. 结果（橙色=不同网段，通常就是要找的设备；双击打开网页） "},
    "c_mac": {"vi": "MAC", "en": "MAC", "zh": "MAC"},
    "c_ip": {"vi": "IP", "en": "IP", "zh": "IP"},
    "c_status": {"vi": "Trạng thái", "en": "Status", "zh": "状态"},
    "c_vendor": {"vi": "Hãng", "en": "Vendor", "zh": "厂商"},
    "c_name": {"vi": "Tên thiết bị", "en": "Device name", "zh": "设备名称"},
    "c_via": {"vi": "Phát hiện qua", "en": "Detected via", "zh": "发现方式"},
    "b_access": {"vi": "Truy cập (thêm IP phụ)…", "en": "Access (add temp IP)…", "zh": "访问（添加临时IP）…"},
    "b_web": {"vi": "Mở web", "en": "Open web", "zh": "打开网页"},
    "b_copy_ip": {"vi": "Copy IP", "en": "Copy IP", "zh": "复制IP"},
    "b_copy_mac": {"vi": "Copy MAC", "en": "Copy MAC", "zh": "复制MAC"},
    "b_dcp_ip": {"vi": "Đổi IP (PROFINET)…", "en": "Set IP (PROFINET)…", "zh": "修改IP（PROFINET）…"},
    "b_blink": {"vi": "Nháy đèn (PROFINET)", "en": "Blink LED (PROFINET)", "zh": "闪烁指示灯（PROFINET）"},
    "b_export": {"vi": "Xuất CSV…", "en": "Export CSV…", "zh": "导出CSV…"},
    "b_remove": {"vi": "Gỡ IP phụ đã thêm", "en": "Remove added IPs", "zh": "移除已添加的IP"},
    "f_log": {"vi": " Nhật ký ", "en": " Log ", "zh": " 日志 "},
    "err": {"vi": "Lỗi", "en": "Error", "zh": "错误"},
    "nics_err": {"vi": "Không đọc được danh sách card mạng:\n{err}", "en": "Cannot read the adapter list:\n{err}",
                 "zh": "无法读取网卡列表：\n{err}"},
    "nics_found": {"vi": "Tìm thấy {n} card mạng.", "en": "Found {n} network adapters.", "zh": "找到 {n} 个网卡。"},
    "overlap": {"vi": "CẢNH BÁO: subnet {net} của '{a}' trùng với {onet} của '{b}'",
                "en": "WARNING: subnet {net} of '{a}' overlaps {onet} of '{b}'",
                "zh": "警告：'{a}' 的网段 {net} 与 '{b}' 的 {onet} 重叠"},
    "no_nic_title": {"vi": "Chưa chọn card", "en": "No adapter selected", "zh": "未选择网卡"},
    "no_nic": {"vi": "Hãy chọn card mạng đang cắm thiết bị cần tìm (bảng số 1).",
               "en": "Select the adapter the device is connected to (table 1).", "zh": "请选择连接目标设备的网卡（表1）。"},
    "bad_opt": {"vi": "Tuỳ chọn không hợp lệ.", "en": "Invalid options.", "zh": "选项无效。"},
    "extend": {"vi": "Quét ARP cần khoảng {sec} giây nên tự kéo dài thời gian dò lên {new} giây.",
               "en": "The ARP sweep needs about {sec} s, so the scan time was extended to {new} s.",
               "zh": "ARP扫描约需 {sec} 秒，已自动将扫描时间延长到 {new} 秒。"},
    "starting": {"vi": "Đang khởi động…", "en": "Starting…", "zh": "正在启动…"},
    "scan_begin": {"vi": "=== Bắt đầu dò {sec}s trên: {nics} ===", "en": "=== Scanning for {sec}s on: {nics} ===",
                   "zh": "=== 开始扫描 {sec} 秒，网卡: {nics} ==="},
    "scan_fail_title": {"vi": "Không dò được", "en": "Scan failed", "zh": "扫描失败"},
    "scanning": {"vi": "Đang dò… còn {left} giây – đã thấy {n} thiết bị", "en": "Scanning… {left} s left – {n} devices found",
                 "zh": "扫描中… 剩余 {left} 秒 – 已发现 {n} 台设备"},
    "stopping": {"vi": "Đang dừng…", "en": "Stopping…", "zh": "正在停止…"},
    "done_status": {"vi": "Xong: {n} thiết bị, {o} thiết bị KHÁC SUBNET.", "en": "Done: {n} devices, {o} in another subnet.",
                    "zh": "完成：{n} 台设备，其中 {o} 台在不同网段。"},
    "done_log": {"vi": "=== Xong: {n} thiết bị ===", "en": "=== Done: {n} devices ===", "zh": "=== 完成：{n} 台设备 ==="},
    "none_title": {"vi": "Không thấy thiết bị", "en": "No devices found", "zh": "未发现设备"},
    "none_msg": {"vi": "Không thấy thiết bị nào.\n\nKiểm tra: đèn link trên card/thiết bị, đúng card mạng, "
                       "và thử dò lại trong lúc TẮT/BẬT NGUỒN thiết bị.",
                 "en": "No devices found.\n\nCheck the link LEDs, that the right adapter is selected, "
                       "and scan again while POWER-CYCLING the device.",
                 "zh": "未发现任何设备。\n\n请检查网卡/设备的链路指示灯、是否选对网卡，并在给设备断电重启的同时重新扫描。"},
    "sel_title": {"vi": "Chọn thiết bị", "en": "Select a device", "zh": "选择设备"},
    "sel_msg": {"vi": "Hãy chọn một thiết bị trong bảng kết quả.", "en": "Select a device in the results table.",
                "zh": "请在结果表中选择一台设备。"},
    "noip_title": {"vi": "Chưa có IP", "en": "No IP yet", "zh": "尚无IP"},
    "noip_msg": {"vi": "Thiết bị này chưa có IPv4. Hãy dò lại trong lúc tắt/bật nguồn thiết bị.",
                 "en": "This device has no IPv4 yet. Scan again while power-cycling it.",
                 "zh": "该设备尚无IPv4。请在给设备断电重启的同时重新扫描。"},
    "web_other_title": {"vi": "Khác subnet", "en": "Other subnet", "zh": "不同网段"},
    "web_other": {"vi": "Thiết bị {ip} khác subnet nên trình duyệt chưa vào được.\n\n"
                        "Bấm 'Truy cập (thêm IP phụ)' trước. Vẫn mở trình duyệt?",
                  "en": "Device {ip} is in another subnet, so the browser cannot reach it yet.\n\n"
                        "Click 'Access (add temp IP)' first. Open the browser anyway?",
                  "zh": "设备 {ip} 在不同网段，浏览器暂时无法访问。\n\n请先点击“访问（添加临时IP）”。仍要打开浏览器吗？"},
    "exported": {"vi": "Đã xuất: {path}", "en": "Exported: {path}", "zh": "已导出：{path}"},
    "mask_title": {"vi": "Subnet mask", "en": "Subnet mask", "zh": "子网掩码"},
    "mask_ask": {"vi": "Subnet mask của thiết bị {ip}\n(không rõ thì giữ 255.255.255.0):",
                 "en": "Subnet mask of device {ip}\n(keep 255.255.255.0 if unsure):",
                 "zh": "设备 {ip} 的子网掩码\n（不确定请保留 255.255.255.0）:"},
    "mask_bad_title": {"vi": "Sai mask", "en": "Invalid mask", "zh": "掩码无效"},
    "mask_bad": {"vi": "Subnet mask không hợp lệ: {mask}", "en": "Invalid subnet mask: {mask}", "zh": "无效的子网掩码：{mask}"},
    "same_title": {"vi": "Đã cùng subnet", "en": "Already in the same subnet", "zh": "已在同一网段"},
    "same_msg": {"vi": "{ip} đã cùng subnet với card '{nic}'. Mở trình duyệt?",
                 "en": "{ip} is already in the subnet of adapter '{nic}'. Open the browser?",
                 "zh": "{ip} 已与网卡 '{nic}' 在同一网段。打开浏览器吗？"},
    "access_msg": {"vi": "Thêm IP phụ {my}/{p} lên card '{nic}'\nđể truy cập thiết bị {ip}.\n\n"
                         "IP chính và các kết nối hiện tại của card KHÔNG thay đổi.",
                   "en": "Add temporary IP {my}/{p} to adapter '{nic}'\nto reach device {ip}.\n\n"
                         "The adapter's main IP and existing connections are NOT changed.",
                   "zh": "在网卡 '{nic}' 上添加临时IP {my}/{p}\n以访问设备 {ip}。\n\n网卡的主IP和现有连接不会改变。"},
    "access_conflict": {"vi": "\n\n⚠ CẢNH BÁO: subnet {net} TRÙNG với {other}.\n"
                              "Thêm IP có thể làm mất kết nối với thiết bị trên card đó!\n"
                              "Nên rút tạm cáp card kia, hoặc dùng mask 255.255.255.252.",
                        "en": "\n\n⚠ WARNING: subnet {net} OVERLAPS {other}.\n"
                              "Adding the IP may break connections to devices on that adapter!\n"
                              "Unplug that adapter temporarily, or use mask 255.255.255.252.",
                        "zh": "\n\n⚠ 警告：网段 {net} 与 {other} 重叠。\n添加该IP可能导致该网卡上的设备断开连接！\n"
                              "建议暂时拔掉该网卡网线，或使用掩码 255.255.255.252。"},
    "conflict_title": {"vi": "Cảnh báo trùng subnet", "en": "Subnet overlap warning", "zh": "网段重叠警告"},
    "continue_q": {"vi": "\n\nTiếp tục?", "en": "\n\nContinue?", "zh": "\n\n继续吗？"},
    "access_title": {"vi": "Truy cập thiết bị", "en": "Access device", "zh": "访问设备"},
    "add_fail_title": {"vi": "Thêm IP thất bại", "en": "Adding the IP failed", "zh": "添加IP失败"},
    "add_fail_dhcp": {"vi": "\n\nWindows chỉ cho thêm IP phụ khi card đặt IP TĨNH. Nếu card đang để DHCP "
                            "(Obtain an IP address automatically), hãy đặt IP tĩnh cho card trước.",
                      "en": "\n\nWindows only allows extra IPs on an adapter with a STATIC IP. If the adapter uses DHCP "
                            "(Obtain an IP address automatically), set a static IP first.",
                      "zh": "\n\nWindows仅允许在设置了静态IP的网卡上添加附加IP。若网卡为DHCP（自动获得IP地址），请先设置静态IP。"},
    "unknown_err": {"vi": "Lỗi không rõ", "en": "Unknown error", "zh": "未知错误"},
    "added_log": {"vi": "Đã thêm IP phụ {my}/{p} lên '{nic}'. Đang kiểm tra thiết bị…",
                  "en": "Added temporary IP {my}/{p} to '{nic}'. Checking the device…",
                  "zh": "已在 '{nic}' 上添加临时IP {my}/{p}。正在检查设备…"},
    "reach_title": {"vi": "Đã truy cập được", "en": "Device reachable", "zh": "已可访问"},
    "reach_msg": {"vi": "Thiết bị {ip} đã trả lời.\n\nMở trình duyệt tới http://{ip} ?\n"
                        "(hoặc dùng phần mềm cấu hình của hãng)\n\nĐổi IP thiết bị xong nhớ bấm 'Gỡ IP phụ đã thêm'.",
                  "en": "Device {ip} answered.\n\nOpen the browser at http://{ip} ?\n(or use the vendor's configuration tool)\n\n"
                        "After changing the device IP, click 'Remove added IPs'.",
                  "zh": "设备 {ip} 已应答。\n\n用浏览器打开 http://{ip} 吗？\n（或使用厂商配置软件）\n\n修改设备IP后，请点击“移除已添加的IP”。"},
    "noreach_title": {"vi": "Chưa thấy trả lời", "en": "No answer yet", "zh": "暂无应答"},
    "noreach_msg": {"vi": "Đã thêm IP nhưng thiết bị {ip} chưa trả lời ARP.\n"
                          "Có thể thiết bị đang khởi động hoặc mask khác. Thử mở web/tool hãng.",
                    "en": "The IP was added but device {ip} has not answered ARP yet.\n"
                          "It may still be booting or use another mask. Try its web page / vendor tool.",
                    "zh": "已添加IP，但设备 {ip} 尚未应答ARP。\n设备可能仍在启动或掩码不同。请尝试网页/厂商工具。"},
    "remove_title": {"vi": "Gỡ IP", "en": "Remove IPs", "zh": "移除IP"},
    "remove_fail": {"vi": "Một số IP chưa gỡ được:\n{list}", "en": "Some IPs could not be removed:\n{list}",
                    "zh": "部分IP未能移除：\n{list}"},
    "removed": {"vi": "Đã gỡ các IP phụ.", "en": "Temporary IPs removed.", "zh": "已移除临时IP。"},
    "dcp_title": {"vi": "Đổi IP thiết bị PROFINET", "en": "Set PROFINET device IP", "zh": "修改PROFINET设备IP"},
    "dcp_mac": {"vi": "Thiết bị MAC: {mac}", "en": "Device MAC: {mac}", "zh": "设备MAC：{mac}"},
    "dcp_cur": {"vi": "IP hiện tại: {ip}", "en": "Current IP: {ip}", "zh": "当前IP：{ip}"},
    "dcp_new_ip": {"vi": "IP mới:", "en": "New IP:", "zh": "新IP:"},
    "dcp_mask": {"vi": "Subnet mask:", "en": "Subnet mask:", "zh": "子网掩码:"},
    "dcp_gw": {"vi": "Gateway:", "en": "Gateway:", "zh": "网关:"},
    "dcp_perm": {"vi": "Lưu vĩnh viễn (bỏ chọn = tạm thời, mất khi tắt nguồn)",
                 "en": "Save permanently (unchecked = temporary, lost at power-off)", "zh": "永久保存（不勾选=临时，断电后失效）"},
    "dcp_warn": {"vi": "Chỉ làm khi thiết bị KHÔNG đang chạy sản xuất / không kết nối PLC.",
                 "en": "Only do this when the device is NOT in production / not connected to a PLC.",
                 "zh": "仅在设备未投入生产/未连接PLC时操作。"},
    "dcp_bad_title": {"vi": "Sai định dạng", "en": "Invalid format", "zh": "格式错误"},
    "dcp_bad": {"vi": "IP / mask / gateway không hợp lệ:\n{err}", "en": "Invalid IP / mask / gateway:\n{err}",
                "zh": "IP/掩码/网关无效：\n{err}"},
    "confirm_title": {"vi": "Xác nhận", "en": "Confirm", "zh": "确认"},
    "dcp_confirm": {"vi": "Đổi IP thiết bị {mac}\nthành {ip} / {mask}, gateway {gw}\n({mode}) ?",
                    "en": "Change the IP of device {mac}\nto {ip} / {mask}, gateway {gw}\n({mode}) ?",
                    "zh": "将设备 {mac} 的IP\n修改为 {ip} / {mask}，网关 {gw}\n（{mode}）？"},
    "mode_perm": {"vi": "lưu vĩnh viễn", "en": "permanent", "zh": "永久"},
    "mode_temp": {"vi": "tạm thời", "en": "temporary", "zh": "临时"},
    "ok_title": {"vi": "Thành công", "en": "Success", "zh": "成功"},
    "dcp_ok": {"vi": "Đã đổi IP thành {ip}.\nBấm 'Bắt đầu dò' lại để xác nhận.", "en": "IP changed to {ip}.\nScan again to confirm.",
               "zh": "IP已修改为 {ip}。\n请重新扫描以确认。"},
    "fail_title": {"vi": "Thất bại", "en": "Failed", "zh": "失败"},
    "dcp_log": {"vi": "Đổi IP PROFINET {mac} -> {ip}: {msg}", "en": "PROFINET set IP {mac} -> {ip}: {msg}",
                "zh": "PROFINET 修改IP {mac} -> {ip}: {msg}"},
    "blink_title": {"vi": "Nháy đèn", "en": "Blink LED", "zh": "闪烁指示灯"},
    "blink_ok": {"vi": "Đã gửi lệnh nháy đèn: ", "en": "Blink command sent: ", "zh": "已发送闪烁命令："},
    "exit_title": {"vi": "Thoát", "en": "Exit", "zh": "退出"},
    "exit_ask": {"vi": "Gỡ các IP phụ đã thêm lên card mạng trước khi thoát?\n(Yes = gỡ, No = giữ lại, Cancel = không thoát)",
                 "en": "Remove the temporary IPs added to the adapters before exiting?\n(Yes = remove, No = keep, Cancel = don't exit)",
                 "zh": "退出前移除已添加到网卡的临时IP吗？\n（是=移除，否=保留，取消=不退出）"},
    "npcap_title": {"vi": "Thiếu Npcap", "en": "Npcap missing", "zh": "缺少Npcap"},
    "npcap_help": {
        "vi": "Chưa cài Npcap – thư viện bắt gói tin mà IP Finder cần để dò thiết bị.\n\n"
              "Cách cài KHÔNG cần Internet trên máy này:\n"
              "  1. Trên máy có Internet, vào https://npcap.com/#download, tải 'Npcap 1.90 installer'\n"
              "     (một file npcap-1.90.exe dùng cho Windows 7/8/10/11, cả 32 và 64-bit).\n"
              "  2. Chép qua USB, chạy file đó (tick 'WinPcap API-compatible Mode').\n"
              "  3. Mở lại IP Finder.\n\n"
              "Mẹo: đặt npcap-1.90.exe cùng thư mục với bộ cài IP Finder, bộ cài sẽ tự cài Npcap.",
        "en": "Npcap is not installed – IP Finder needs this packet capture driver.\n\n"
              "To install WITHOUT Internet on this PC:\n"
              "  1. On a PC with Internet, open https://npcap.com/#download and get 'Npcap 1.90 installer'\n"
              "     (one npcap-1.90.exe for Windows 7/8/10/11, 32 and 64-bit).\n"
              "  2. Copy it by USB and run it (tick 'WinPcap API-compatible Mode').\n"
              "  3. Start IP Finder again.\n\n"
              "Tip: put npcap-1.90.exe in the same folder as the IP Finder setup and the setup installs it for you.",
        "zh": "未安装Npcap —— IP Finder需要此抓包驱动来查找设备。\n\n"
              "在本机无需联网的安装方法：\n"
              "  1. 在可上网的电脑上打开 https://npcap.com/#download，下载“Npcap 1.90 installer”\n"
              "     （一个 npcap-1.90.exe，适用于 Windows 7/8/10/11 的32位和64位）。\n"
              "  2. 用U盘拷贝并运行（勾选“WinPcap API-compatible Mode”）。\n"
              "  3. 重新打开 IP Finder。\n\n"
              "提示：把 npcap-1.90.exe 放在 IP Finder 安装程序同一文件夹中，安装程序会自动安装Npcap。"},
    "admin_title": {"vi": "Cần quyền Administrator", "en": "Administrator rights needed", "zh": "需要管理员权限"},
    "admin_msg": {"vi": "IP Finder cần chạy bằng quyền Administrator để bắt/gửi gói tin.\n"
                        "Đóng chương trình, chuột phải > Run as administrator.",
                  "en": "IP Finder must run as Administrator to capture/send packets.\n"
                        "Close it, then right-click > Run as administrator.",
                  "zh": "IP Finder需要以管理员身份运行才能抓包/发包。\n请关闭程序，右键 > 以管理员身份运行。"},
}
