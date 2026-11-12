# IP Finder – dò IP thiết bị công nghiệp khi không biết IP, không reset được

Công cụ cho máy tính công nghiệp (IPC) cắm nhiều thiết bị qua Ethernet: đầu đọc mã vạch,
đầu đọc RFID, camera, PLC, module I/O... Dùng khi thiết bị cũ hoặc thiết bị lấy từ kho
**có IP không rõ**, **không có nút reset**, và IP mặc định không dùng được.

Thiết bị có IP ở **lớp mạng khác** (VD PC là `10.50.0.x`, thiết bị là `192.168.100.100`)
thì ping, Angry IP Scanner hay `arp -a` đều không thấy. IP Finder làm việc ở **tầng Ethernet (L2)**
ngay trên card mạng (NIC) cắm thiết bị, nên **không cần cùng subnet**.

## Cách hoạt động

| Kỹ thuật | Tìm được | Ghi chú |
|---|---|---|
| **Nghe thụ động** ARP / Gratuitous ARP / ARP probe | Mọi thiết bị IPv4 | Hầu hết thiết bị gửi gratuitous ARP khi **bật nguồn** hoặc **cắm lại cáp**, nên cách này bắt được IP **bất kỳ**, kể cả IP lạ nhất |
| Nghe DHCP/BOOTP | Thiết bị đang ở chế độ DHCP | Báo "DHCP – CHƯA CÓ IP" kèm hostname, vendor class |
| Nghe LLDP | Thiết bị có LLDP (PROFINET bắt buộc có) | Lấy tên, mô tả, IP quản lý |
| **PROFINET DCP** Identify All | Siemens, SICK, Balluff, Turck, Pepperl+Fuchs... | Multicast L2, trả về IP / mask / tên trạm |
| **EtherNet/IP** ListIdentity | Cognex, Keyence, Datalogic, Omron, Rockwell... | Trả về IP, tên sản phẩm, serial |
| Ping broadcast | Một số thiết bị | |
| **Quét ARP** các dải IP mặc định phổ biến (`quick`), cả `192.168.0.0/16` (`192`), hoặc dải tự chọn | Thiết bị có IP nằm trong dải quét | Thiết bị vẫn trả lời ARP dù khác subnet |

### An toàn khi máy đang chạy sản xuất

- **Không giả mạo IP** của máy khác. Gói ARP chỉ dùng IP thật của NIC hoặc `0.0.0.0` (ARP probe),
  nên **không làm hỏng bảng ARP** của PLC/thiết bị đang chạy.
- Giới hạn tốc độ gửi (mặc định 500 gói/giây, chỉnh bằng `--rate`).
- Chỉ chạy trên NIC bạn chọn. Có chế độ `--passive` (chỉ nghe, **không gửi gói nào**).
- Lệnh `access` chỉ **thêm IP phụ**, không đổi IP chính của NIC. Lệnh này **từ chối chạy** nếu subnet
  mới trùng với NIC khác (để không phá định tuyến tới thiết bị khác).

## Cài đặt

### Windows (thường gặp trên IPC)
1. Cài **Npcap**: https://npcap.com (tick *"Install Npcap in WinPcap API-compatible Mode"*).
2. Chọn một trong hai cách:
   - **Không cần Python**: tải `ipfinder.exe` ở tab **Actions** của repo → lần chạy mới nhất →
     *Artifacts* → `ipfinder-windows`. Double-click để chạy (exe tự xin quyền Administrator).
   - **Có Python 3.8+**: `pip install -r requirements.txt`, rồi chạy `run_windows.bat`
     bằng *Run as administrator*.

### Linux
```bash
sudo pip install -r requirements.txt
sudo python3 ipfinder.py
```

## Sử dụng nhanh

**Cách dễ nhất**: chạy không có tham số (hoặc double-click `ipfinder.exe`). Chương trình sẽ hỏi lần lượt
card mạng, thời gian và dải quét.

**Quy trình khuyên dùng khi tìm 1 thiết bị:**
1. Cắm thiết bị vào NIC của IPC (trực tiếp hoặc qua switch).
2. `ipfinder ifaces` → xem số thứ tự của card.
3. `ipfinder find --iface 12 --time 60`
4. **Trong lúc dò, TẮT/BẬT NGUỒN thiết bị (hoặc rút/cắm lại cáp)** → thiết bị sẽ tự báo IP.
5. Tìm dòng **KHÁC SUBNET** trong kết quả → đó thường là thiết bị cần tìm.
6. Vào được thiết bị: `ipfinder access --iface 12 --ip 192.168.100.100 --apply`
   → mở web/tool của hãng để đổi IP → gỡ IP phụ bằng lệnh mà chương trình in ra.

Ví dụ kết quả:
```
NIC          MAC               IP                  TRẠNG THÁI         HÃNG / TÊN
---------------------------------------------------------------------------------------------
Ethernet 2   00:d0:24:12:34:56 192.168.100.100     KHÁC SUBNET        Cognex Corporation | EIP:DM262
Ethernet 2   00:1b:1b:aa:bb:cc 172.31.77.9         KHÁC SUBNET        Siemens AG | PN:rf-reader-02
Ethernet 2   00:01:fc:01:02:03 thử 10.11.12.13     DHCP - CHƯA CÓ IP  Keyence Corporation
Ethernet 2   00:06:77:0a:0b:0c 10.50.0.20          cùng subnet        Sick Ag
```

## Các lệnh

```text
ipfinder ifaces                                  Liệt kê NIC, IP/subnet; cảnh báo subnet trùng giữa các NIC
ipfinder find   --iface <số|tên|MAC|all> [...]   Dò thiết bị
ipfinder access --iface X --ip <IP thiết bị>     Thêm IP phụ tạm để truy cập thiết bị khác subnet
ipfinder dcp-setip --iface X --mac M --ip ...    Đổi IP thiết bị PROFINET trực tiếp (không cần cùng subnet)
ipfinder dcp-blink --iface X --mac M             Nháy đèn thiết bị PROFINET để nhận ra nó trên tủ điện
```

### Tuỳ chọn của `find`
| Tuỳ chọn | Ý nghĩa |
|---|---|
| `--iface X` (lặp lại được), `--iface all` | Dò song song trên nhiều NIC / nhiều lớp mạng; kết quả ghi rõ NIC |
| `--time 60` | Thời gian dò (giây) |
| `--passive` | Chỉ nghe, không gửi gì (an toàn tuyệt đối cho mạng sản xuất) |
| `--preset quick\|192\|wide\|none` | Dải quét ARP. `quick` ≈ 7.000 IP (~15 giây), `192` = 65.000 IP (~2 phút), `wide` ≈ 390.000 IP |
| `--range 10.20.0.0/16`, `--range 192.168.7.10-50` | Thêm dải quét |
| `--arp-src own\|probe\|both` | IP nguồn của gói ARP. Nếu thiết bị không trả lời, thử `probe` hoặc `both` |
| `--rate 500` | Số gói/giây tối đa |
| `--mac 00:d0:24` | Chỉ hiện MAC bắt đầu bằng... (MAC in trên tem thiết bị) |
| `--save base.json` / `--diff base.json` | Lưu danh sách thiết bị hiện có, lần sau đánh dấu **[MỚI]** thiết bị vừa cắm vào |
| `--out ketqua.csv` / `.json` | Xuất kết quả |
| `--no-arp --no-dcp --no-enip --no-icmp` | Tắt từng kỹ thuật |

### IPC có nhiều thiết bị trên cùng mạng

Khi switch đang có nhiều thiết bị, kết quả sẽ liệt kê tất cả. Để biết thiết bị nào mới cắm:

```bash
ipfinder find --iface 12 --time 30 --save base.json      # trước khi cắm thiết bị
# ... cắm thiết bị cần tìm ...
ipfinder find --iface 12 --time 60 --diff base.json      # thiết bị mới có nhãn [MỚI]
```

Hoặc lọc theo MAC in trên tem: `--mac 00:d0:24:12`. Cột *HÃNG* tra theo OUI của địa chỉ MAC.

## Xử lý sự cố

| Hiện tượng | Cách xử lý |
|---|---|
| Không thấy NIC / lỗi pcap trên Windows | Cài Npcap, chạy bằng **Administrator** |
| Thấy MAC nhưng "CHƯA THẤY IPv4" | Bật/tắt nguồn thiết bị trong lúc dò; thử `--preset 192 --arp-src both` |
| "DHCP – CHƯA CÓ IP" | Thiết bị đang chờ DHCP. Cần chạy DHCP/BOOTP server trên NIC đó (tool BOOTP của hãng, Tftpd64, dnsmasq) để cấp IP |
| `access` báo lỗi trên Windows | Windows chỉ cho thêm IP phụ khi card dùng **IP tĩnh**. Đặt IP tĩnh cho card trước |
| `access` báo trùng subnet NIC khác | Rút tạm cáp của NIC kia, hoặc dùng `--prefix 30` để thu hẹp subnet IP phụ |
| Thiết bị cắm qua switch có VLAN | Cắm thiết bị thẳng vào NIC hoặc vào port cùng VLAN |
| `dcp-setip` báo "Không được phép" | Thiết bị đang có kết nối PROFINET với PLC. Ngắt kết nối PLC trước |

## Công cụ có sẵn khác (tham khảo)

- [royhills/arp-scan](https://github.com/royhills/arp-scan) (Linux): quét ARP L2, `arp-scan -I eth1 192.168.0.0/16`.
- [netdiscover-scanner/netdiscover](https://github.com/netdiscover-scanner/netdiscover) (Linux): `netdiscover -p` để nghe ARP thụ động.
- **Wireshark**: lọc `arp || bootp || lldp || pn_dcp || enip` rồi bật/tắt nguồn thiết bị.
- Tool của hãng: Siemens PRONETA / Primary Setup Tool (PROFINET), Cognex DataMan Setup Tool,
  Keyence AutoID Navigator, SICK SOPAS ET, Datalogic DL.CODE, Rockwell BOOTP/DHCP Server.

IP Finder gom các cách trên vào một chương trình chạy được trên Windows, dò được nhiều NIC cùng lúc,
và có thêm bước truy cập/đổi IP.

## Kiểm thử

`tests/run_lab_test.sh` (Linux, root) tạo một mạng ảo gồm 2 NIC và 4 thiết bị giả lập
(khác subnet, ngoài mọi dải mặc định, có PROFINET DCP / EtherNet/IP, cùng subnet), rồi kiểm tra
`find`, chế độ nghe thụ động, `access`, `dcp-blink` và `dcp-setip`. CI chạy test này mỗi lần push
và build `ipfinder.exe` cho Windows.

> Lưu ý: phần PROFINET DCP / EtherNet/IP mới được kiểm thử với thiết bị giả lập theo đặc tả,
> chưa chạy thử trên thiết bị thật.
