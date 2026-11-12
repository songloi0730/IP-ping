IP Finder {VER} - GOI CAI DAT OFFLINE / OFFLINE PACKAGE / 离线安装包
==========================================================================

[TIẾNG VIỆT]
Gói này cài IP Finder lên máy KHÔNG có Internet, KHÔNG cần Python (Windows 7 SP1 - 11, 64-bit).

1. Npcap (driver bắt gói tin, bắt buộc - chỉ cần làm 1 lần):
   - Trên máy CÓ Internet: chạy Download-Npcap.bat trong thư mục này
     (hoặc vào https://npcap.com/#download, bấm "Npcap 1.90 installer").
   - File npcap-1.90.exe phải nằm CÙNG THƯ MỤC với IPFinder-Setup-{VER}.exe.
   - Nếu máy đích đã cài Wireshark/Npcap thì bỏ qua bước này.
   - Lưu ý giấy phép: Npcap bản miễn phí chỉ được cài trên tối đa 5 máy và không được phân phối ra ngoài.
     Cần cài nhiều hơn 5 máy thì phải mua Npcap OEM (Npcap kèm Wireshark cũng tính vào giới hạn này khi dùng với IP Finder).
2. Chép cả thư mục này sang máy đích bằng USB.
3. Chạy IPFinder-Setup-{VER}.exe -> chọn ngôn ngữ -> Next. Bộ cài tự cài Npcap nếu máy chưa có.
4. Mở "IP Finder" trên Desktop (tự xin quyền Administrator). Đổi ngôn ngữ ở góc trên bên phải.
Không muốn cài: dùng thư mục Portable\IPFinder\IPFinder.exe (vẫn cần Npcap).
Windows 7 báo thiếu api-ms-win-crt-*.dll: cài bản cập nhật KB2999226 của Microsoft.

[ENGLISH]
This package installs IP Finder on a PC WITHOUT Internet; no Python needed (Windows 7 SP1 - 11, 64-bit).

1. Npcap (packet capture driver, required - once):
   - On a PC WITH Internet: run Download-Npcap.bat in this folder
     (or open https://npcap.com/#download and click "Npcap 1.90 installer").
   - npcap-1.90.exe must be in the SAME FOLDER as IPFinder-Setup-{VER}.exe.
   - Skip this if the target PC already has Wireshark/Npcap.
   - License: the free Npcap edition may be installed on up to 5 systems and must not be redistributed.
     For more than 5 systems you need Npcap OEM (Npcap installed with Wireshark also counts when used by IP Finder).
2. Copy this whole folder to the target PC by USB.
3. Run IPFinder-Setup-{VER}.exe -> choose a language -> Next. Setup installs Npcap if it is missing.
4. Open "IP Finder" on the desktop (it asks for Administrator rights). Change language at the top right.
No install: use Portable\IPFinder\IPFinder.exe (Npcap still required).
Windows 7 missing api-ms-win-crt-*.dll: install Microsoft update KB2999226.

[中文]
本离线包可在无网络、无需安装 Python 的电脑上安装 IP Finder（Windows 7 SP1 - 11，64位）。

1. Npcap（抓包驱动，必需，只需一次）：
   - 在可上网的电脑上运行本文件夹中的 Download-Npcap.bat
     （或打开 https://npcap.com/#download，点击“Npcap 1.90 installer”）。
   - npcap-1.90.exe 必须与 IPFinder-Setup-{VER}.exe 放在同一文件夹。
   - 目标电脑已安装 Wireshark/Npcap 则可跳过。
   - 许可：Npcap 免费版最多可安装在 5 台电脑上，且不得对外分发。超过 5 台需购买 Npcap OEM（随 Wireshark 安装的 Npcap 被 IP Finder 使用时同样计入此限制）。
2. 用U盘把整个文件夹拷贝到目标电脑。
3. 运行 IPFinder-Setup-{VER}.exe -> 选择语言 -> 下一步。若缺少 Npcap，安装程序会自动安装。
4. 打开桌面上的“IP Finder”（会请求管理员权限）。可在右上角切换语言。
免安装：使用 Portable\IPFinder\IPFinder.exe（仍需 Npcap）。
Windows 7 提示缺少 api-ms-win-crt-*.dll：请安装微软更新 KB2999226。
