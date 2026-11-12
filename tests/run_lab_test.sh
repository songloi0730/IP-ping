#!/usr/bin/env bash
# Kiểm thử tự động ipfinder trên phòng lab ảo (Linux, cần root). Dùng trong CI.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
OUT="$(mktemp -d)"
FAIL=0
# Lệnh chạy ipfinder: mặc định là script Python; đặt IPF=dist/ipfinder-cli để test bản đóng gói PyInstaller
IPF="${IPF:-python3 $ROOT/ipfinder.py}"
trap '"$HERE/lab.sh" down >/dev/null 2>&1; rm -rf "$OUT"' EXIT

check() {  # check <mô tả> <lệnh>
  if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; FAIL=1; fi
}

"$HERE/lab.sh" down >/dev/null 2>&1
"$HERE/lab.sh" up

echo "--- find trên 2 NIC (chủ động + thụ động)"
$IPF find -i lab1 -i lab2 -t 20 --rate 1000 -q --out "$OUT/r.json" | tee "$OUT/find.txt"
check "dev1 192.168.100.100 (quét ARP, khác subnet)" "grep -q '\"192.168.100.100\"' $OUT/r.json"
check "dev2 172.31.77.9 (PROFINET DCP)"            "grep -q 'PROFINET DCP' $OUT/r.json && grep -q '\"172.31.77.9\"' $OUT/r.json"
check "dev2 tên qua EtherNet/IP"                     "grep -q 'EIP:rfid-reader-02' $OUT/r.json"
check "dev3 10.50.0.20 (cùng subnet)"                "grep -q '\"10.50.0.20\"' $OUT/r.json"
check "dev4 192.168.1.10 trên NIC thứ 2"             "python3 -c \"import json,sys;d=json.load(open('$OUT/r.json'));sys.exit(0 if any(x['nic']=='lab2' and '192.168.1.10' in x['ips'] for x in d['devices']) else 1)\""

echo "--- nghe thụ động: gratuitous ARP từ IP ngoài mọi dải quét"
ip -n dev1 addr flush dev v1d && ip -n dev1 addr add 10.99.88.77/24 dev v1d
( sleep 3; ip netns exec dev1 arping -c 2 -U -I v1d 10.99.88.77 >/dev/null 2>&1 ) &
$IPF find -i lab1 --passive -t 8 -q --out "$OUT/p.json" >/dev/null
wait
check "dev1 10.99.88.77 (gratuitous ARP)" "grep -q 'Gratuitous ARP' $OUT/p.json && grep -q '\"10.99.88.77\"' $OUT/p.json"

echo "--- access: thêm IP phụ và kiểm tra ARP"
$IPF access -i lab1 --ip 10.99.88.77 --apply | tee "$OUT/a.txt"
check "access thêm IP & thiết bị trả lời" "grep -q 'TRẢ LỜI ARP' $OUT/a.txt && ip addr show lab1 | grep -q 10.99.88.254"
$IPF access -i lab1 --ip 10.99.88.77 --remove 10.99.88.254 --apply >/dev/null
check "access gỡ IP phụ" "! ip addr show lab1 | grep -q 10.99.88.254"
check "access chặn khi trùng subnet NIC khác" "! $IPF access -i lab1 --ip 10.60.0.77 --apply >/dev/null 2>&1"

echo "--- PROFINET DCP blink / set IP"
MAC2=$(ip netns exec dev2 cat /sys/class/net/v2d/address)
check "dcp-blink" "$IPF dcp-blink -i lab1 --mac $MAC2 | grep -q OK"
check "dcp-setip" "$IPF dcp-setip -i lab1 --mac $MAC2 --ip 10.50.0.42 -y | grep -q 'THÀNH CÔNG'"
check "IP mới có hiệu lực" "ip netns exec dev2 ip addr show v2d | grep -q 10.50.0.42"

[ $FAIL -eq 0 ] && echo "TẤT CẢ ĐỀU PASS" || echo "CÓ LỖI"
exit $FAIL
