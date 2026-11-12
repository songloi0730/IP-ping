#!/usr/bin/env bash
# Dựng / gỡ phòng thí nghiệm ảo để thử ipfinder trên Linux (cần root, iproute2).
#
#   NIC 1 "lab1" (PC: 10.50.0.1/24) - bridge, cắm 3 thiết bị:
#       dev1  192.168.100.100  (khác subnet, nằm trong dải 'quick')   -> tìm bằng quét ARP
#       dev2  172.31.77.9      (khác subnet, ngoài mọi dải mặc định)  -> tìm bằng DCP/EtherNet-IP/ARP thụ động
#       dev3  10.50.0.20       (cùng subnet, thiết bị đang chạy bình thường)
#   NIC 2 "lab2" (PC: 10.60.0.1/24) - cắm 1 thiết bị:
#       dev4  192.168.1.10     (khác subnet)
#
#   sudo tests/lab.sh up      # dựng
#   sudo tests/lab.sh down    # gỡ
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PIDS=/tmp/ipfinder-lab.pids

up() {
  ip link add lab1 type bridge && ip link set lab1 up
  ip addr add 10.50.0.1/24 dev lab1
  for n in 1 2 3; do
    ip netns add dev$n
    ip link add v${n}h type veth peer name v${n}d
    ip link set v${n}h master lab1 up
    ip link set v${n}d netns dev$n
    ip -n dev$n link set lo up
    ip -n dev$n link set v${n}d up
  done
  ip -n dev1 addr add 192.168.100.100/24 dev v1d
  ip -n dev2 addr add 172.31.77.9/24 dev v2d
  ip -n dev3 addr add 10.50.0.20/24 dev v3d

  ip netns add dev4
  ip link add lab2 type veth peer name v4d
  ip link set v4d netns dev4
  ip link set lab2 up
  ip addr add 10.60.0.1/24 dev lab2
  ip -n dev4 link set lo up
  ip -n dev4 link set v4d up
  ip -n dev4 addr add 192.168.1.10/24 dev v4d

  : > "$PIDS"
  ip netns exec dev2 python3 "$HERE/fake_device.py" --iface v2d --ip 172.31.77.9 --name rfid-reader-02 > /tmp/fake-dev2.log 2>&1 &
  echo $! >> "$PIDS"
  sleep 2
  echo "lab up"
}

down() {
  [ -f "$PIDS" ] && xargs -r kill < "$PIDS" 2>/dev/null || true
  rm -f "$PIDS"
  for n in 1 2 3 4; do ip netns del dev$n 2>/dev/null || true; done
  ip link del lab1 2>/dev/null || true
  ip link del lab2 2>/dev/null || true
  echo "lab down"
}

"${1:-up}"
