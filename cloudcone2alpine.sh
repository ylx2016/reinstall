#!/bin/sh
## cloudcone专用版，ovz6、ovz7、kvm请使用对应版本
## Telegram 群组: https://t.me/vpsqun

logfile="/tmp/kvm-alpine.log"
if [ "$1" = "--step-chroot" ]; then
  printf "" > "$logfile"
  printf "  Installing packages..." >&2
  if ! apk add --no-cache alpine-base linux-virt syslinux grub grub-bios e2fsprogs eudev openssh rng-tools rng-tools-openrc >>"$logfile" 2>>"$logfile"; then
    echo
    exit 1
  fi
  echo " Done" >&2
  printf "  Configuring services..." >&2
#系统自启动服务，根据需要修改
#  rc-update add --quiet hostname boot
  rc-update add --quiet networking boot
#  rc-update add --quiet urandom boot
  rc-update add --quiet crond default
#  rc-update add --quiet swap boot
  rc-update add --quiet udev sysinit
  rc-update add --quiet udev-trigger sysinit
  rc-update add --quiet sshd default
#  rc-update add --quiet rngd boot
  sed -i -r -e 's/^(tty[2-6]:)/#\1/' /etc/inittab
  echo " Done" >&2
  printf "  Installing bootloader..." >&2
#定义grub安装的磁盘以及root的mount分区，part变量下面用到
disk=$(fdisk -l|grep Disk|awk '{print $2}'|awk -F: '{print $1}')
part=$(fdisk -l|grep Linux|sed -n '1p'|awk '{print $1}')
  if ! grub-install $disk >>"$logfile" 2>>"$logfile"; then
    echo
    exit 1
  fi
  if ! grub-mkconfig -o /boot/grub/grub.cfg >>"$logfile" 2>>"$logfile"; then
    echo
    exit 1
  fi
  sync
  echo " Done" >&2
  rm -f "$0"
  ln -sf /boot/grub/ /boot/grub2
  exit 0
fi
SCRIPTPATH="$(realpath "$0")"
#如果有更新，自行替换新版本文件
printf "Downloading Alpine" >&2
if ! wget -q -O /tmp/rootfs.tar.gz http://dl-cdn.alpinelinux.org/alpine/edge/releases/x86_64/alpine-minirootfs-3.12.0-x86_64.tar.gz; then
  echo " Failed!" >&2
  exit 1
fi
echo " Done" >&2
printf "Creating mount points..." >&2
umount -a >/dev/null 2>&1
mount -o rw,remount --make-rprivate $part /
mkdir /tmp/tmpalpine
mount none /tmp/tmpalpine -t tmpfs
echo " Done" >&2
printf "Extracting Alpine..." >&2
tar xzf /tmp/rootfs.tar.gz -C /tmp/tmpalpine
cp "$SCRIPTPATH" /tmp/tmpalpine/tmp/kvm-alpine.sh
echo " Done" >&2
printf "Copying existing droplet configuration..." >&2
cp /etc/fstab /tmp/tmpalpine/etc
cp /etc/hostname /tmp/tmpalpine/etc
cp /etc/resolv.conf /tmp/tmpalpine/etc
grep -v ^root: /tmp/tmpalpine/etc/shadow > /tmp/tmpalpine/etc/shadow.bak
mv /tmp/tmpalpine/etc/shadow.bak /tmp/tmpalpine/etc/shadow
grep ^root: /etc/shadow >> /tmp/tmpalpine/etc/shadow
mkdir -p /tmp/tmpalpine/etc/ssh
cp -r /etc/ssh/ssh_host_* /tmp/tmpalpine/etc/ssh
cp -r /root/.ssh /tmp/tmpalpine/root
apt install net-tools -y
#设置固定ip，网卡eth0，根据实际需要修改,alpine识别eth0和centos一样，vultr下debian识别是ens3
#如果网卡不是ifconfig第一选项，可以指定ifconfig $dev
dev=eth0
ip=$(ifconfig |grep inet| sed -n '1p'|awk '{print $2}')
mask=$(ifconfig |grep inet| sed -n '1p'|awk '{print $4}')
gw=$(ip route |grep default|awk '{print $3}')
cat > /tmp/tmpalpine/etc/network/interfaces << EOF
auto lo
iface lo inet loopback
 
auto $dev
iface $dev inet static
    address $ip
    netmask $mask
    gateway $gw
EOF
echo " Done" >&2
printf "Changing to new root..." >&2
mkdir /tmp/tmpalpine/oldroot
pivot_root /tmp/tmpalpine /tmp/tmpalpine/oldroot
cd / || exit 1
echo " Done" >&2
printf "Rebuilding file systems..." >&2
echo PermitRootLogin yes >> /etc/ssh/sshd_config
mount --move /oldroot/dev /dev
mount --move /oldroot/proc /proc
mount --move /oldroot/sys /sys
mount --move /oldroot/run /run
rm -rf /oldroot/*
cp -r /bin /etc /home /lib/ /media /mnt/ /root /sbin /srv /tmp /usr /var /oldroot
mkdir /oldroot/dev /oldroot/proc /oldroot/sys /oldroot/run
mount -t proc proc /oldroot/proc
mount -t sysfs sys /oldroot/sys
mount -o bind /dev /oldroot/dev
echo " Done" >&2
echo "chroot configuration..." >&2
if ! chroot /oldroot /bin/ash /tmp/kvm-alpine.sh --step-chroot; then
  echo "ERROR: could not install Alpine Linux. See /oldroot$logfile" >&2
  exit 1
fi
echo "Rebooting system. You should be able to reconnect shortly." >&2

reboot
sleep 1
reboot
