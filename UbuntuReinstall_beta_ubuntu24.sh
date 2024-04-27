#!/usr/bin/env bash
# 设置环境变量，确保脚本能正确使用系统命令
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 提醒用户更改默认密码。此处可以加强，强调安全性重要性
echo "注意：默认密码为 blog.ylx.me，请在安装后立即更改！"

#from bohanyang/debi 处理传进来的参数
while [ $# -gt 0 ]; do
  case $1 in

  --authorized-keys-url)
    authorized_keys_url=$2
    shift
    ;;
  --password)
    password=$2
    shift
    ;;
  --ssh-port)
    ssh_port=$2
    shift
    ;;
  --hostname)
    tmpHostName=$2
    shift
    ;;
  *)
    err "Unknown option: \"$1\""
    ;;
  esac
  shift
done

# 检查bash是否在/usr/bin/bash，如果不在，则创建链接
if [ ! -f "/usr/bin/bash" ]; then
  ln $(which bash) /usr/bin/bash
fi

# 检查并安装curl
if ! type curl >/dev/null 2>&1; then
  echo 'curl 未安装，正在安装...'
  apt-get update && apt-get install curl -y || yum install curl -y
else
  echo 'curl 已安装，继续'
fi

# 检查并安装wget
if ! type wget >/dev/null 2>&1; then
  echo 'wget 未安装，正在安装...'
  apt-get update && apt-get install wget -y || yum install curl -y
else
  echo 'wget 已安装，继续'
fi

# 检查并安装 zip 和 tar
if ! type zip >/dev/null 2>&1; then
  echo 'zip 未安装，正在安装...'
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install zip -y
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install zip -y
  else
    echo '未知的包管理器，请手动安装 zip。'
    exit 1
  fi
else
  echo 'zip 已安装，继续'
fi

if ! type tar >/dev/null 2>&1; then
  echo 'tar 未安装，正在安装...'
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install tar -y
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install tar -y
  else
    echo '未知的包管理器，请手动安装 tar。'
    exit 1
  fi
else
  echo 'tar 已安装，继续'
fi

# 定义变量以便于后续使用
my_wget=$(which wget)
my_curl=$(which curl)
my_mkdir=$(which mkdir)

# 根据系统架构下载不同的Debian镜像和BusyBox
bit=$(uname -m)
if [[ ${bit} == "x86_64" ]]; then
  urldata=$(rm -rf /tmp/url.tmp && curl -o /tmp/url.tmp 'https://cf-image.ylx.workers.dev/images/ubuntu/noble/amd64/cloud/?C=M;O=D' && grep -o 2.......[\_]..[\:].. /tmp/url.tmp | head -n 1)
  IMGURL=https://cf-image.ylx.workers.dev/images/ubuntu/noble/amd64/cloud/${urldata}/rootfs.tar.xz
  #IMGURL='https://us.images.linuxcontainers.org/images/ubuntu/noble/amd64/cloud/20210225_11:39/rootfs.tar.xz'
  #IMGURL='https://github.com/ylx2016/reinstall/releases/download/docker-file/Ubuntu20_2021.2.27_rootfs.tar.xz'
  #https://us.images.linuxcontainers.org/images/ubuntu
  CN_IMGURL=https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/ubuntu/noble/amd64/cloud/${urldata}/rootfs.tar.xz
  #BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
  #BUSYBOX='https://raw.githubusercontent.com/ylx2016/reinstall/master/busybox_1.32.1'
  #BUSYBOX='https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox'
  BUSYBOX='https://reinstall.pages.dev/busybox_1.35.0'
  CN_BUSYBOX='https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64'
elif [[ ${bit} == "aarch64" ]]; then
  urldata=$(rm -rf /tmp/url.tmp && curl -o /tmp/url.tmp 'https://cf-image.ylx.workers.dev/images/ubuntu/noble/arm64/cloud/?C=M;O=D' && grep -o 2.......[\_]..[\:].. /tmp/url.tmp | head -n 1)
  IMGURL=https://cf-image.ylx.workers.dev/images/ubuntu/noble/arm64/cloud/${urldata}/rootfs.tar.xz
  #IMGURL='https://us.images.linuxcontainers.org/images/ubuntu/noble/arm64/cloud/20210225_11:39/rootfs.tar.xz'
  #IMGURL='https://github.com/ylx2016/reinstall/releases/download/docker-file/Ubuntu20_2021.2.27_rootfs.tar.xz'
  CN_IMGURL=https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/ubuntu/noble/arm64/cloud/${urldata}/rootfs.tar.xz
  #BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
  BUSYBOX='https://reinstall.pages.dev/busybox_arm64'
  CN_BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv8l'
else
  echo "此系统骨骼太清奇，不支持！"
  exit
fi

# 设置下载根目录
ROOTDIR='/os'

# 下载系统镜像的函数
DOWNLOAD_IMG() {
  if command -v wget >/dev/null 2>&1; then
    mkdir -p $ROOTDIR
    if [[ "$isCN" == '1' ]]; then
      IMGURLstate=$(curl -k -s --head $CN_IMGURL | head -n 1)
      BUSYBOXstate=$(curl -k -s --head $CN_BUSYBOX | head -n 1)
    else
      IMGURLstate=$(curl -k -s --head $IMGURL | head -n 1)
      BUSYBOXstate=$(curl -k -s --head $BUSYBOX | head -n 1)
    fi
    if [[ ${IMGURLstate} != *200* ]]; then
      echo "镜像地址检查出错，退出！"
      exit 1
    fi
    if [[ ${BUSYBOXstate} != *200* && ${BUSYBOXstate} != *308* ]]; then
      echo "BUSYBOX地址检查出错，退出！"
      exit 1
    fi
    if [[ "$isCN" == '1' ]]; then
      wget --no-check-certificate -O "$ROOTDIR/os.tar.xz" $CN_IMGURL
      wget --no-check-certificate -O "$ROOTDIR/busybox" $CN_BUSYBOX
    else
      wget --no-check-certificate -O "$ROOTDIR/os.tar.xz" $IMGURL
      wget --no-check-certificate -O "$ROOTDIR/busybox" $BUSYBOX
    fi
    chmod +x "$ROOTDIR/busybox"
  else
    echo "ERROR: wget not found !"
    exit
  fi
}

# 删除所有旧系统文件的函数
DELALL() {
  cp /etc/fstab $ROOTDIR
  sysbios="0"
  sysefi="0"
  sysefifile=""
  if [ -d "/sys/firmware/efi" ]; then
    sysefi="1"
    # elif [ -f "/boot/efi/boot/grub/grub.cfg" ]; then
    # sysefi="1"
    # elif [ -f "/boot/efi/EFI/grub/grub.cfg" ]; then
    # sysefi="1"
    # elif [ -f "/boot/efi/EFI/ubuntu/grub.cfg" ]; then
    # sysefi="1"
    # elif [ -f "/boot/efi/EFI/debian/grub.cfg" ]; then
    # sysefi="1"
  else
    sysbios="1"
  fi

  if command -v chattr >/dev/null 2>&1; then
    find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) \
      -exec chattr -i {} + 2>/dev/null || true
  fi
  find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) -delete 2>/dev/null || true
}

# 解压新系统镜像的函数
EXTRACT_IMG() {
  xzcat="$ROOTDIR/busybox xzcat"
  tar="$ROOTDIR/busybox tar"
  $xzcat "$ROOTDIR/os.tar.xz" | $tar -x -C /
  mv -f $ROOTDIR/fstab /etc
}

# 初始化新系统的函数
INIT_OS() {
  cd /
  rm -rf /etc/resolv.conf
  touch /etc/resolv.conf
  if [[ "$isCN" == '1' ]]; then
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
    echo "nameserver 223.5.5.5" >>/etc/resolv.conf
    sed -i 's#http://deb.debian.org#http://mirrors.163.com#g' /etc/apt/sources.list
  else
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
    echo "nameserver 8.8.8.8" >>/etc/resolv.conf
    echo "nameserver 9.9.9.9" >>/etc/resolv.conf
  fi
  rm -f /root/anaconda-ks.cfg
  export LC_ALL=C.UTF-8
  apt-get update
  bit=$(uname -m)
  cd /
  DEBIAN_FRONTEND=noninteractive apt-get install -y systemd openssh-server passwd wget nano linux-image-generic linux-headers-generic htop net-tools isc-dhcp-client ifplugd ifupdown ifmetric ifscheme ethtool guessnet fdisk coreutils curl sudo -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
  DEBIAN_FRONTEND=noninteractive apt-get install -y grub2* -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"

  device=$(fdisk -l | grep -o /dev/*da | head -1)
  # 根据系统架构和启动方式安装GRUB
  if [[ ${sysefi} == "1" ]]; then
    echo "安装EFI模式的GRUB（架构：${bit}）"
    # 针对不同架构选择合适的GRUB EFI包
    if [[ ${bit} == "x86_64" ]]; then
      apt-get install -y grub-efi-amd64
    elif [[ ${bit} == "aarch64" ]]; then
      apt-get install -y grub2-common efivar grub-efi-arm64 efibootmgr
    else
      echo "不支持的架构：${bit}"
      exit 1
    fi

    # 安装GRUB到EFI分区并更新配置
    grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck
    update-grub

    # 特定于x86_64架构的后续操作
    if [[ ${bit} == "x86_64" ]]; then
      mkdir -p /boot/efi/EFI/boot
      cp /boot/efi/EFI/debian/grubx64.efi /boot/efi/EFI/boot/bootx64.efi
    fi
  elif [[ ${sysbios} == "1" ]]; then
    echo "安装BIOS模式的GRUB（设备：${device}）"
    apt-get install -y grub-pc
    grub-install --target=i386-pc ${device}
    update-grub
  else
    echo "无法确定系统的启动模式（EFI或BIOS）。"
    exit 1
  fi

  sed -i '/Port /d' /etc/ssh/sshd_config
  #echo "Port 52890" >>/etc/ssh/sshd_config
  sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
  sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
  sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
  sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 30/' /etc/ssh/sshd_config
  sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
  systemctl enable ssh

  echo -e "blog.ylx.me\nblog.ylx.me" | passwd "root"

  [ -n "$password" ] && echo -e "$password\n$password" | passwd "root"

  [ -n "$authorized_keys_url" ] && ! download "$authorized_keys_url" /dev/null &&
    err "Failed to download SSH authorized public keys from \"$authorized_keys_url\""

  [ -n "$authorized_keys_url" ] && mkdir -m 0700 -p /root/.ssh && wget -O /root/.ssh/authorized_keys $authorized_keys_url && sed -i '/PasswordAuthentication\s/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config

  [ -n "$ssh_port" ] && sed -i "/Port\s/s/.*/Port ${ssh_port}/" /etc/ssh/sshd_config

  echo "net.core.default_qdisc=fq_pie" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf

  sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
  echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >>/etc/default/grub
  $(which update-grub)

  systemctl enable networking
  # network_adapter_name=$( ls /sys/class/net | grep ens )
  network_adapter_name="eth0"

  if [ "$isAuto" == '1' ]; then
    cat >/etc/network/interfaces <<EOFILE
   auto lo
iface lo inet loopback

auto $network_adapter_name
iface $network_adapter_name inet static
address $MAINIP
netmask $NETMASK
gateway $GATEWAYIP
EOFILE
  else
    cat >/etc/network/interfaces <<EOFILE
   auto lo
iface lo inet loopback

auto $network_adapter_name
iface $network_adapter_name inet dhcp
iface $network_adapter_name inet6 dhcp
EOFILE
  fi

  cat >>/etc/security/limits.conf <<EOFILE

    * soft nofile 65535
    * hard nofile 65535
    * soft nproc 65535
    * hard nproc 65535
EOFILE

  $(which mkdir) -p /etc/systemd/system/networking.service.d/
  echo -e "[Service]\nTimeoutStartSec=15sec" >/etc/systemd/system/networking.service.d/timeout.conf

  # sed -i 's/4096/65535/' /etc/security/limits.d/20-nproc.conf
  if [[ "$isCN" == '1' ]]; then
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
    echo "nameserver 223.5.5.5" >>/etc/resolv.conf
  else
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
    echo "nameserver 8.8.8.8" >>/etc/resolv.conf
    echo "nameserver 9.9.9.9" >>/etc/resolv.conf
  fi
  echo "precedence ::ffff:0:0/96 100" >>/etc/gai.conf
  rm -rf /etc/hostname
  touch /etc/hostname

  [[ -n "$tmpHostName" ]] && HostName="$tmpHostName" || HostName=$(hostname)
  [[ -z "$HostName" || "$HostName" =~ "localhost" || "$HostName" =~ "localdomain" || "$HostName" == "random" ]] && HostName="instance-$(date "+%Y%m%d")-$(date "+%H%M")"

  echo "$HostName" >>/etc/hostname
  echo "127.0.0.1 $HostName" >>/etc/hosts
  $(which wget) -O /root/tcpx.sh "https://github.000060000.xyz/tcpx.sh" && $(which chmod) +x /root/tcpx.sh
  ln -fs /usr/bin/bash /usr/bin/sh
  cat >/etc/timezone <<EOFILE
Asia/Shanghai
EOFILE
  systemctl disable networkd-dispatcher.service
  systemctl disable unattended-upgrades.service

}

# 检查IP合法性的函数
function isValidIp() {
  local ip=$1
  local ret=1
  if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    ip=(${ip//\./ })
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    ret=$?
  fi
  return $ret
}

# 检查IP信息的函数
function ipCheck() {
  isLegal=0
  for add in $MAINIP $GATEWAYIP $NETMASK; do
    isValidIp $add
    if [ $? -eq 1 ]; then
      isLegal=1
    fi
  done
  return $isLegal
}

# 获取IP信息的函数
function GetIp() {
  MAINIP=$(ip route get 1 | awk -F 'src ' '{print $2}' | awk '{print $1}')
  GATEWAYIP=$(ip route | grep default | awk '{print $3}' | head -1)
  SUBNET=$(ip -o -f inet addr show | awk '/scope global/{sub(/[^.]+\//,"0/",$4);print $4}' | head -1 | awk -F '/' '{print $2}')
  value=$((0xffffffff ^ ((1 << (32 - $SUBNET)) - 1)))
  NETMASK="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"
}

# 更新IP信息的函数
function UpdateIp() {
  read -r -p "Your IP: " MAINIP
  read -r -p "Your Gateway: " GATEWAYIP
  read -r -p "Your Netmask: " NETMASK
}

# 设置网络的函数
function SetNetwork() {
  isCN='0'
  geoip=$(wget --no-check-certificate -qO- https://api.ip.sb/geoip -T 10 | grep "\"country_code\":\"CN\"")
  if [[ "$geoip" != "" ]]; then
    isCN='1'
  fi

  isAuto='0'
  if [[ -f '/etc/network/interfaces' ]]; then
    [[ ! -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && isAuto='1'
    [[ -d /etc/network/interfaces.d ]] && {
      cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' | wc -l)" || cfgNum='0'
      [[ "$cfgNum" -ne '0' ]] && {
        for netConfig in $(ls -1 /etc/network/interfaces.d/*.cfg); do
          [[ ! -z "$(cat $netConfig | sed -n '/iface.*inet static/p')" ]] && isAuto='1'
        done
      }
    }
  fi

  if [[ -d '/etc/sysconfig/network-scripts' ]]; then
    cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' | wc -l)" || cfgNum='0'
    [[ "$cfgNum" -ne '0' ]] && {
      for netConfig in $(ls -1 /etc/sysconfig/network-scripts/ifcfg-* | grep -v 'lo$' | grep -v ':[0-9]\{1,\}'); do
        [[ ! -z "$(cat $netConfig | sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p')" ]] && isAuto='1'
      done
    }
  fi
}

# 网络模式设置的函数
function NetMode() {

  if [ "$isAuto" == '0' ]; then
    read -p "设置网络为动态获取IP吗(DHCP) [Y/n] :" input
    [ -z "${input}" ] && input="y"
    case $input in
    [yY][eE][sS] | [yY]) NETSTR='' ;;
    [nN][oO] | [nN]) isAuto='1' ;;
    *)
      clear
      echo "Canceled by user!"
      exit 1
      ;;
    esac
  fi
  # isAuto='1'

  if [ "$isAuto" == '1' ]; then
    GetIp
    ipCheck
    if [ $? -ne 0 ]; then
      echo -e "Error occurred when detecting ip. Please input manually.\n"
      UpdateIp
    else

      echo "IP: $MAINIP"
      echo "Gateway: $GATEWAYIP"
      echo "Netmask: $NETMASK"
      echo -e "\n"
      read -p "Confirm? [Y/n] :" input
      [ -z "${input}" ] && input="y"
      case $input in
      [yY][eE][sS] | [yY]) ;;
      [nN][oO] | [nN])
        echo -e "\n"
        UpdateIp
        ipCheck
        [[ $? -ne 0 ]] && {
          clear
          echo -e "Input error!\n"
          exit 1
        }
        ;;
      *)
        clear
        echo "Canceled by user!"
        exit 1
        ;;
      esac
    fi
    NETSTR="--ip-addr ${MAINIP} --ip-gate ${GATEWAYIP} --ip-mask ${NETMASK}"
  fi
}

# 执行网络设置、下载、删除、解压和初始化操作

SetNetwork
NetMode

DOWNLOAD_IMG
DELALL
EXTRACT_IMG
INIT_OS

# 清理安装后的临时文件并提示重启
rm -rf $ROOTDIR
apt-get clean all
sync
echo "安装完成，建议重启系统。"

read -p "确认上面没有严重的错误信息，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
  echo -e "${Info} VPS 重启中..."
  reboot -f
fi
