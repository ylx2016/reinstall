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
  urldata=$(rm -rf /tmp/url.tmp && curl -o /tmp/url.tmp 'https://cf-image.ylx.workers.dev/images/oracle/7/amd64/cloud/?C=M;O=D' && grep -o '2.......[\_]..[\:]..' /tmp/url.tmp | head -n 1)
  IMGURL=https://cf-image.ylx.workers.dev/images/oracle/7/amd64/cloud/${urldata}/rootfs.tar.xz
  #IMGURL='https://us.images.linuxcontainers.org/images/oracle/7/amd64/cloud/20210225_11:39/rootfs.tar.xz'
  #IMGURL='https://github.com/ylx2016/reinstall/releases/download/docker-file/Ubuntu20_2021.2.27_rootfs.tar.xz'
  #https://us.images.linuxcontainers.org/images/ubuntu
  CN_IMGURL=https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/oracle/7/amd64/cloud/${urldata}/rootfs.tar.xz
  #BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
  #BUSYBOX='https://raw.githubusercontent.com/ylx2016/reinstall/master/busybox_1.32.1'
  #BUSYBOX='https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox'
  BUSYBOX='https://reinstall.pages.dev/busybox_1.35.0'
  CN_BUSYBOX='https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64'
elif [[ ${bit} == "aarch64" ]]; then
  urldata=$(rm -rf /tmp/url.tmp && curl -o /tmp/url.tmp 'https://cf-image.ylx.workers.dev/images/oracle/7/arm64/cloud/?C=M;O=D' && grep -o '2.......[\_]..[\:]..' /tmp/url.tmp | head -n 1)
  IMGURL=https://cf-image.ylx.workers.dev/images/oracle/7/arm64/cloud/${urldata}/rootfs.tar.xz
  #IMGURL='https://us.images.linuxcontainers.org/images/oracle/7/arm64/cloud/20210225_11:39/rootfs.tar.xz'
  #IMGURL='https://github.com/ylx2016/reinstall/releases/download/docker-file/Ubuntu20_2021.2.27_rootfs.tar.xz'
  CN_IMGURL=https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/oracle/7/arm64/cloud/${urldata}/rootfs.tar.xz
  #BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
  BUSYBOX='https://reinstall.pages.dev/busybox_arm64'
  CN_BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-armv8l'
else
  echo "此系统骨骼太清奇，不支持！"
  exit
fi

_exists() {
  local cmd="$1"
  if eval type type >/dev/null 2>&1; then
    eval type "$cmd" >/dev/null 2>&1
  elif command >/dev/null 2>&1; then
    command -v "$cmd" >/dev/null 2>&1
  else
    which "$cmd" >/dev/null 2>&1
  fi
  local rt=$?
  return ${rt}
}

err() {
  printf "\nError: %s.\n" "$1" 1>&2
  exit 1
}
download() {

  if _exists wget; then
    wget -O "$2" "$1"
  elif _exists curl; then
    curl -fL "$1" -o "$2"
  elif _exists busybox && busybox wget --help >/dev/null 2>&1; then
    busybox wget -O "$2" "$1"
  else
    err 'Cannot find "wget", "curl" or "busybox wget" to download files'
  fi
}

ROOTDIR

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
  rm -rf /etc/resolv.conf
  touch /etc/resolv.conf
  if [[ "$isCN" == '1' ]]; then
    dns_name1="114.114.114.114"
    dns_name2="223.5.5.5"
    echo "nameserver $dns_name1" >/etc/resolv.conf
    echo "nameserver $dns_name2" >>/etc/resolv.conf
    #mv /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.backup
    #mv /etc/yum.repos.d/epel-testing.repo /etc/yum.repos.d/epel-testing.repo.backup
    # mv /etc/yum.repos.d/CentOS-Base.repo{,.bak}
    # curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.163.com/.help/CentOS7-Base-163.repo
    # curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/Centos-7.repo
    yum install oracle-epel-release-el7.x86_64
  else
    dns_name1="1.1.1.1"
    dns_name2="8.8.8.8"
    echo "nameserver $dns_name1" >/etc/resolv.conf
    echo "nameserver $dns_name2" >>/etc/resolv.conf
    # echo "nameserver 9.9.9.9" >> /etc/resolv.conf
    yum install oracle-epel-release-el7.x86_64
  fi
  rm -f /root/anaconda-ks.cfg
  export LC_ALL=en_US.UTF-8
  yum makecache fast
  yum install -y grub2 grub2-common grub2-tools grub2-tools-extra grub2-tools-minimal grubby util-linux dhclient openssh-server passwd wget nano kernel htop coreutils net-tools

  device=$(fdisk -l | grep -o '/dev/*da' | head -1)
  if [[ ${sysefi} == "1" ]]; then
    cd /
    yum install grub2-efi grub2-efi-modules shim -y

    grub2-install --target=x86_64-efi --bootloader-id=centos --efi-directory=/boot/efi --verbose $device --boot-directory=/boot/efi
    grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
    touch /etc/default/grub
    sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
    sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub
    echo "GRUB_CMDLINE_LINUX=\"GRUB_TIMEOUT=5\"" >>/etc/default/grub
    echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >>/etc/default/grub
    grub2-mkconfig -o /boot/efi/EFI/centos/grub.cfg
    grub2-install --target=x86_64-efi --bootloader-id=centos --efi-directory=/boot/efi --verbose $device --boot-directory=/boot/efi
  elif [[ ${sysbios} == "1" ]]; then
    #if [[ "$isCN" == '1' ]];then
    #yum install -y https://download.fastgit.org/ylx2016/kernel/releases/download/cloud/kernel-5.10.3_cloud-1.x86_64.rpm
    #yum install -y https://download.fastgit.org/ylx2016/kernel/releases/download/cloud/kernel-headers-5.10.3_cloud-1.x86_64.rpm
    #else
    #	yum install -y https://github.com/ylx2016/kernel/releases/download/cloud/kernel-5.10.3_cloud-1.x86_64.rpm
    #	yum install -y https://github.com/ylx2016/kernel/releases/download/cloud/kernel-headers-5.10.3_cloud-1.x86_64.rpm
    #fi
    #yum install -y grub2
    cd /
    grub2-install $device
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null
    touch /etc/default/grub
    sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
    sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub
    echo "GRUB_CMDLINE_LINUX=\"GRUB_TIMEOUT=5\"" >>/etc/default/grub
    echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >>/etc/default/grub
    # echo -e "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" > /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null
    # grub2-install $device
  fi

  sed -i '/^#PermitRootLogin\s/s/.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  sed -i '/MaxAuthTries\s/s/.*/MaxAuthTries 3/' /etc/ssh/sshd_config
  sed -i '/GSSAPIAuthentication\s/s/.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
  sed -i '/ClientAliveInterval\s/s/.*/ClientAliveInterval 30/' /etc/ssh/sshd_config
  sed -i '/UseDNS\s/s/.*/UseDNS no/' /etc/ssh/sshd_config
  systemctl enable ssh

  echo -e "blog.ylx.me\nblog.ylx.me" | passwd "root"

  [ -n "$password" ] && echo -e "$password\n$password" | passwd "root"

  [ -n "$authorized_keys_url" ] && ! download "$authorized_keys_url" /dev/null &&
    err "Failed to download SSH authorized public keys from \"$authorized_keys_url\""

  [ -n "$authorized_keys_url" ] && mkdir -m 0700 -p /root/.ssh && wget -O /root/.ssh/authorized_keys $authorized_keys_url && sed -i '/PasswordAuthentication\s/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config

  [ -n "$ssh_port" ] && sed -i "/Port\s/s/.*/Port ${ssh_port}/" /etc/ssh/sshd_config

  echo "net.core.default_qdisc=fq" >>/etc/sysctl.d/99-sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf

  touch /etc/sysconfig/network

  if [ "$isAuto" == '1' ]; then
    cat >/etc/sysconfig/network-scripts/ifcfg-eth0 <<EOFILE
    DEVICE=eth0
    BOOTPROTO=static
    ONBOOT=yes
    IPADDR=$MAINIP
    GATEWAY=$GATEWAYIP
    NETMASK=$NETMASK
    DNS1=$dns_name1
    DNS2=$dns_name2
EOFILE
  else
    cat >/etc/sysconfig/network-scripts/ifcfg-eth0 <<EOFILE
    DEVICE=eth0
    BOOTPROTO=dhcp
    ONBOOT=yes
    NETWORKING_IPV6=yes
    IPV6_AUTOCONF=yes
    DNS1=$dns_name1
    DNS2=$dns_name2
EOFILE
  fi

  cat >>/etc/security/limits.conf <<EOFILE

    * soft nofile 65535
    * hard nofile 65535
    * soft nproc 65535
    * hard nproc 65535
EOFILE

  if [[ "$isCN" == '1' ]]; then
    echo "nameserver 114.114.114.114" >/etc/resolv.conf
    echo "nameserver 223.5.5.5" >>/etc/resolv.conf
  else
    echo "nameserver 1.1.1.1" >/etc/resolv.conf
    echo "nameserver 8.8.8.8" >>/etc/resolv.conf
    echo "nameserver 9.9.9.9" >>/etc/resolv.conf
  fi
  echo "precedence ::ffff:0:0/96 100" >>/etc/gai.conf
  echo "NETWORKING_IPV6=yes" >>/etc/sysconfig/network
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
