#!/bin/bash

# Default Password: blog.ylx.me , Change it after installation ! By dansnow and YLX

IMGURL='https://github.com/debuerreotype/docker-debian-artifacts/raw/dist-amd64/bullseye/rootfs.tar.xz'
CN_IMGURL='https://raw.sevencdn.com/debuerreotype/docker-debian-artifacts/dist-amd64/bullseye/rootfs.tar.xz'
BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
CN_BUSYBOX='https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64'
ROOTDIR='/os'

DOWNLOAD_IMG(){
    if command -v wget >/dev/null 2>&1 ;then
        mkdir $ROOTDIR
		if [[ "$isCN" == '1' ]];then
			wget -O "$ROOTDIR/os.tar.xz" $CN_IMGURL
			wget -O "$ROOTDIR/busybox" $CN_BUSYBOX
		else
			wget -O "$ROOTDIR/os.tar.xz" $IMGURL
			wget -O "$ROOTDIR/busybox" $BUSYBOX
		fi
        chmod +x "$ROOTDIR/busybox"
    else
        echo "ERROR: wget not found !"
        exit
    fi
}

DELALL(){
    cp /etc/fstab $ROOTDIR
	sysbios="0"
	sysefi="0"
	sysefifile=""
	if [ -f "/boot/efi/EFI/BOOT/grub.cfg" ]; then
		sysefi="1"
	elif [ -f "/boot/efi/boot/grub/grub.cfg" ]; then
		sysefi="1"
	elif [ -f "/boot/efi/EFI/ubuntu/grub.cfg" ]; then
		sysefi="1"
	elif [ -f "/boot/efi/EFI/debian/grub.cfg" ]; then
		sysefi="1"	
	else
		sysbios="1"
	fi
    if command -v chattr >/dev/null 2>&1; then
        find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) \
            -exec chattr -i {} + 2>/dev/null || true
    fi
    find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) -delete 2>/dev/null || true
}

EXTRACT_IMG(){
    xzcat="$ROOTDIR/busybox xzcat"
    tar="$ROOTDIR/busybox tar"
    $xzcat "$ROOTDIR/os.tar.xz" | $tar -x -C /
    mv -f $ROOTDIR/fstab /etc
}

INIT_OS(){
	if [[ "$isCN" == '1' ]];then
		echo "nameserver 114.114.114.114" > /etc/resolv.conf
		echo "nameserver 223.5.5.5" >> /etc/resolv.conf
		sed -i 's#http://deb.debian.org#http://mirrors.163.com#g' /etc/apt/sources.list
	else
		echo "nameserver 1.1.1.1" > /etc/resolv.conf
		echo "nameserver 8.8.8.8" >> /etc/resolv.conf
		echo "nameserver 9.9.9.9" >> /etc/resolv.conf
	fi
    rm -f /root/anaconda-ks.cfg
    export LC_ALL=C.UTF-8
    apt-get update
	apt-get install -y systemd openssh-server passwd wget nano linux-image-amd64 htop net-tools isc-dhcp-client ifplugd ifupdown ifmetric ifscheme ethtool guessnet fdisk coreutils curl sudo
	DEBIAN_FRONTEND=noninteractive apt-get install -y grub2* -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
	
	device=$(fdisk -l | grep -o /dev/*da | head -1)
	if [[ ${sysefi} == "1" ]];then
		cd /
		apt-get install -y grub-efi grub-efi-amd64
		grub-install
		update-grub
		cd /boot/efi/EFI && mkdir boot && cp debian/grubx64.efi boot/bootx64.efi
		cd /
	elif [[ ${sysbios} == "1" ]];then
		cd /
		grub-install $device
		/usr/sbin/update-grub
		grub-install $device
	fi
	
	sed -i '/Port /d' /etc/ssh/sshd_config
	echo "Port 52890" >> /etc/ssh/sshd_config
    	sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
    	sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    	sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
    	sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 30/' /etc/ssh/sshd_config
    	sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
    	systemctl enable ssh

	echo -e "blog.ylx.me\nblog.ylx.me" |passwd "root"
	
	echo "net.core.default_qdisc=fq_pie" >> /etc/sysctl.d/99-sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-sysctl.conf		

    	sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
	echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >> /etc/default/grub
	/usr/sbin/update-grub
	
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
EOFILE
	fi

    cat >>/etc/security/limits.conf<<EOFILE

    * soft nofile 65535
    * hard nofile 65535
    * soft nproc 65535
    * hard nproc 65535
EOFILE
    # sed -i 's/4096/65535/' /etc/security/limits.d/20-nproc.conf
   if [[ "$isCN" == '1' ]];then
		echo "nameserver 114.114.114.114" > /etc/resolv.conf
		echo "nameserver 223.5.5.5" >> /etc/resolv.conf
	else
		echo "nameserver 1.1.1.1" > /etc/resolv.conf
		echo "nameserver 8.8.8.8" >> /etc/resolv.conf
		echo "nameserver 9.9.9.9" >> /etc/resolv.conf
	fi
	hostnamectl set-hostname ylx2016
	echo "127.0.0.1 ylx2016" >> /etc/hosts
    	wget -O /root/tcpx.sh "https://github.000060000.xyz/tcpx.sh" && /bin/chmod +x /root/tcpx.sh
	
}

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

function GetIp() {
  MAINIP=$(ip route get 1 | awk -F 'src ' '{print $2}' | awk '{print $1}')
  GATEWAYIP=$(ip route | grep default | awk '{print $3}' | head -1)
  SUBNET=$(ip -o -f inet addr show | awk '/scope global/{sub(/[^.]+\//,"0/",$4);print $4}' | head -1 | awk -F '/' '{print $2}')
  value=$(( 0xffffffff ^ ((1 << (32 - $SUBNET)) - 1) ))
  NETMASK="$(( (value >> 24) & 0xff )).$(( (value >> 16) & 0xff )).$(( (value >> 8) & 0xff )).$(( value & 0xff ))"
}

function UpdateIp() {
  read -r -p "Your IP: " MAINIP
  read -r -p "Your Gateway: " GATEWAYIP
  read -r -p "Your Netmask: " NETMASK
}

function SetNetwork() {
	isCN='0'
	geoip=$(wget --no-check-certificate -qO- https://api.ip.sb/geoip -T 10 | grep "\"country_code\":\"CN\"")
	if [[ "$geoip" != "" ]];then
		isCN='1'
	fi

  isAuto='0'
  if [[ -f '/etc/network/interfaces' ]];then
    [[ ! -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && isAuto='1'
    [[ -d /etc/network/interfaces.d ]] && {
      cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
      [[ "$cfgNum" -ne '0' ]] && {
        for netConfig in `ls -1 /etc/network/interfaces.d/*.cfg`
        do 
          [[ ! -z "$(cat $netConfig | sed -n '/iface.*inet static/p')" ]] && isAuto='1'
        done
      }
    }
  fi
  
  if [[ -d '/etc/sysconfig/network-scripts' ]];then
    cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' |wc -l)" || cfgNum='0'
    [[ "$cfgNum" -ne '0' ]] && {
      for netConfig in `ls -1 /etc/sysconfig/network-scripts/ifcfg-* | grep -v 'lo$' | grep -v ':[0-9]\{1,\}'`
      do 
        [[ ! -z "$(cat $netConfig | sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p')" ]] && isAuto='1'
      done
    }
  fi
}

function NetMode() {

  if [ "$isAuto" == '0' ]; then
    read -p "设置网络为动态获取IP吗(DHCP) [Y/n] :" input
	[ -z "${input}" ] && input="y"
    case $input in
      [yY][eE][sS]|[yY]) NETSTR='' ;;
      [nN][oO]|[nN]) isAuto='1' ;;
      *) clear; echo "Canceled by user!"; exit 1;;
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
        [yY][eE][sS]|[yY]) ;;
        [nN][oO]|[nN])
          echo -e "\n"
          UpdateIp
          ipCheck
          [[ $? -ne 0 ]] && {
            clear
            echo -e "Input error!\n"
            exit 1
          }
        ;;
        *) clear; echo "Canceled by user!"; exit 1;;
      esac
    fi
    NETSTR="--ip-addr ${MAINIP} --ip-gate ${GATEWAYIP} --ip-mask ${NETMASK}"
  fi
}

SetNetwork
NetMode

DOWNLOAD_IMG
DELALL
EXTRACT_IMG
INIT_OS

rm -rf $ROOTDIR
apt-get clean all
sync
# reboot -f

read -p "确认上面没有严重的错误信息，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
	echo -e "${Info} VPS 重启中..."
	reboot -f
fi
