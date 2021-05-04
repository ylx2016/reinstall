#!/bin/bash

# Default Password: blog.ylx.me , Change it after installation ! By dansnow and YLX

#IMGURL='https://github.com/ylx2016/reinstall/releases/download/CentOS-7.9.2009-x86_64-docker/CentOS-7.9.2009-x86_64-docker.tar.xz'
#IMGURL='https://github.com/ylx2016/reinstall/releases/download/docker-file/oraclelinux-8-amd64-rootfs_2020.12.22.tar.xz'
#IMGURL='https://raw.githubusercontent.com/oracle/container-images/dist-amd64/8/oraclelinux-8-amd64-rootfs.tar.xz'
#CN_IMGURL='https://raw.sevencdn.com/oracle/container-images/dist-amd64/8/oraclelinux-8-amd64-rootfs.tar.xz'
urldata=$(rm -rf /tmp/url.tmp && curl -o /tmp/url.tmp 'https://cf-image.ylx.workers.dev/images/oracle/8/amd64/cloud/?C=M;O=D' && grep -o 2.......[\_]..[\:].. /tmp/url.tmp | head -n 1)
IMGURL=https://cf-image.ylx.workers.dev/images/oracle/8/amd64/cloud/${urldata}/rootfs.tar.xz
CN_IMGURL=https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/oracle/8/amd64/cloud/${urldata}/rootfs.tar.xz
BUSYBOX='https://raw.githubusercontent.com/ylx2016/reinstall/master/busybox_1.32.1'
CN_BUSYBOX='https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64'
ROOTDIR='/os'

DOWNLOAD_IMG(){
    if command -v wget >/dev/null 2>&1 ;then
        mkdir $ROOTDIR
		if [[ "$isCN" == '1' ]];then
			CN_IMGURLstate=$(curl -s --head $CN_IMGURL | head -n 1)
			if [[ ${CN_IMGURLstate} == *200* ]]; then
				echo "CN 镜像地址检查OK，继续！"
			else
				echo "CN 镜像地址检查出错，退出！"
				exit 1
			fi
			BUSYBOXstate=$(curl -s --head $CN_BUSYBOX | head -n 1)
			if [[ ${BUSYBOXstate} == *200* ]]; then
				echo "CN BUSYBOX镜像地址检查OK，继续！"
			else
				echo "CN BUSYBOX地址检查出错，退出！"
				exit 1
			fi
			wget -O "$ROOTDIR/os.tar.xz" $CN_IMGURL
			wget -O "$ROOTDIR/busybox" $CN_BUSYBOX
		else
			IMGURLstate=$(curl -s --head $IMGURL | head -n 1)
			if [[ ${IMGURLstate} == *200* ]]; then
				echo "镜像地址检查OK，继续！"
			else
				echo "镜像地址检查出错，退出！"
				exit 1
			fi
			BUSYBOXstate=$(curl -s --head $BUSYBOX | head -n 1)
			if [[ ${BUSYBOXstate} == *200* ]]; then
				echo "BUSYBOX地址检查OK，继续！"
			else
				echo "BUSYBOX地址检查出错，退出！"
				exit 1
			fi
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
	if [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
		sysefi="1"
		sysefifile="/boot/efi/EFI/centos/grub.cfg"
	elif [ -f "/boot/efi/EFI/redhat/grub.cfg" ]; then
		sysefi="1"
		sysefifile="/boot/efi/EFI/redhat/grub.cfg"
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
		dns_name1="114.114.114.114"
		dns_name2="223.5.5.5"
		echo "nameserver $dns_name1" > /etc/resolv.conf
		echo "nameserver $dns_name2" >> /etc/resolv.conf
		#mv /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.backup
		#mv /etc/yum.repos.d/epel-testing.repo /etc/yum.repos.d/epel-testing.repo.backup
		mv /etc/yum.repos.d/CentOS-Base.repo{,.bak}
		curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.163.com/.help/CentOS8-Base-163.repo
		curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/Centos-8.repo
		yum makecache
		yum install -y https://mirrors.aliyun.com/epel/epel-release-latest-8.noarch.rpm
	else
		dns_name1="1.1.1.1"
		dns_name2="8.8.8.8"
		echo "nameserver $dns_name1" > /etc/resolv.conf
		echo "nameserver $dns_name2" >> /etc/resolv.conf
		# echo "nameserver 9.9.9.9" >> /etc/resolv.conf
		yum makecache
		yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm
		yum install htop -y
	fi
    rm -f /root/anaconda-ks.cfg
    export LC_ALL=en_US.UTF-8
    yum install glibc-langpack-en -y
    #yum install -y grub2 cracklib-dicts dhcp-client openssh-server passwd wget kernel kernel-core nano network-scripts htop
    yum install -y grub2* cracklib-dicts dhcp-client openssh-server passwd wget kernel kernel-core nano NetworkManager util-linux coreutils net-tools grubby
     
    device=$(fdisk -l | grep -o /dev/*da | head -1)
	if [[ ${sysefi} == "1" ]];then
		cd /
		yum install grub2-efi grub2-efi-modules shim grub2-efi-x64 grub2-efi-x64-modules -y
		grub2-install --target=x86_64-efi --bootloader-id=redhat --efi-directory=/boot/efi --verbose $device --boot-directory=/boot/efi
		touch /etc/default/grub		
		sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
		sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub
		echo "GRUB_CMDLINE_LINUX=\"GRUB_TIMEOUT=5\"" >> /etc/default/grub
		echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >> /etc/default/grub
		grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg
		grub2-install --target=x86_64-efi --bootloader-id=redhat --efi-directory=/boot/efi --verbose $device --boot-directory=/boot/efi
		#yum install NetworkManager -y
		#systemctl enable NetworkManager
	elif [[ ${sysbios} == "1" ]];then
		#yum install -y grub2
		cd /
		grub2-install $device
		touch /etc/default/grub
		sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
		sed -i '/GRUB_TIMEOUT=/d' /etc/default/grub
		echo "GRUB_CMDLINE_LINUX=\"GRUB_TIMEOUT=5\"" >> /etc/default/grub
		echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >> /etc/default/grub
		grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null
		grub2-install $device
	fi
	
	sed -i '/Port /d' /etc/ssh/sshd_config
	echo "Port 52890" >> /etc/ssh/sshd_config
    sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 30/' /etc/ssh/sshd_config
    sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.d/99-sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.d/99-sysctl.conf
    systemctl enable sshd
    systemctl enable NetworkManager
    echo "blog.ylx.me" | passwd --stdin root

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
	DNS1=$dns_name1
	DNS2=$dns_name2
EOFILE
	fi
   
    cat >>/etc/security/limits.conf<<EOFILE

    * soft nofile 65535
    * hard nofile 65535
    * soft nproc 65535
    * hard nproc 65535
EOFILE
    rm -rf /etc/hostname
    touch /etc/hostname
    echo "ylx2016" >> /etc/hostname
    echo "127.0.0.1 ylx2016" >> /etc/hosts
    #sed -i 's/4096/65535/' /etc/security/limits.d/20-nproc.conf
	wget -O /root/tcpx.sh "https://github.000060000.xyz/tcpx.sh" && /usr/bin/chmod +x /root/tcpx.sh
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
		echo -e "检测到大陆环境."
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
yum clean all
sync
# reboot -f
read -p "确认上面没有严重的错误信息，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
	echo -e "${Info} VPS 重启中..."
	reboot -f
fi
