#!/bin/bash

# Default Password: Pwd@CentOS , Change it after installation !

#IMGURL='https://github.com/ylx2016/reinstall/releases/download/CentOS-7.9.2009-x86_64-docker/CentOS-7.9.2009-x86_64-docker.tar.xz'
IMGURL='https://github.com/debuerreotype/docker-debian-artifacts/raw/dist-amd64/buster/rootfs.tar.xz'
BUSYBOX='https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/busybox-x86_64'
ROOTDIR='/os'

DOWNLOAD_IMG(){
    if command -v wget >/dev/null 2>&1 ;then
        mkdir $ROOTDIR
        wget -O "$ROOTDIR/os.tar.xz" $IMGURL
        wget -O "$ROOTDIR/busybox" $BUSYBOX
        chmod +x "$ROOTDIR/busybox"
    else
        echo "ERROR: wget not found !"
        exit
    fi
}

DELALL(){
    cp /etc/fstab $ROOTDIR
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
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
    rm -f /root/anaconda-ks.cfg
    export LC_ALL=en_US.UTF-8
    apt-get update
   
    #apt-get install -y systemd openssh-server passwd wget nano linux-image-amd64 htop isc-dhcp-client isc-dhcp-common networking-mlnx-common
	apt-get install -y systemd openssh-server passwd wget nano linux-image-amd64 htop network-manager
	#apt-get install -y linux-image
	#apt-get install -y network-manager
	#apt-get install -y grub2 && echo "1"
	DEBIAN_FRONTEND=noninteractive apt-get install -y grub2 -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold"
	
	#apt-get install -y networking
    
    sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 30/' /etc/ssh/sshd_config
    sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
    systemctl enable sshd
    #echo "blog.ylx.me" | passwd --stdin root
	echo -e "blog.ylx.me\nblog.ylx.me" |passwd "root"

    cd /
    device=$(fdisk -l | grep -o /dev/*da | head -1)
    grub2-install $device
   #echo -e "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX=\"net.ifnames=0\"" > /etc/default/grub
    /usr/sbin/update-grub 2>/dev/null
	
	systemctl enable network-manager
	#systemctl enable networking
    #touch /etc/sysconfig/network
	touch /etc/network/interfaces
	mkdir /etc/network
   # cat >/etc/network/interfaces <<EOFILE
#source /etc/network/interfaces.d/*
#auto lo
#iface lo inet loopback
#allow-hotplug ens33
#iface ens33 inet dhcp
#EOFILE

    cat >>/etc/security/limits.conf<<EOFILE

    * soft nofile 65535
    * hard nofile 65535
    * soft nproc 65535
    * hard nproc 65535
EOFILE
    sed -i 's/4096/65535/' /etc/security/limits.d/20-nproc.conf
}

DOWNLOAD_IMG
DELALL
EXTRACT_IMG
INIT_OS

rm -rf $ROOTDIR
apt-get clean all
sync
reboot -f
