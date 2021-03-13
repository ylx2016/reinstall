# reinstall

backup from https://www.cxthhhhh.com/network-reinstall-system-modify
<br>
go to https://github.com/ylx2016/Linux-NetSpeed

    wget --no-check-certificate -qO ~/Network-Reinstall-System-Modify.sh 'https://github.com/ylx2016/reinstall/raw/master/Network-Reinstall-System-Modify.sh' && chmod a+x ~/Network-Reinstall-System-Modify.sh && bash ~/Network-Reinstall-System-Modify.sh -UI_Options


重装脚本 passwd:blog.ylx.me     port:52890
https://www.hostloc.com/thread-717814-1-1.html

    wget -N -O CentOSReinstall_beta_CentOS7.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_CentOS7.sh && bash CentOSReinstall_beta_CentOS7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux7.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux7.sh && bash            CentOSReinstall_beta_oraclelinux7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux8.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux8.sh && bash CentOSReinstall_beta_oraclelinux8.sh
    wget -N -O CentOSReinstall_beta_oraclelinux6.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux6.sh && bash CentOSReinstall_beta_oraclelinux6.sh
    wget -N -O DebianReinstall_beta_debian10.sh https://github.com/ylx2016/reinstall/raw/master/DebianReinstall_beta_debian10.sh && bash DebianReinstall_beta_debian10.sh
    wget -N -O DebianReinstall_beta_debian11.sh https://github.com/ylx2016/reinstall/raw/master/DebianReinstall_beta_debian11.sh && bash DebianReinstall_beta_debian11.sh
    wget -N -O DebianReinstall_beta_debian11_ma.sh https://github.com/ylx2016/reinstall/raw/master/DebianReinstall_beta_debian11_ma.sh && bash DebianReinstall_beta_debian11_ma.sh
    wget -N -O UbuntuReinstall_beta_ubuntu20.sh  https://github.com/ylx2016/reinstall/raw/master/UbuntuReinstall_beta_ubuntu20.sh && bash UbuntuReinstall_beta_ubuntu20.sh
一键dnscrypt-proxy from johnrosen1 and others

    wget -O dnscrypt-proxy.sh https://raw.githubusercontent.com/ylx2016/reinstall/master/dnscrypt-proxy.sh && chmod +x dnscrypt-proxy.sh && ./dnscrypt-proxy.sh
    sed -i '/Port /d' /etc/ssh/sshd_config && echo "Port 52890" >> /etc/ssh/sshd_config && service sshd restart
    apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && systemctl disable exim4 && systemctl stop exim4
    rm -rf /etc/hostname && touch /etc/hostname && echo "ylx2016" >> /etc/hostname && echo "127.0.0.1 ylx2016" >> /etc/hosts
    bash <(curl -sSL "https://www.zeroteam.top/files/mediatest.sh")
    apt install xz-utils tar  wget curl -y && wget https://github.com/ylx2016/reinstall/raw/master/besttrace4linux.tar.xz && tar -Jxvf besttrace4linux.tar.xz &&  chmod +x besttrace && ./besttrace -q1 -g cn ip

DD alpine

cloudcone

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/cloudcone2alpine.sh && chmod +x cloudcone2alpine.sh && ./cloudcone2alpine.sh

谷歌云GCP

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/alpine.sh && chmod +x alpine.sh && sed -i "s|^mask|mask=255.255.255.0\n#mask|" alpine.sh && ./alpine.sh

其他KVM

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/alpine.sh && chmod +x alpine.sh && ./alpine.sh
