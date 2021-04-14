# reinstall

backup from https://www.cxthhhhh.com/network-reinstall-system-modify
<br>
go to https://github.com/ylx2016/Linux-NetSpeed

    wget --no-check-certificate -qO ~/Network-Reinstall-System-Modify.sh 'https://github.com/ylx2016/reinstall/raw/master/Network-Reinstall-System-Modify.sh' && chmod a+x ~/Network-Reinstall-System-Modify.sh && bash ~/Network-Reinstall-System-Modify.sh -UI_Options


重装脚本 passwd:blog.ylx.me     port:52890
原始作者https://www.hostloc.com/thread-717814-1-1.html

兼容性规则:

同版本重装>不同版本重装

bios重装>efi重装（不可从efi跨系重装 如Centos重装到Debian）

同系重装>跨系重装（如:从centos重装到debian，一旦docker重装一次后，跨系重装兼容性将加强）

一般衍生系没有兼容问题，centos和oracle同系 Ubuntu和Debian同系，举例centos装debian,先用此法装一遍centos重启后再用此法装debian,大大避免跨系失败

    wget -N -O CentOSReinstall_beta_CentOS7.sh https://reinstall.pages.dev/CentOSReinstall_beta_CentOS7.sh && bash CentOSReinstall_beta_CentOS7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux7.sh https://reinstall.pages.dev/CentOSReinstall_beta_oraclelinux7.sh && bash            CentOSReinstall_beta_oraclelinux7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux8.sh https://reinstall.pages.dev/CentOSReinstall_beta_oraclelinux8.sh && bash CentOSReinstall_beta_oraclelinux8.sh
    wget -N -O CentOSReinstall_beta_oraclelinux6.sh https://reinstall.pages.dev/CentOSReinstall_beta_oraclelinux6.sh && bash CentOSReinstall_beta_oraclelinux6.sh
    wget -N -O DebianReinstall_beta_debian9.sh https://reinstall.pages.dev/master/DebianReinstall_beta_debian9.sh && bash DebianReinstall_beta_debian9.sh
    wget -N -O DebianReinstall_beta_debian10.sh https://reinstall.pages.dev/DebianReinstall_beta_debian10.sh && bash DebianReinstall_beta_debian10.sh
    wget -N -O DebianReinstall_beta_debian11.sh https://reinstall.pages.dev/DebianReinstall_beta_debian11.sh && bash DebianReinstall_beta_debian11.sh
    wget -N -O DebianReinstall_beta_debian11_ma.sh https://reinstall.pages.dev/DebianReinstall_beta_debian11_ma.sh && bash DebianReinstall_beta_debian11_ma.sh
    wget -N -O UbuntuReinstall_beta_ubuntu18.sh  https://reinstall.pages.dev/UbuntuReinstall_beta_ubuntu18.sh && bash UbuntuReinstall_beta_ubuntu18.sh
    wget -N -O UbuntuReinstall_beta_ubuntu20.sh  https://reinstall.pages.dev/UbuntuReinstall_beta_ubuntu20.sh && bash UbuntuReinstall_beta_ubuntu20.sh
    wget -N -O UbuntuReinstall_beta_ubuntu21.sh  https://reinstall.pages.dev/UbuntuReinstall_beta_ubuntu21.sh && bash UbuntuReinstall_beta_ubuntu21.sh
常用杂烩

    wget -O dnscrypt-proxy.sh https://reinstall.pages.dev/dnscrypt-proxy.sh && chmod +x dnscrypt-proxy.sh && ./dnscrypt-proxy.sh
    sed -i '/Port /d' /etc/ssh/sshd_config && echo "Port 52890" >> /etc/ssh/sshd_config && service sshd restart
    apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && systemctl disable exim4 && systemctl stop exim4
    rm -rf /etc/hostname && touch /etc/hostname && echo "ylx2016" >> /etc/hostname && echo "127.0.0.1 ylx2016" >> /etc/hosts
    bash <(curl -sSL "https://github.com/CoiaPrant/MediaUnlock_Test/raw/main/check.sh")
    bash <(curl -sSL "https://raw.githubusercontent.com/xb0or/nftest/main/netflix.sh")
    apt install xz-utils tar  wget curl -y && wget https://reinstall.pages.dev/besttrace4linux.tar.xz && tar -Jxvf besttrace4linux.tar.xz &&  chmod +x besttrace && ./besttrace -q1 -g cn ip
    wget -O wgcf.sh https://ylx.pages.dev/wgcf.sh && chmod +x wgcf.sh && ./wgcf.sh
    wget -O wgcfgo.sh https://ylx.pages.dev/wgcfgo.sh && chmod +x wgcfgo.sh && ./wgcfgo.sh
