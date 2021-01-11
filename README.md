# reinstall

backup from https://www.cxthhhhh.com/network-reinstall-system-modify

    wget --no-check-certificate -qO ~/Network-Reinstall-System-Modify.sh 'https://github.com/ylx2016/reinstall/raw/master/Network-Reinstall-System-Modify.sh' && chmod a+x ~/Network-Reinstall-System-Modify.sh && bash ~/Network-Reinstall-System-Modify.sh -UI_Options


重装脚本 Pwd@CentOS Or blog.ylx.me
https://www.hostloc.com/thread-717814-1-1.html

    wget -N -O CentOSReinstall_beta_CentOS7.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_CentOS7.sh && bash CentOSReinstall_beta_CentOS7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux7.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux7.sh && bash            CentOSReinstall_beta_oraclelinux7.sh
    wget -N -O CentOSReinstall_beta_oraclelinux8.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux8.sh && bash CentOSReinstall_beta_oraclelinux8.sh
    wget -N -O CentOSReinstall_beta_oraclelinux6.sh https://github.com/ylx2016/reinstall/raw/master/CentOSReinstall_beta_oraclelinux6.sh && bash CentOSReinstall_beta_oraclelinux6.sh
    wget -N -O DebianReinstall_beta_debian10.sh https://github.com/ylx2016/reinstall/raw/master/DebianReinstall_beta_debian10.sh && bash DebianReinstall_beta_debian10.sh

一键dnscrypt-proxy from johnrosen1

    wget -O dnscrypt-proxy.sh https://raw.githubusercontent.com/ylx2016/reinstall/master/dnscrypt-proxy.sh && chmod +x dnscrypt-proxy.sh && ./dnscrypt-proxy.sh
    sed -i '/Port /d' /etc/ssh/sshd_config && echo "Port 52890" >> /etc/ssh/sshd_config && service sshd restart

DD alpine

cloudcone

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/cloudcone2alpine.sh && chmod +x cloudcone2alpine.sh && ./cloudcone2alpine.sh

谷歌云GCP

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/alpine.sh && chmod +x alpine.sh && sed -i "s|^mask|mask=255.255.255.0\n#mask|" alpine.sh && ./alpine.sh

其他KVM

    wget --no-check-certificate https://github.com/ylx2016/reinstall/raw/master/alpine.sh && chmod +x alpine.sh && ./alpine.sh
