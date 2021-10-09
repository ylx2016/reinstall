#!/bin/sh
PATH=$PATH:/sbin:/usr/sbin:/usr/local/sbin:$HOME/bin:/usr/local/bin:/usr/bin
export PATH
export LANG=en_US.UTF-8

yum -y install epel-release
yum -y install net-tools

curl -o /tmp/tcpa_packets_180619_1151.tar.gz https://github.com/ylx2016/reinstall/releases/download/tcpa_file/tcpa_packets_180619_1151.tar.gz
chmod +x /etc/rc.d/rc.local
cat>>/etc/rc.local<<EOF
####tcpa####
cd /tmp/
tar xf tcpa_packets_180619_1151.tar.gz
cd tcpa_packets
sh install.sh
cd /usr/local/storage/tcpav2
sh start.sh
lsmod|grep tcpa
rm -f /tmp/tcpa_packets_180619_1151.tar.gz
rm -rf /tmp/tcpa_packets
sed -i '/####tcpa####/','/####tcpa####/d' /etc/rc.local
####tcpa####
cd /usr/local/storage/tcpav2
sh start.sh
EOF

rpm -ivh https://github.com/ylx2016/reinstall/releases/download/tcpa_file/kernel-3.10.0-693.5.2.tcpa06.tl2.x86_64.rpm --force
echo "内核安装完毕,3秒后将自动重启..."
echo "重启后安装自动完成,lsmod|grep tcpa查看是否开启成功."
sleep 3
reboot
