#!/bin/bash
#
#********************************************************************
#Author:        chailonggang
#QQ:            1603233605
#Date:          2020-07-26
#FileName：        haproxy-install.sh
#URL:           http://www.chailonggang.com
#Description：     The haproxy script
#Copyright (C):     2020 All rights reserved
#********************************************************************
FILE_DIR="/tmp"
LUA_PKG="lua-5.3.6_Sources.tar.gz"
LUA_DIR="lua53"
HAPROXY_PKG="haproxy-2.4-dev6.tar.gz"
HAPROXY_DIR="haproxy-2.4-dev6"
HAPROXY_VER="2.2.0"
LUA_WGET="https://github.com/ylx2016/reinstall/raw/master/lua-5.3.6_Sources.tar.gz"
HAPROXY_WGET="https://github.com/ylx2016/reinstall/raw/master/haproxy-2.4-dev6.tar.gz"

function install_system_package(){
    grep "Ubuntu" /etc/issue &amp;&gt; /dev/null
    if [ $? -eq 0 ];then
        apt update
        apt -y install iproute2 ntpdate make tcpdump telnet traceroute nfs-kernel-server nfs-common lrzsz tree openssl libssl-dev libpcre3 libpcre3-dev zlib1g-dev gcc openssl-server iotop unzip zip libreadline-dev libsystemd-dev
    fi

    grep "Kernel" /etc/issue &amp;&gt; /dev/null
    if [ $? -eq 0 ];then
        yum -y install vim iotop bc gcc gcc-c++ glibc glibc-devel pcre pcre-devel openssl openssl-devel zip unzip zlib-devel net-tools lrzsz tree ntpdate telnet lsof tcpdump wget libvent libvent-devel systemd-devel bash-completion traceroute psmisc
    fi
}

function install_lua(){
    cd ${FILE_DIR} &amp;&amp; wget -O ${LUA_PKG} ${LUA_WGET} &amp;&amp; tar xvf ${LUA_PKG} &amp;&amp; cd ${LUA_DIR} &amp;&amp; make linux test
}

function install_haproxy(){
    if -d /etc/haproxy;then
        echo "haproxy 已经安装，即将退安装！" &amp;&amp; sleep 2
    else
        mkdir -p /var/lib/haproxy /etc/haproxy
        cd ${FILE_DIR} &amp;&amp; wget -O ${HAPROXY_PKG} ${HAPROXY_WGET} &amp;&amp; tar xvf ${HAPROXY_PKG} &amp;&amp; cd ${HAPROXY_DIR} &amp;&amp; make ARCH=x86_64 TARGET=linux-glibc USE_PCRE=1 USE_OPENSSL=1 USE_ZLIB=1 USE_SYSTEMD=1 USE_CPU_AFFINITY=1 USE_LUA=1 LUA_INC=/usr/local/src/lua-5.3.5/src/ LUA_LIB=/usr/local/src/lua-5.3.5/src/ PREFIX=/apps/haproxy &amp;&amp; make install PREFIX=/apps/haproxy &amp;&amp; cp haproxy /usr/sbin/
        cp ${FILE_DIR}/haproxy.cfg /etc/haproxy/haproxy.cfg
        cp ${FILE_DIR}/haproxy.service /usr/lib/systemd/system/haproxy.service
        systemctl daemon-reload &amp;&amp; systemctl enable --now haproxy
        killall -0 haproxy
        if [ $? -eq 0 ];then
            echo "haproxy ${HAPROXY_VER} 安装成功!" &amp;&amp; echo "即将退出!" &amp;&amp; sleep 2
        else
            echo "haproxy ${HAPROXY_VER} 安装失败!" &amp;&amp; echo "即将退出!" &amp;&amp; sleep 2
        fi
    fi
}

main(){
    install_system_package
    install_lua
    install_haproxy
}

main