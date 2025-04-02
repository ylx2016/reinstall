# reinstall



    'wget -N -O ReinstallDebianUbuntu.sh  https://reinstall.pages.dev/ReinstallDebianUbuntu.sh && chmod +x ReinstallDebianUbuntu.sh &&  ./ReinstallDebianUbuntu.sh'
    ./ReinstallDebianUbuntu.sh --password '*******' --authorized-keys-url 'https://123.com/123.pub' --hostname 'ylx2016'

常用杂烩

    wget -O dnscrypt-proxy.sh https://reinstall.pages.dev/dnscrypt-proxy.sh && chmod +x dnscrypt-proxy.sh && ./dnscrypt-proxy.sh
    sed -i '/Port /d' /etc/ssh/sshd_config && echo "Port 52890" >> /etc/ssh/sshd_config && service sshd restart
    apt-get update && apt-get dist-upgrade -y && apt-get autoremove -y && systemctl disable exim4 && systemctl stop exim4
    apt update && apt-get dist-upgrade -y && apt -t bullseye-backports upgrade -y && apt-get autoremove -y
    apt update && apt-get dist-upgrade -y && apt -t focal-backports upgrade -y && apt-get autoremove -y
    rm -rf /etc/hostname && touch /etc/hostname && echo "ylx2016" >> /etc/hostname && echo "127.0.0.1 ylx2016" >> /etc/hosts
    bash <(curl -sSL "https://github.com/CoiaPrant/MediaUnlock_Test/raw/main/check.sh")
    bash <(curl -sSL "https://raw.githubusercontent.com/xb0or/nftest/main/netflix.sh")
    bash <(curl -L -s https://raw.githubusercontent.com/lmc999/RegionRestrictionCheck/main/check.sh)
    apt install xz-utils tar  wget curl -y && wget -O besttrace4linux.tar.xz https://reinstall.pages.dev/besttrace4linux.tar.xz && tar -Jxvf besttrace4linux.tar.xz &&  chmod +x besttrace && ./besttrace -q1 -g cn ip
    wget -O wgcf.sh https://ylx.pages.dev/wgcf.sh && chmod +x wgcf.sh && ./wgcf.sh
    wget -O wgcfgo.sh https://ylx.pages.dev/wgcfgo.sh && chmod +x wgcfgo.sh && ./wgcfgo.sh
    sudo date -s "$(wget -qSO- --max-redirect=0 google.com 2>&1 | grep Date: | cut -d' ' -f5-8)Z"
    wget -O blcok.sh https://ylx.pages.dev/blcok.sh && chmod +x blcok.sh && ./blcok.sh
    curl https://raw.githubusercontent.com/zhucaidan/mtr_trace/main/mtr_trace.sh|bash
    apt remove cloudflare-warp -y && apt install cloudflare-warp -y && systemctl enable warp-svc && warp-cli --accept-tos register && warp-cli --accept-tos set-mode proxy && warp-cli --accept-tos set-proxy-port 31303 && warp-cli --accept-tos connect
    
    wget -O tcpa.sh https://github.com/ylx2016/reinstall/raw/master/tcpa.sh sh tcpa.sh
    
    wget -qO- bench.sh | bash
    bash <(curl -Ls unlock.moe)
    wget -qO- https://github.com/yeahwu/check/raw/main/check.sh | bash
    curl https://raw.githubusercontent.com/zhanghanyun/backtrace/main/install.sh -sSf | sh
