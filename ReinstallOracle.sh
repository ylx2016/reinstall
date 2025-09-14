#!/usr/bin/env bash

# 目的：重新安装 Oracle/CentOS 系统，支持自定义网络和系统设置
# 环境设置
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$HOME/bin"
export PATH

# 默认配置
DEFAULT_HOSTNAME="my-os-$(date +%Y%m%d)"
DEFAULT_TIMEZONE="Asia/Shanghai"
DEFAULT_REGION="global"

# 脚本变量
authorized_keys_url=""
password=""
ssh_port=""
hostname="${DEFAULT_HOSTNAME}"
apt_mirror_url=""
region="${DEFAULT_REGION}"
timezone="${DEFAULT_TIMEZONE}"
root_dir="/os"
busybox_path="${root_dir}/busybox"
system=""
selected_version=""
is_cn=0
is_auto=0
network_adapter="eth0"
main_ip=""
gateway_ip=""
netmask=""
subnet=""
dns1=""
dns2=""
has_ipv6=0
has_native_ipv6=0
native_ipv6_iface=""
native_ipv6_addr=""
native_ipv6_mask=""
native_ipv6_gw=""
he_tunnel=0
he_client_ipv4=""
he_server_ipv4=""
he_client_ipv6=""
he_netmask=""
he_server_ipv6=""
use_native_ipv6=0
use_he_tunnel=0

# 错误处理
err() {
    echo "错误: $1" >&2
    exit 1
}

# 使用帮助信息
usage() {
    cat <<EOF
用法: $0 [选项]

一个强大的脚本，用于重新安装 CentOS 或 Oracle Linux 系统。

选项:
  --authorized-keys-url URL   设置 SSH 公钥 URL (将禁用密码登录)
  --password PASS             设置 root 密码 (在命令行使用此选项存在安全风险)
  --ssh-port PORT             设置 SSH 端口 (1-65535)
  --hostname NAME             设置主机名 (默认: ${DEFAULT_HOSTNAME})
  --region {cn|global}        设置区域以优化下载速度 (默认: ${DEFAULT_REGION})
  --timezone ZONE             设置时区 (默认: ${DEFAULT_TIMEZONE})
  --help                      显示此帮助信息
EOF
    exit 0
}

# 解析命令行参数
while [ $# -gt 0 ]; do
    case "$1" in
        --authorized-keys-url)
            authorized_keys_url="$2"
            shift 2
            ;;
        --password)
            password="$2"
            shift 2
            ;;
        --ssh-port)
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                err "无效的 SSH 端口 '$2'，必须为 1-65535 之间的整数"
            fi
            ssh_port="$2"
            shift 2
            ;;
        --hostname)
            hostname="$2"
            shift 2
            ;;
        --apt-mirror) # This argument is parsed but not used in the script.
            apt_mirror_url="$2"
            shift 2
            ;;
        --region)
            if [[ "$2" != "cn" && "$2" != "global" ]]; then
                err "无效的区域 '$2'，请使用 'cn' 或 'global'"
            fi
            region="$2"
            shift 2
            ;;
        --timezone)
            timezone="$2"
            shift 2
            ;;
        --help)
            usage
            ;;
        *)
            err "未知选项: '$1'"
            ;;
    esac
done

# 确保 bash 软链接存在
[ ! -e "/usr/bin/bash" ] && ln -s "$(command -v bash)" /usr/bin/bash

# 安装必要工具
install_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "正在安装 $tool..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y "$tool"
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y "$tool"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "$tool"
        else
            err "未知的包管理器，请手动安装 $tool"
        fi
    else
        echo "$tool 已安装，继续执行"
    fi
}

for t in curl wget zip tar; do
    install_tool "$t"
done

# 获取系统架构
arch="$(uname -m)"

# 选择操作系统
choose_system() {
    echo "请选择要安装的系统："
    echo "1. centos"
    echo "2. oracle"
    while true; do
        read -p "请输入数字 (1 或 2)： " choice
        case "$choice" in
            1)
                system="centos"
                base_url="https://images.linuxcontainers.org/images/centos"
                cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/centos"
                break
                ;;
            2)
                system="oracle"
                base_url="https://images.linuxcontainers.org/images/oracle"
                cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/oracle"
                break
                ;;
            *)
                echo "无效输入，请输入 1 或 2"
                ;;
        esac
    done
    echo "已选择系统：$system"
}

# 获取可用版本
get_versions() {
    local versions_file="/tmp/versions.txt"
    declare -A version_map

    # 定义支持的版本和其对应的内部标识
    if [ "$system" == "centos" ]; then
        version_map=(
            ["9-Stream"]="centos9-Stream"
        )
    elif [ "$system" == "oracle" ]; then
        version_map=(
            ["7"]="centos7"
            ["8"]="centos8"
            ["9"]="centos9"
        )
    else
        err "未知的系统选择: $system"
    fi

    echo "正在获取支持的 $system 版本..."
    curl -s -L "$base_url/" -o "$versions_file" || err "无法获取版本列表：$base_url/"
    
    # 提取所有版本号
    mapfile -t all_versions < <(grep -oE 'href="[0-9a-zA-Z.-]+/"' "$versions_file" | sed -e 's/href="//' -e 's|/"||' | sort -u)

    # 过滤出我们支持的版本
    declare -a versions
    for version in "${all_versions[@]}"; do
        [ -n "${version_map[$version]}" ] && versions+=("$version")
    done

    if [ ${#versions[@]} -eq 0 ]; then
        echo "错误：解析版本列表失败。文件 /tmp/versions.txt 内容如下："
        cat "$versions_file"
        err "未检测到支持的 $system 版本"
    fi

    echo "支持的 $system 版本："
    for i in "${!versions[@]}"; do
        echo "$((i + 1)). ${versions[$i]}"
    done

    while true; do
        read -p "请选择要安装的版本（输入数字 1-${#versions[@]}）： " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#versions[@]}" ]; then
            selected_version="${versions[$((choice - 1))]}"
            echo "已选择版本：$selected_version"
            break
        else
            echo "无效输入，请输入 1 到 ${#versions[@]} 之间的数字"
        fi
    done

    rm -f "$versions_file"
}

# 下载系统镜像和 BusyBox
download_image() {
    local version="$selected_version"
    local file="rootfs.tar.xz"
    local os_filename="${root_dir}/os.tar.xz"
    local attempts=3
    local timeout=15
    local busybox_filename=""
    local image_arch=""

    # 设置架构相关变量
    case "$arch" in
        x86_64)
            image_arch="amd64"
            busybox_filename="busybox-x86_64-linux-gnu"
            ;;
        aarch64)
            image_arch="arm64"
            busybox_filename="busybox-aarch64-linux-gnu"
            ;;
        *)
            err "不支持的系统架构：$arch"
            ;;
    esac

    mkdir -p "$root_dir" || err "无法创建 $root_dir 目录"

    # 获取时间戳列表
    local list_url="$base_url/$version/$image_arch/cloud/?C=M;O=D"
    echo "正在获取可用镜像时间戳列表..."
    curl -s -L "$list_url" -o /tmp/url.tmp || err "无法获取时间戳列表：$list_url"
    
    # 使用更具可移植性的 grep -E
    mapfile -t timestamp_list < <(grep -oE '[0-9]{8}_[0-9]{2}:[0-9]{2}' /tmp/url.tmp | sort -r)

    if [ ${#timestamp_list[@]} -eq 0 ]; then
        err "未检测到任何可用时间戳目录"
    fi

    echo "找到最新的镜像时间戳：${timestamp_list[0]}"
    local timestamp="${timestamp_list[0]}"

    # 设置下载 URL
    local img_url="$base_url/$version/$image_arch/cloud/$timestamp/$file"
    local cn_img_url="$cn_base_url/$version/$image_arch/cloud/$timestamp/$file"
    local url_to_use="$img_url"
    [ "$is_cn" -eq 1 ] && url_to_use="$cn_img_url"

    local checksum_url="$base_url/$version/$image_arch/cloud/$timestamp/SHA256SUMS"
    local checksum_available=1
    local expected_checksum=""
    
    if ! curl -s -L "$checksum_url" -o "SHA256SUMS"; then
        echo "警告：无法下载校验和文件，跳过 SHA256 验证"
        checksum_available=0
    else
        expected_checksum=$(grep "$file" SHA256SUMS | awk '{print $1}')
        if [ -z "$expected_checksum" ]; then
            echo "警告：校验和文件中未找到 $file 的记录"
            checksum_available=0
        fi
    fi

    echo "开始下载镜像文件：$url_to_use"
    for ((i = 1; i <= attempts; i++)); do
        echo "尝试下载镜像（第 $i 次）..."
        if curl -SL --retry 2 --connect-timeout "$timeout" -o "$os_filename" "$url_to_use"; then
            break
        elif [ "$i" -eq "$attempts" ]; then
            err "下载镜像失败：$url_to_use"
        fi
        sleep 5
    done
    
    # 验证镜像文件 SHA256 校验和
    if [ "$checksum_available" -eq 1 ]; then
        echo "验证镜像文件 SHA256 校验和..."
        local actual_checksum
        actual_checksum=$(sha256sum "$os_filename" | awk '{print $1}')
        if [ "$actual_checksum" == "$expected_checksum" ]; then
            echo "镜像文件 SHA256 校验和匹配，文件完整性验证通过"
        else
            err "镜像文件 SHA256 校验和不匹配！期望值: $expected_checksum，实际值: $actual_checksum"
        fi
    else
        # 如果无法校验和，则校验文件大小
        echo "验证镜像文件大小..."
        local remote_size
        remote_size=$(curl -sI -L "$url_to_use" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r')
        if [ -z "$remote_size" ] || [ "$remote_size" -eq 0 ]; then
            echo "警告：无法获取远程文件大小，跳过大小验证"
        else
            local local_size
            local_size=$(stat -c%s "$os_filename" 2>/dev/null || wc -c <"$os_filename")
            if [ "$local_size" -eq "$remote_size" ]; then
                echo "镜像文件大小匹配：$local_size 字节"
            else
                err "镜像文件大小不匹配！本地大小: $local_size，远程大小: $remote_size"
            fi
        fi
    fi

    # 下载 BusyBox
    local busybox_base_url="https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
    [ "$region" == "cn" ] && busybox_base_url="https://ghproxy.net/https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
    local current_busybox_url="${busybox_base_url}${busybox_filename}"
    
    echo "开始下载 BusyBox：$current_busybox_url"
    if ! curl -SLf --retry 2 --connect-timeout "$timeout" -o "$busybox_path" "$current_busybox_url"; then
        err "下载 BusyBox 失败：$current_busybox_url"
    fi
    
    chmod +x "$busybox_path" || err "无法为 $busybox_path 设置可执行权限"
    if ! "$busybox_path" --help >/dev/null 2>&1; then
        err "BusyBox 测试失败，可能下载不完整或不兼容"
    fi
    echo "BusyBox 下载并测试成功"

    rm -f SHA256SUMS /tmp/url.tmp
}

# 删除旧系统文件
delete_old_system() {
    [ ! -f "$busybox_path" ] && err "BusyBox 文件缺失：$busybox_path"
    
    # 备份 fstab
    [ -f /etc/fstab ] && cp /etc/fstab "$root_dir"

    echo "正在准备删除旧系统文件..."
    if command -v chattr >/dev/null 2>&1; then
        # 解除文件锁定
        find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$root_dir/*" \) \
            -exec chattr -i {} + 2>/dev/null || true
    fi
    
    # 使用 BusyBox 删除文件
    "$busybox_path" find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$root_dir/*" \) -delete 2>/dev/null || true
    echo "旧系统文件已删除"
}

# 解压新系统镜像
extract_image() {
    echo "开始解压系统镜像..."
    if ! "$busybox_path" tar -xJf "$root_dir/os.tar.xz" -C /; then
        err "系统镜像解压失败"
    fi
    
    # 恢复 fstab
    [ -f "$root_dir/fstab" ] && mv -f "$root_dir/fstab" /etc/
    echo "系统镜像解压完成"
}

# 初始化新系统
init_os() {
    cd /

    # 配置 DNS
    echo "正在配置临时 DNS..."
    rm -rf /etc/resolv.conf
    if [ "$is_cn" -eq 1 ]; then
        cat > /etc/resolv.conf <<EOF
nameserver 114.114.114.114
nameserver 223.5.5.5
EOF
    else
        cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
EOF
    fi

    # 清理不必要的文件
    rm -f /root/anaconda-ks.cfg /etc/machine-id
    export LC_ALL=en_US.UTF-8

    # 包管理器和更新命令
    local pkgmgr="yum"
    command -v dnf >/dev/null 2>&1 && pkgmgr="dnf"
    
    echo "正在使用 $pkgmgr 更新软件包缓存..."
    $pkgmgr makecache || err "更新软件包缓存失败"

	if [ "$system" == "centos" ]; then
		$pkgmgr install epel-release -y
	fi

	if [ "$system" == "oracle" ]; then
		$pkgmgr install oracle-epel-release* -y
	fi
	
    # 安装引导、内核、网络等核心软件包
    echo "正在安装核心系统软件包 (kernel, grub2, network-scripts)..."
    $pkgmgr install -y kernel grub2 grubby util-linux policycoreutils chrony openssh-server \
        dhclient passwd wget nano htop coreutils net-tools || err "安装核心软件包失败"

    # --- GRUB 安装 ---
    echo "正在配置引导加载程序 (GRUB)..."
    
	# 检测磁盘
    local grub_device=""
    mapfile -t potential_disks < <(lsblk -nd -o NAME,TYPE,RO,RM | awk '$2=="disk" && $3=="0" && $4=="0" {print "/dev/"$1}')

    if [ ${#potential_disks[@]} -eq 0 ]; then
        grub_device=$(fdisk -l 2>/dev/null | grep -Eo '/dev/[sv]d[a-z]+|/dev/nvme[0-9]+n[0-9]+|/dev/xvd[a-z]+|/dev/vd[a-z]+' | head -1)
        [ -z "$grub_device" ] && err "无法自动检测到合适的磁盘设备用于 GRUB 安装"
        echo "检测到磁盘 $grub_device 用于 GRUB 安装"
    elif [ ${#potential_disks[@]} -eq 1 ]; then
        grub_device="${potential_disks[0]}"
        local disk_size
        disk_size=$(lsblk -b -d -o SIZE "${grub_device}" | tail -n 1 | awk '{print $1/1024/1024/1024 " GB"}')
        echo "自动选择磁盘 $grub_device (大小: ${disk_size}) 用于 GRUB 安装"
    else
        echo "检测到多个磁盘设备，请选择安装 GRUB 的主系统引导盘:"
        for i in "${!potential_disks[@]}"; do
            local disk_info
            disk_info=$(lsblk -b -d -o SIZE,MODEL "${potential_disks[$i]}" | tail -n 1 | awk '{model=$2; for(j=3;j<=NF;j++) model=model"_"$j; printf "大小: %.2f GB, 型号: %s\n", $1/1024/1024/1024, model}')
            echo "$((i + 1)). ${potential_disks[$i]} (${disk_info})"
        done
        read -p "请输入 GRUB 安装目标设备的数字: " choice_grub_disk
        if [[ "$choice_grub_disk" =~ ^[0-9]+$ ]] && [ "$choice_grub_disk" -ge 1 ] && [ "$choice_grub_disk" -le "${#potential_disks[@]}" ]; then
            grub_device="${potential_disks[$((choice_grub_disk - 1))]}"
        else
            err "无效选择，无法确定 GRUB 安装设备"
        fi
    fi
    echo "GRUB 将安装到: $grub_device"
    read -t 8 -p "确认磁盘选择正确？8秒后自动继续，按 Ctrl+C 中止"

    # 修改 GRUB 默认配置
    touch /etc/default/grub
    sed -i '/^GRUB_TIMEOUT=/d' /etc/default/grub
    sed -i '/^GRUB_CMDLINE_LINUX=/d' /etc/default/grub
    cat >> /etc/default/grub <<EOF
GRUB_TIMEOUT=3
GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"
EOF

    # 根据 BIOS/EFI 模式安装 GRUB
    if [ -d "/sys/firmware/efi" ]; then
        echo "检测到 EFI 模式，安装 GRUB-EFI..."
        local grub_efi_pkg1="" grub_efi_pkg2="" grub_target=""
        if [ "$arch" == "x86_64" ]; then
            grub_efi_pkg1="grub2-efi-x64"; grub_efi_pkg2="shim-x64"; grub_target="x86_64-efi"
        elif [ "$arch" == "aarch64" ]; then
            grub_efi_pkg1="grub2-efi-aa64"; grub_efi_pkg2="shim-aa64"; grub_target="arm64-efi"
        else
            err "不支持的 EFI 架构: $arch"
        fi
        
        $pkgmgr install -y "$grub_efi_pkg1" "$grub_efi_pkg2" efibootmgr
        grub2-install --target="$grub_target" --efi-directory=/boot/efi --bootloader-id="$system" --recheck "$grub_device" || err "GRUB EFI 安装失败"
        grub2-mkconfig -o "/boot/efi/EFI/$system/grub.cfg" || err "生成 GRUB EFI 配置失败"
    else
        echo "检测到 BIOS 模式，安装 GRUB-PC..."
        grub2-install "$grub_device" || err "GRUB BIOS 安装失败"
        grub2-mkconfig -o /boot/grub2/grub.cfg || err "生成 GRUB BIOS 配置失败"
    fi
    
    # # 使用 grubby 确保引导项正确
    # echo "使用 grubby 添加并设置默认引导项..."
    # local kernel_path initrd_path root_device root_uuid root_identifier
    # kernel_path=$(find /boot/ -name 'vmlinuz-*' | sort -V | tail -n 1)
    # [ -z "$kernel_path" ] && err "致命错误: 未在 /boot/ 目录下找到任何内核文件！"
    
    # initrd_path="${kernel_path/vmlinuz-/initramfs-}.img"
    # [ ! -f "$initrd_path" ] && err "致命错误: 未找到与内核匹配的 initramfs 文件: $initrd_path"
    
    # root_device=$(findmnt -n -o SOURCE /)
    # [ -z "$root_device" ] && err "致命错误: 无法确定根分区设备！"
    
    # root_uuid=$(blkid -s UUID -o value "$root_device")
    # if [ -n "$root_uuid" ]; then
    #     root_identifier="UUID=$root_uuid"
    #     echo "使用 UUID ($root_uuid) 作为根分区"
    # else
    #     root_identifier="$root_device"
    #     echo "警告: 无法获取 UUID，将直接使用设备路径 ($root_device) 作为根分区"
    # fi

    # grubby --add-kernel="$kernel_path" \
    #        --initrd="$initrd_path" \
    #        --args="root=$root_identifier console=ttyS0,115200n8 console=tty0 net.ifnames=0 biosdevname=0" \
    #        --title="${system}-reinstalled-$(date +%Y%m%d)" \
    #        --make-default || err "grubby 添加内核引导项失败！"

    # --- 系统配置 ---
    localectl set-locale LANG=zh_CN.UTF-8

    echo "配置 SSH 服务..."
    sed -i -e 's/^#*Port .*/Port 22/' \
           -e 's/^#*PermitRootLogin .*/PermitRootLogin yes/' \
           -e 's/^#*PasswordAuthentication .*/PasswordAuthentication yes/' \
           -e 's/^#*UseDNS .*/UseDNS no/' /etc/ssh/sshd_config
    [ -n "$ssh_port" ] && sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config
    systemctl enable sshd

    echo "设置 root 用户密码..."
    local final_password="${password:-blog.ylx.me}"
    echo "$final_password" | passwd --stdin "root"
    [ "$final_password" == "blog.ylx.me" ] && echo "警告：root 密码设置为默认值，请在首次登录后更改！"

    if [ -n "$authorized_keys_url" ]; then
        echo "从 $authorized_keys_url 下载并配置 SSH 公钥..."
        mkdir -p -m 0700 /root/.ssh
        if curl -sSLf --connect-timeout 10 "$authorized_keys_url" -o /root/.ssh/authorized_keys; then
            chmod 0600 /root/.ssh/authorized_keys
            sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
            echo "SSH 公钥配置完成，密码登录已禁用"
        else
            echo "警告：无法下载 SSH 公KEY：$authorized_keys_url"
        fi
    fi

    # --- 网络配置 ---
    local ifcfg_file="/etc/sysconfig/network-scripts/ifcfg-${network_adapter}"
    echo "配置网络: $ifcfg_file"
    systemctl enable network

    if [ "$is_auto" -eq 1 ]; then
        # 静态IP配置
        cat >"$ifcfg_file" <<EOFILE
DEVICE=${network_adapter}
BOOTPROTO=static
ONBOOT=yes
IPADDR=${main_ip}
NETMASK=${netmask}
GATEWAY=${gateway_ip}
DNS1=${dns1:-8.8.8.8}
DNS2=${dns2:-1.1.1.1}
EOFILE
        [ "$is_cn" -eq 1 ] && sed -i -e 's/DNS1=.*/DNS1=223.5.5.5/' -e 's/DNS2=.*/DNS2=114.114.114.114/' "$ifcfg_file"
        
        if [ "$use_native_ipv6" == "1" ]; then
            cat >>"$ifcfg_file" <<EOFILE
IPV6INIT=yes
IPV6ADDR=${native_ipv6_addr}/${native_ipv6_mask}
IPV6_DEFAULTGW=${native_ipv6_gw}
EOFILE
        fi
    else
        # 动态IP配置 (DHCP)
        cat >"$ifcfg_file" <<EOFILE
DEVICE=${network_adapter}
BOOTPROTO=dhcp
ONBOOT=yes
IPV6INIT=yes
IPV6_AUTOCONF=yes
EOFILE
    fi

    # HE.net 隧道配置
    if [ "$use_he_tunnel" == "1" ]; then
        cat > "/etc/sysconfig/network-scripts/ifcfg-he-ipv6" <<EOFILE
DEVICE=he-ipv6
BOOTPROTO=none
ONBOOT=yes
IPV6INIT=yes
IPV6TUNNEL=yes
IPV6TUNNEL_TYPE=sit
IPV6TUNNEL_REMOTE=${he_server_ipv4}
IPV6TUNNEL_LOCAL=${he_client_ipv4}
IPV6ADDR=${he_client_ipv6}/${he_netmask}
EOFILE
        echo "default via ${he_server_ipv6} dev he-ipv6" > "/etc/sysconfig/network-scripts/route6-he-ipv6"
    fi

    # --- 其他配置 ---
    # 配置主机名
    echo "$hostname" >/etc/hostname
    echo "127.0.0.1 $hostname" >>/etc/hosts
    
    # 配置时区
    if [ -f "/usr/share/zoneinfo/$timezone" ]; then
        ln -sf "/usr/share/zoneinfo/$timezone" /etc/localtime
    else
        echo "警告: 时区文件 /usr/share/zoneinfo/$timezone 未找到。"
    fi

	# 下载 tcpx.sh
    echo "尝试下载 tcpx.sh ..."
    local tcpx_sh_url="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
    [ "$region" == "cn" ] && tcpx_sh_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
    if wget --connect-timeout=15 -T 10 -O /root/tcpx.sh "$tcpx_sh_url"; then
        chmod +x /root/tcpx.sh
        echo "tcpx.sh 下载成功，可在系统启动后运行 /root/tcpx.sh"
    else
        echo "警告：tcpx.sh 下载失败，跳过此步骤"
    fi
}

# 获取当前系统 IP 信息
get_ip() {
    main_ip=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
    [ -z "$main_ip" ] && main_ip=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)
    [ -z "$main_ip" ] && return 1

    gateway_ip=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -1)
    [ -z "$gateway_ip" ] && return 1

    subnet=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d'/' -f2 | head -1)
    [ -z "$subnet" ] && subnet=24
    
    local value=$((0xffffffff ^ ((1 << (32 - subnet)) - 1)))
    netmask="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"
    return 0
}

# 检查 IPv6 配置
check_ipv6() {
    local ipv6_addr
    ipv6_addr=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+/[0-9]+' | head -1)
    [ -n "$ipv6_addr" ] && has_ipv6=1 || has_ipv6=0
}

# 设置网络参数
set_network() {
    [ "$region" == "cn" ] && is_cn=1
    
    # 检测当前是否为静态IP
    is_auto=0
    if grep -q -E "iface.*inet static" /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null || \
       grep -q -E "BOOTPROTO.*[sS][tT][aA][tT][iI][cC]" /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null; then
        is_auto=1
    fi
    
    check_ipv6
}

# 设置网络模式
net_mode() {
    if [ "$is_auto" -eq 0 ]; then
        read -p "当前为动态 IP (DHCP)，是否在新系统中继续使用 DHCP？[Y/n]: " input
        [[ "$input" =~ ^[nN]$ ]] && is_auto=1
    fi

    if [ "$is_auto" -eq 1 ]; then
        if ! get_ip; then
            echo "自动检测 IPv4 配置失败，请手动输入："
            read -r -p "请输入 IP 地址: " main_ip
            read -r -p "请输入网关地址: " gateway_ip
            read -r -p "请输入子网掩码: " netmask
        fi
        echo "将使用以下静态 IPv4 配置："
        echo "IP: $main_ip"
        echo "网关: $gateway_ip"
        echo "子网掩码: $netmask"
        read -p "确认使用以上配置？[Y/n]: " input
        if [[ "$input" =~ ^[nN]$ ]]; then
            read -r -p "请输入 IP 地址: " main_ip
            read -r -p "请输入网关地址: " gateway_ip
            read -r -p "请输入子网掩码: " netmask
        fi
    fi

    if [ "$has_ipv6" -eq 1 ]; then
        read -p "检测到 IPv6，是否在新系统中启用？[Y/n]: " input
        [[ "$input" =~ ^[yY]?$ ]] && use_native_ipv6=1
    fi
}

# --- 主执行流程 ---
main() {
    choose_system
    set_network
    net_mode
    get_versions
    download_image

    delete_old_system
    extract_image
    init_os

    # 清理临时文件并提示重启
    echo "系统安装成功"
    rm -rf "$root_dir" || echo "警告：无法删除 $root_dir 目录"
    
    # 清理包管理器缓存
    if command -v dnf >/dev/null 2>&1; then
        dnf clean all
    elif command -v yum >/dev/null 2>&1; then
        yum clean all
    fi

    echo "正在强制将缓存数据写入磁盘..."
sync; sync; sync
sleep 5
echo "数据同步完成"
mount -o remount,rw /
sync; sync; sync
sleep 10
echo "数据同步完成"

echo "安装完成，建议重启系统"
echo "确认无严重错误，请选择重启方式："
echo "1: 性能机 - 10秒后重启"
echo "2: 一般机 - 30秒后重启"
echo "3: 钻石机 - 2分钟后重启"

read -t 10 -p "请输入选项（1/2/3，10s后默认2）: " choice

[ -z "$choice" ] && choice=2

case "$choice" in
    1)
        echo "性能机模式：10秒后重启..."
        sleep 10
        ;;
    2)
        echo "一般机模式：30秒后重启..."
        sleep 30
        ;;
    3)
        echo "钻石机模式：2分钟后重启..."
        sleep 120
        ;;
    *)
        echo "无效选项，默认使用一般机模式：30秒后重启..."
        sleep 30
        ;;
esac

echo "系统正在重启..."
reboot -f
}

main
