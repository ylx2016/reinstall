#!/usr/bin/env bash

# 目的：重新安装 Debian 或 Ubuntu 系统，支持自定义网络和系统设置
# 环境设置
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
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
    echo "错误：$1" >&2
    exit 1
}

# 使用帮助信息
usage() {
    cat <<EOF
用法: $0 [选项]
选项:
  --authorized-keys-url URL  设置 SSH 公钥 URL
  --password PASS           设置 root 密码
  --ssh-port PORT           设置 SSH 端口 (1-65535)
  --hostname NAME           设置主机名
  --apt-mirror URL          设置 APT 镜像 URL
  --region {cn|global}      设置区域
  --timezone ZONE           设置时区
  --help                    显示此帮助信息
EOF
    exit 0
}

# 解析命令行参数
while [ $# -gt 0 ]; do
    case $1 in
        --authorized-keys-url) authorized_keys_url="$2"; shift ;;
        --password) password="$2"; shift ;;
        --ssh-port)
            if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                err "无效的 SSH 端口 '$2'，必须为 1-65535 之间的整数"
            fi
            ssh_port="$2"
            shift
            ;;
        --hostname) hostname="$2"; shift ;;
        --apt-mirror) apt_mirror_url="$2"; shift ;;
        --region)
            if [[ "$2" != "cn" && "$2" != "global" ]]; then
                err "无效的区域 '$2'，请使用 'cn' 或 'global'"
            fi
            region="$2"
            shift
            ;;
        --timezone) timezone="$2"; shift ;;
        --help) usage ;;
        *) err "未知选项：'$1'" ;;
    esac
    shift
done

# 确保 bash 软链接存在
[ ! -f "/usr/bin/bash" ] && ln -s "$(which bash)" /usr/bin/bash

# 安装必要工具
install_tool() {
    local tool=$1
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "正在安装 $tool..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y "$tool"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "$tool"
        else
            err "未知的包管理器，请手动安装 $tool"
        fi
    else
        echo "$tool 已安装，继续执行"
    fi
}

install_tool curl
install_tool wget
install_tool zip
install_tool tar

# 获取系统架构
arch=$(uname -m)

# 选择操作系统
choose_system() {
    echo "请选择要安装的系统："
    echo "1. Debian"
    echo "2. Ubuntu"
    while true; do
        read -p "请输入数字 (1 或 2)： " choice
        case "$choice" in
            1) system="debian"; base_url="https://images.linuxcontainers.org/images/debian"; cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/debian"; break ;;
            2) system="ubuntu"; base_url="https://images.linuxcontainers.org/images/ubuntu"; cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/ubuntu"; break ;;
            *) echo "无效输入，请输入 1 或 2" ;;
        esac
    done
    echo "已选择系统：$system"
}

# 获取可用版本
get_versions() {
    local versions_file="/tmp/versions.txt"
    declare -A version_map
    if [ "$system" == "debian" ]; then
        version_map=(
            ["bookworm"]="Debian 12"
            ["bullseye"]="Debian 11"
            ["buster"]="Debian 10"
            ["trixie"]="Debian 13 (测试版)"
        )
    else
        version_map=(
            ["focal"]="Ubuntu 20.04 (Focal Fossa)"
            ["jammy"]="Ubuntu 22.04 (Jammy Jellyfish)"
            ["noble"]="Ubuntu 24.04 (Noble Numbat)"
            ["oracular"]="Ubuntu 24.10 (Oracular Oriole)"
            ["plucky"]="Ubuntu 25.04 (Plucky Puffin)"
        )
    fi

    echo "正在获取支持的 $system 版本..."
    curl -s -L "$base_url" -o "$versions_file" || err "无法获取版本列表：$base_url"
    mapfile -t all_versions < <(grep -oP '[a-z]+(?=/)' "$versions_file" | sort -u)
    declare -a versions
    for version in "${all_versions[@]}"; do
        [ -n "${version_map[$version]}" ] && versions+=("$version")
    done

    if [ ${#versions[@]} -eq 0 ]; then
        err "未检测到支持的 $system 版本"
    fi

    echo "支持的 $system 版本："
    for i in "${!versions[@]}"; do
        echo "$((i + 1)). ${versions[$i]} (${version_map[${versions[$i]}]})"
    done

    while true; do
        read -p "请选择要安装的版本（输入数字 1-${#versions[@]}）： " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#versions[@]}" ]; then
            selected_version="${versions[$((choice - 1))]}"
            echo "已选择版本：$selected_version (${version_map[$selected_version]})"
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
    local timeout=10
    local busybox_url=""
    local cn_busybox_url=""
    local busybox_filename=""

    # 设置架构相关变量
    case "$arch" in
        x86_64)
            image_arch="amd64"
            busybox_url="https://raw.githubusercontent.com/ylx2016/reinstall/master/busybox_1.32.1"
            cn_busybox_url="https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64"
            busybox_filename="busybox-x86_64-linux-gnu"
            ;;
        aarch64)
            image_arch="arm64"
            busybox_url="https://raw.githubusercontent.com/iweizime/static-binaries/master/arm64/linux/busybox"
            cn_busybox_url="$busybox_url"
            busybox_filename="busybox-aarch64-linux-gnu"
            ;;
        *) err "不支持的系统架构：$arch" ;;
    esac

    mkdir -p "$root_dir" || err "无法创建 $root_dir 目录"

    # 获取时间戳列表
    local list_url="$base_url/$version/$image_arch/cloud/?C=M;O=D"
    echo "正在获取可用镜像时间戳列表..."
    curl -s -L "$list_url" -o /tmp/url.tmp || err "无法获取时间戳列表：$list_url"
    mapfile -t timestamp_list < <(grep -oP '2[0-9]{7}[\_]..[\:]..' /tmp/url.tmp)

    if [ ${#timestamp_list[@]} -eq 0 ]; then
        err "未检测到任何可用时间戳目录"
    fi

    echo "可用镜像时间戳："
    for i in "${!timestamp_list[@]}"; do
        echo "$((i + 1)). ${timestamp_list[$i]}"
    done

    while true; do
        read -p "请选择要使用的镜像时间戳（输入数字 1-${#timestamp_list[@]}）： " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#timestamp_list[@]}" ]; then
            timestamp="${timestamp_list[$((choice - 1))]}"
            echo "已选择时间戳：$timestamp"
            break
        else
            echo "无效输入，请输入 1 到 ${#timestamp_list[@]} 之间的数字"
        fi
    done

    # 设置下载 URL
    local img_url="$base_url/$version/$image_arch/cloud/$timestamp/$file"
    local cn_img_url="$cn_base_url/$version/$image_arch/cloud/$timestamp/$file"
    local url="$img_url"
    local checksum_url="$base_url/$version/$image_arch/cloud/$timestamp/SHA256SUMS"

    # 下载镜像文件
    echo "开始下载镜像文件：$url"
    local remote_size=$(curl -sI -L "$url" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r')
    local size_check=1
    [ -z "$remote_size" ] && { echo "警告：无法获取远程文件大小，跳过大小验证"; size_check=0; }

    local checksum_available=1
    if ! curl -s -L "$checksum_url" -o "SHA256SUMS"; then
        echo "警告：无法下载校验和文件 $checksum_url，跳过 SHA256 验证"
        checksum_available=0
    else
        expected_checksum=$(grep "$file" SHA256SUMS | awk '{print $1}')
        [ -z "$expected_checksum" ] && { echo "警告：校验和文件中未找到 $file 的校验和"; checksum_available=0; }
    fi

    for ((i=1; i<=attempts; i++)); do
        echo "尝试下载镜像（第 $i 次）..."
        if curl -SL --retry 2 --connect-timeout "$timeout" -o "$os_filename" "$url"; then
            break
        elif [ "$i" -eq "$attempts" ]; then
            echo "尝试中国镜像：$cn_img_url"
            url="$cn_img_url"
            checksum_url="$cn_base_url/$version/$image_arch/cloud/$timestamp/SHA256SUMS"
            for ((j=1; j<=attempts; j++)); do
                echo "尝试下载镜像（第 $j 次）..."
                if curl -SL --retry 2 --connect-timeout "$timeout" -o "$os_filename" "$url"; then
                    break
                elif [ "$j" -eq "$attempts" ]; then
                    err "下载镜像失败：$url 在 $attempts 次尝试后仍未成功"
                fi
                sleep 5
            done
            if ! curl -s -L "$checksum_url" -o "SHA256SUMS"; then
                checksum_available=0
            else
                expected_checksum=$(grep "$file" SHA256SUMS | awk '{print $1}')
                [ -z "$expected_checksum" ] && checksum_available=0
            fi
            break
        fi
        sleep 5
    done

    # SHA256存在则不校验大小
    if [ "$checksum_available" -eq 1 ]; then
        size_check=0
        echo "SHA256存在，不校验大小"
    fi    

    # 验证镜像文件大小
    if [ "$size_check" -eq 1 ]; then
        echo "验证镜像文件大小..."
        local local_size=$(stat -c%s "$os_filename" 2>/dev/null || wc -c <"$os_filename")
        if [ "$local_size" -eq "$remote_size" ]; then
            echo "镜像文件大小匹配：$local_size 字节"
        else
            err "镜像文件大小不匹配，下载可能不完整！本地大小: $local_size 字节，远程大小: $remote_size 字节"
        fi
    fi

    # 验证镜像文件 SHA256 校验和
    if [ "$checksum_available" -eq 1 ]; then
        echo "验证镜像文件 SHA256 校验和..."
        local actual_checksum=$(sha256sum "$os_filename" | awk '{print $1}')
        if [ "$actual_checksum" == "$expected_checksum" ]; then
            echo "镜像文件 SHA256 校验和匹配，文件完整性验证通过"
        else
            err "镜像文件 SHA256 校验和不匹配，文件可能损坏！期望值: $expected_checksum，实际值: $actual_checksum"
        fi
    fi

    # 下载 BusyBox
    local busybox_base_url="https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
    [ "$region" == "cn" ] && busybox_base_url="https://ghproxy.net/https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
    local current_busybox_url="${busybox_base_url}${busybox_filename}"

    echo "开始下载 BusyBox：$current_busybox_url"
    local remote_size=$(curl -sIL "$current_busybox_url" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r\n')
    [ -z "$remote_size" ] && echo "警告：无法获取 BusyBox 远程文件大小"

    local download_successful=0
    for ((i=1; i<=attempts; i++)); do
        echo "尝试下载 BusyBox（第 $i/$attempts 次）..."
        if curl -SLf --retry 2 --connect-timeout "$timeout" -o "$busybox_path" "$current_busybox_url"; then
            download_successful=1
            break
        else
            echo "BusyBox 下载尝试 $i 失败"
            sleep 5
        fi
    done

    [ "$download_successful" -ne 1 ] && err "下载 BusyBox 失败：$current_busybox_url"

    chmod +x "$busybox_path" || err "无法为 $busybox_path 设置可执行权限"
    if "$busybox_path" --help >/dev/null 2>&1; then
        echo "BusyBox 测试成功"
    else
        err "BusyBox 测试失败：$busybox_path"
    fi

    if [ -n "$remote_size" ] && [ "$remote_size" != "0" ]; then
        local local_size=$(stat -c%s "$busybox_path" 2>/dev/null || wc -c <"$busybox_path")
        if [ "$local_size" -eq "$remote_size" ]; then
            echo "BusyBox 文件大小匹配：$local_size 字节"
        else
            echo "警告：BusyBox 文件大小不匹配。本地: $local_size，远程: $remote_size"
        fi
    fi

    rm -f SHA256SUMS /tmp/url.tmp
}

# 删除旧系统文件
delete_old_system() {
    [ ! -f "$busybox_path" ] && err "BusyBox 文件缺失：$busybox_path"
    "$busybox_path" --help >/dev/null 2>&1 || err "BusyBox 不可执行：$busybox_path"

    cp /etc/fstab "$root_dir" || echo "警告：无法备份 fstab"
    local sys_bios=0 sys_efi=0

    if [ -d "/sys/firmware/efi" ]; then
        sys_efi=1
    else
        sys_bios=1
    fi

    if command -v chattr >/dev/null 2>&1; then
        find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$root_dir/*" \) \
            -exec chattr -i {} + 2>/dev/null || true
    fi
    find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$root_dir/*" \) -delete 2>/dev/null || true
}

# 解压新系统镜像
extract_image() {
    if [ -e "/etc/machine-id" ]; then
        echo "尝试移除旧的 /etc/machine-id..."
        if command -v chattr >/dev/null 2>&1; then
            chattr -i /etc/machine-id 2>/dev/null
        fi
        rm -f /etc/machine-id || echo "警告：无法删除旧的 /etc/machine-id"
    fi
    echo "开始解压系统镜像..."

    cd "$root_dir"
    local xzcat="$busybox_path xzcat"
    local tar="$busybox_path tar"
    $xzcat "$root_dir/os.tar.xz" | $tar -x -C /
    mv -f "$root_dir/fstab" /etc
}

# 初始化新系统
init_os() {
    cd /
    # 配置 DNS
    rm -rf /etc/resolv.conf
    touch /etc/resolv.conf
    if [ "$is_cn" == '1' ]; then
        echo "nameserver 114.114.114.114" >/etc/resolv.conf
        echo "nameserver 223.5.5.5" >>/etc/resolv.conf
    else
        echo "nameserver 1.1.1.1" >/etc/resolv.conf
        echo "nameserver 8.8.8.8" >>/etc/resolv.conf
        echo "nameserver 9.9.9.9" >>/etc/resolv.conf
    fi
    rm -f /root/anaconda-ks.cfg
    export LC_ALL=C.UTF-8

    echo "配置 APT 软件源..."
    local final_apt_mirror_url="$apt_mirror_url"
    if [ -z "$final_apt_mirror_url" ]; then
        if [ "$is_cn" == '1' ]; then
            if [ "$system" == "debian" ]; then
                final_apt_mirror_url="https://mirrors.ustc.edu.cn/debian"
            elif [ "$system" == "ubuntu" ]; then
                final_apt_mirror_url="https://mirrors.ustc.edu.cn/ubuntu"
            fi
            echo "未指定 --apt-mirror，使用中国区域镜像：$final_apt_mirror_url"
        else
            if [ "$system" == "debian" ]; then
                final_apt_mirror_url="http://deb.debian.org/debian"
            elif [ "$system" == "ubuntu" ]; then
                final_apt_mirror_url="http://archive.ubuntu.com/ubuntu"
            fi
            echo "未指定 --apt-mirror，使用官方镜像：$final_apt_mirror_url"
        fi
    else
        echo "使用用户指定的 APT 镜像：$final_apt_mirror_url"
    fi

    if [ -f "/etc/apt/sources.list" ]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.bak."$(date +%s)"
        echo "已备份原始 /etc/apt/sources.list 文件"
    fi
    echo "" >/etc/apt/sources.list

    local codename="$selected_version"
    if [ "$system" == "debian" ]; then
        local components="main contrib non-free"
        [[ "$codename" == "bookworm" || "$codename" == "trixie" ]] && components="main contrib non-free non-free-firmware"
        echo "deb $final_apt_mirror_url $codename $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-updates $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-backports $components" >>/etc/apt/sources.list
        local security_mirror_url="http://security.debian.org/debian-security"
        echo "deb $security_mirror_url $codename-security $components" >>/etc/apt/sources.list
    elif [ "$system" == "ubuntu" ]; then
        local components="main restricted universe multiverse"
        echo "deb $final_apt_mirror_url $codename $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-updates $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-backports $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-security $components" >>/etc/apt/sources.list
    fi
    echo "APT 软件源配置完成"

    # 更新软件源
    apt-get update || err "无法更新软件源"

    # 安装软件包
    if [ "$system" == "debian" ]; then
        if [ "$arch" == "x86_64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-cloud-amd64 htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 x86_64 软件包失败"
        elif [ "$arch" == "aarch64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-arm64 htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 aarch64 软件包失败"
        fi
    elif [ "$system" == "ubuntu" ]; then
        if [ "$arch" == "x86_64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-virtual htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 x86_64 软件包失败"
        elif [ "$arch" == "aarch64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-virtual htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 aarch64 软件包失败"
        fi
    else
        err "未知系统类型：$system"
    fi

    echo "安装 GRUB 引导加载程序..."
    apt-get install -y grub2 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装 GRUB 失败"

    # 检测磁盘
    local grub_device=""
    mapfile -t potential_disks < <(lsblk -nd -o NAME,TYPE,RO,RM | awk '$2=="disk" && $3=="0" && $4=="0" {print "/dev/"$1}')

    if [ ${#potential_disks[@]} -eq 0 ]; then
        grub_device=$(fdisk -l 2>/dev/null | grep -Eo '/dev/[sv]d[a-z]+|/dev/nvme[0-9]+n[0-9]+|/dev/xvd[a-z]+|/dev/vd[a-z]+' | head -1)
        [ -z "$grub_device" ] && err "无法自动检测到合适的磁盘设备用于 GRUB 安装"
        echo "检测到磁盘 $grub_device 用于 GRUB 安装"
    elif [ ${#potential_disks[@]} -eq 1 ]; then
        grub_device="${potential_disks[0]}"
        local disk_size=$(lsblk -b -d -o SIZE "${grub_device}" | tail -n 1 | awk '{print $1/1024/1024/1024 " GB"}')
        echo "自动选择磁盘 $grub_device (大小: ${disk_size}) 用于 GRUB 安装"
    else
        echo "检测到多个磁盘设备，请选择安装 GRUB 的主系统引导盘:"
        for i in "${!potential_disks[@]}"; do
            local disk_info=$(lsblk -b -d -o SIZE,MODEL "${potential_disks[$i]}" | tail -n 1 | awk '{model=$2; for(j=3;j<=NF;j++) model=model"_"$j; printf "大小: %.2f GB, 型号: %s\n", $1/1024/1024/1024, model}')
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
    read -p "确认磁盘选择正确？按 Enter 继续，按 Ctrl+C 中止"

    if [ -d "/sys/firmware/efi" ]; then
        echo "检测到 EFI 模式，安装 GRUB-EFI..."
        local grub_efi_pkg=""
        local grub_target=""
        if [ "$arch" == "x86_64" ]; then
            grub_efi_pkg="grub-efi-amd64"
            grub_target="x86_64-efi"
        elif [ "$arch" == "aarch64" ]; then
            grub_efi_pkg="grub-efi-arm64"
            grub_target="arm64-efi"
            apt-get install -y efibootmgr || echo "警告: efibootmgr 安装失败，但继续尝试 GRUB 安装"
        else
            err "不支持的 EFI 架构: $arch"
        fi
        apt-get install -y "$grub_efi_pkg" || err "安装 $grub_efi_pkg 失败"
        mkdir -p /boot/efi
        grub-install --target="$grub_target" --efi-directory=/boot/efi --bootloader-id="$system" --recheck "$grub_device" || err "GRUB EFI 安装失败"

        local efi_file_path="/boot/efi/EFI/$system/grubx64.efi"
        [ "$arch" == "aarch64" ] && efi_file_path="/boot/efi/EFI/$system/grubaa64.efi"
        if [ ! -f "$efi_file_path" ]; then
            err "验证失败：GRUB EFI 关键文件 $efi_file_path 未找到，请勿重启！"
        else
            echo "验证成功：GRUB EFI 关键文件已找到"
        fi

        if [ "$arch" == "x86_64" ] && [ -f "/boot/efi/EFI/$system/grubx64.efi" ]; then
            mkdir -p /boot/efi/EFI/BOOT
            cp "/boot/efi/EFI/$system/grubx64.efi" /boot/efi/EFI/BOOT/BOOTX64.EFI
            echo "已复制 grubx64.efi 到 /boot/efi/EFI/BOOT/BOOTX64.EFI"
        elif [ "$arch" == "aarch64" ] && [ -f "/boot/efi/EFI/$system/grubaa64.efi" ]; then
            mkdir -p /boot/efi/EFI/BOOT
            cp "/boot/efi/EFI/$system/grubaa64.efi" /boot/efi/EFI/BOOT/BOOTAA64.EFI
            echo "已复制 grubaa64.efi 到 /boot/efi/EFI/BOOT/BOOTAA64.EFI"
        fi
    else
        echo "检测到 BIOS 模式，安装 GRUB-PC 到 $grub_device ..."
        grub-install --target=i386-pc --boot-directory=/boot --recheck "$grub_device" || err "GRUB BIOS 安装失败"

        if [ ! -f "/boot/grub/i386-pc/normal.mod" ]; then
            err "验证失败：GRUB BIOS 关键文件 /boot/grub/i386-pc/normal.mod 未找到，请勿重启！"
        else
            echo "验证成功：GRUB BIOS 关键文件已找到"
        fi
    fi
    update-grub || err "更新 GRUB 配置失败"

    echo "正在强制将缓存数据写入磁盘..."
    sync; sync; sync
    sleep 5
    echo "数据同步完成"

    echo "配置 SSH 服务..."
    if [ ! -f "/etc/ssh/sshd_config" ]; then
        echo "警告：/etc/ssh/sshd_config 未找到，SSH 可能无法启动"
    else
        if ! grep -q "^Port " /etc/ssh/sshd_config; then echo "Port 22" >>/etc/ssh/sshd_config; fi
        [ -n "$ssh_port" ] && sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config || sed -i "s/^Port .*/Port 22/" /etc/ssh/sshd_config
        if grep -q "^#*PermitRootLogin" /etc/ssh/sshd_config; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        else
            echo "PermitRootLogin yes" >>/etc/ssh/sshd_config
        fi
        if grep -q "^#*PasswordAuthentication" /etc/ssh/sshd_config; then
            sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        else
            echo "PasswordAuthentication yes" >>/etc/ssh/sshd_config
        fi
        sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/^#*GSSAPIAuthentication .*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/^#*ClientAliveInterval .*/ClientAliveInterval 60/' /etc/ssh/sshd_config
        sed -i 's/^#*UseDNS .*/UseDNS no/' /etc/ssh/sshd_config
    fi
    systemctl enable ssh

    echo "设置 root 用户密码..."
    local final_password="${password:-blog.ylx.me}"
    echo -e "$final_password\n$final_password" | passwd "root"
    if [ "$final_password" == "blog.ylx.me" ]; then
        echo "警告：root 密码设置为默认值 'blog.ylx.me'，请在首次登录后更改！"
    else
        echo "root 密码已根据用户输入设置"
    fi

    if [ -n "$authorized_keys_url" ]; then
        echo "从 $authorized_keys_url 下载并配置 SSH 公钥..."
        mkdir -p -m 0700 /root/.ssh
        if curl -sSLf --connect-timeout 10 "$authorized_keys_url" -o /root/.ssh/authorized_keys; then
            chmod 0600 /root/.ssh/authorized_keys
            sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
            echo "SSH 公钥配置完成，密码登录已禁用"
        else
            echo "警告：无法下载 SSH 公钥：$authorized_keys_url"
        fi
    fi

    echo "应用系统优化配置..."
    echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
    if [ -f "/etc/default/grub" ]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="[^"]*"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /etc/default/grub
        if ! grep -q "GRUB_CMDLINE_LINUX=" /etc/default/grub; then
            echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' >>/etc/default/grub
        fi
        update-grub
    else
        echo "警告：/etc/default/grub 未找到，无法修改内核参数"
    fi

    # 网络配置
    systemctl enable networking
    if [ "$is_auto" == '1' ]; then
        cat >/etc/network/interfaces <<EOFILE
auto lo
iface lo inet loopback

auto $network_adapter
iface $network_adapter inet static
    address $main_ip
    netmask $netmask
    gateway $gateway_ip
EOFILE
        if [ "$use_native_ipv6" == "1" ]; then
            cat >>/etc/network/interfaces <<EOFILE
iface $network_adapter inet6 static
    address $native_ipv6_addr
    netmask $native_ipv6_mask
    gateway $native_ipv6_gw
EOFILE
        fi
    else
        cat >/etc/network/interfaces <<EOFILE
auto lo
iface lo inet loopback

auto $network_adapter
iface $network_adapter inet dhcp
iface $network_adapter inet6 dhcp
EOFILE
    fi

    if [ "$use_he_tunnel" == "1" ]; then
        cat >>/etc/network/interfaces <<EOFILE
auto he-ipv6
iface he-ipv6 inet6 v4tunnel
    address $he_client_ipv6
    netmask $he_netmask
    endpoint $he_server_ipv4
    local $he_client_ipv4
    ttl 255
    gateway $he_server_ipv6
EOFILE
    fi

    # 系统限制
    cat >>/etc/security/limits.conf <<EOFILE
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOFILE

    mkdir -p /etc/systemd/system/networking.service.d/
    echo -e "[Service]\nTimeoutStartSec=15sec" >/etc/systemd/system/networking.service.d/timeout.conf

    # 配置 DNS
    if [ "$is_cn" == '1' ]; then
        echo "nameserver 114.114.114.114" >/etc/resolv.conf
        echo "nameserver 223.5.5.5" >>/etc/resolv.conf
    else
        echo "nameserver 1.1.1.1" >/etc/resolv.conf
        echo "nameserver 8.8.8.8" >>/etc/resolv.conf
        echo "nameserver 9.9.9.9" >>/etc/resolv.conf
    fi
    echo "precedence ::ffff:0:0/96 100" >>/etc/gai.conf

    # 配置主机名
    rm -rf /etc/hostname
    touch /etc/hostname
    [ -n "$hostname" ] && echo "$hostname" >/etc/hostname || echo "debian-$(date +%Y%m%d)" >/etc/hostname
    echo "127.0.0.1 $(cat /etc/hostname)" >>/etc/hosts

    # 配置时区
    echo "配置时区：$timezone ..."
    if [ -f "/usr/share/zoneinfo/$timezone" ]; then
        echo "$timezone" >/etc/timezone
        ln -sf "/usr/share/zoneinfo/$timezone" /etc/localtime
        dpkg-reconfigure -f noninteractive tzdata || echo "警告：dpkg-reconfigure tzdata 失败，但时区已设置"
    else
        echo "警告：时区文件 /usr/share/zoneinfo/$timezone 未找到，使用 Etc/UTC"
        echo "Etc/UTC" >/etc/timezone
        ln -sf "/usr/share/zoneinfo/Etc/UTC" /etc/localtime
        dpkg-reconfigure -f noninteractive tzdata || echo "警告：dpkg-reconfigure tzdata 失败 (UTC)"
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

    ln -fs /usr/bin/bash /usr/bin/sh
}

# 获取当前系统 IP 信息
get_ip() {
    main_ip=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
    if [ -z "$main_ip" ]; then
        main_ip=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)
    fi
    [ -z "$main_ip" ] && { echo "警告：无法自动检测主 IP"; return 1; }

    gateway_ip=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -1)
    [ -z "$gateway_ip" ] && { echo "警告：无法自动检测网关"; return 1; }

    subnet=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+/\d+' | head -1 | cut -d'/' -f2)
    if [ -z "$subnet" ]; then
        echo "警告：无法自动检测子网掩码，假设为 24"
        subnet=24
    fi
    value=$((0xffffffff ^ ((1 << (32 - $subnet)) - 1)))
    netmask="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"
    return 0
}

# 检查 IPv6 配置
check_ipv6() {
    ipv6_addr=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+/[0-9]+' | head -1)
    if [ -n "$ipv6_addr" ]; then
        echo "检测到 IPv6 地址：$ipv6_addr"
        has_ipv6=1
    else
        echo "未检测到 IPv6 地址"
        has_ipv6=0
    fi

    native_ipv6_iface=$(ip -6 addr show scope global | grep -B1 "$ipv6_addr" | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -E '^(eth|en)' | head -1)
    if [ -n "$native_ipv6_iface" ]; then
        echo "检测到原生 IPv6（接口：$native_ipv6_iface）"
        has_native_ipv6=1
        native_ipv6_addr=$(echo "$ipv6_addr" | cut -d'/' -f1)
        native_ipv6_mask=$(echo "$ipv6_addr" | cut -d'/' -f2)
        native_ipv6_gw=$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)
        echo "原生 IPv6 信息：地址: $native_ipv6_addr，掩码: $native_ipv6_mask，网关: $native_ipv6_gw"
    else
        has_native_ipv6=0
    fi

    if [ "$has_ipv6" == "1" ]; then
        tunnel_iface=$(ip -6 addr show scope global | grep -B1 "$ipv6_addr" | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -v -E '^(eth|en)' | head -1)
        if [ -n "$tunnel_iface" ] && ip tunnel show "$tunnel_iface" | grep -q "ipv6/ip"; then
            if echo "$ipv6_addr" | grep -q "^2001:470:"; then
                echo "检测到 HE.net 6in4 隧道（接口：$tunnel_iface）"
                he_tunnel=1
                he_client_ipv4=$(ip tunnel show "$tunnel_iface" | grep -oP 'local \K[\d.]+')
                he_server_ipv4=$(ip tunnel show "$tunnel_iface" | grep -oP 'remote \K[\d.]+')
                he_client_ipv6=$(echo "$ipv6_addr" | cut -d'/' -f1)
                he_netmask=$(echo "$ipv6_addr" | cut -d'/' -f2)
                he_server_ipv6=$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)
                [ -z "$he_server_ipv6" ] && he_server_ipv6=$(echo "$he_client_ipv6" | sed 's/::2$/::1/')
                echo "隧道信息：客户端 IPv4: $he_client_ipv4，服务器 IPv4: $he_server_ipv4，客户端 IPv6: $he_client_ipv6，服务器 IPv6: $he_server_ipv6"
            else
                he_tunnel=0
            fi
        else
            he_tunnel=0
        fi
    else
        he_tunnel=0
    fi

    [ "$has_ipv6" == "0" ] && [ "$he_tunnel" == "0" ] && [ "$has_native_ipv6" == "0" ] && return 1
    return 0
}

# 测试 IPv6 连通性
test_ipv6() {
    ping6 -c 4 2001:4860:4860::8888 >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo "IPv6 连通性测试成功"
        return 0
    else
        echo "IPv6 连通性测试失败"
        return 1
    fi
}

# 检查 IP 配置合法性
ip_check() {
    local is_legal=0
    for addr in "$main_ip" "$gateway_ip" "$netmask"; do
        if [ -z "$addr" ]; then
            echo "错误：IP、网关或子网掩码为空"
            is_legal=1
        elif ! is_valid_ip "$addr"; then
            echo "错误：无效的 IP 地址 '$addr'"
            is_legal=1
        fi
    done
    return $is_legal
}

# 验证 IP 地址格式
is_valid_ip() {
    local ip=$1
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    IFS='.' read -r -a octets <<<"$ip"
    for octet in "${octets[@]}"; do
        octet=$((10#$octet))
        [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ] && return 1
    done
    return 0
}

# 更新 IP 配置
update_ip() {
    read -r -p "请输入 IP 地址: " main_ip
    read -r -p "请输入网关地址: " gateway_ip
    read -r -p "请输入子网掩码: " netmask
}

# 设置网络参数
set_network() {
    if [ "$region" == "cn" ]; then
        is_cn=1
        echo "根据 --region cn 参数，判定为中国区域"
    else
        is_cn=0
        echo "根据 --region ${region} 参数，判定为非中国区域"
    fi

    is_auto=0
    if [[ -f '/etc/network/interfaces' ]]; then
        [[ -n "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && is_auto=1
        if [[ -d /etc/network/interfaces.d ]]; then
            cfg_num=$(find /etc/network/interfaces.d -name '*.cfg' | wc -l) || cfg_num=0
            if [ "$cfg_num" -ne 0 ]; then
                for net_config in /etc/network/interfaces.d/*.cfg; do
                    [[ -n "$(sed -n '/iface.*inet static/p' "$net_config")" ]] && is_auto=1
                done
            fi
        fi
    fi

    if [[ -d '/etc/sysconfig/network-scripts' ]]; then
        cfg_num=$(find /etc/sysconfig/network-scripts -name 'ifcfg-*' | grep -v 'lo$' | wc -l) || cfg_num=0
        if [ "$cfg_num" -ne 0 ]; then
            for net_config in /etc/sysconfig/network-scripts/ifcfg-*; do
                [[ ! $net_config =~ lo$ && -n "$(sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p' "$net_config")" ]] && is_auto=1
            done
        fi
    fi

    check_ipv6
}

# 设置网络模式
net_mode() {
    if [ "$is_auto" == '0' ]; then
        read -p "是否设置为动态获取 IP (DHCP)？[Y/n]: " input
        [ -z "$input" ] && input="y"
        case $input in
            [yY][eE][sS]|[yY]) ;;
            [nN][oO]|[nN]) is_auto=1 ;;
            *) err "用户取消操作" ;;
        esac
    fi

    if [ "$is_auto" == '1' ]; then
        get_ip
        if ip_check; then
            echo "自动检测的 IPv4 配置："
            echo "IP: $main_ip"
            echo "网关: $gateway_ip"
            echo "子网掩码: $netmask"
            read -p "确认使用以上配置？[Y/n]: " input
            [ -z "$input" ] && input="y"
            case $input in
                [yY][eE][sS]|[yY]) ;;
                [nN][oO]|[nN])
                    update_ip
                    ip_check || err "输入的 IPv4 配置无效"
                    ;;
                *) err "用户取消操作" ;;
            esac
        else
            echo "检测 IPv4 配置失败，请手动输入："
            update_ip
            ip_check || err "输入的 IPv4 配置无效"
        fi
    fi

    if [ "$has_native_ipv6" == "1" ]; then
        use_native_ipv6=1
    fi

    if [ "$he_tunnel" == "1" ]; then
        read -p "检测到 HE.net IPv6 隧道，是否在新系统中启用？[Y/n]: " input
        [ -z "$input" ] && input="y"
        case $input in
            [yY][eE][sS]|[yY]) use_he_tunnel=1 ;;
            [nN][oO]|[nN]) use_he_tunnel=0 ;;
            *) err "用户取消操作" ;;
        esac
    fi
}

# 主执行流程
set_network
net_mode
choose_system
get_versions
download_image
delete_old_system
extract_image
init_os

# 清理临时文件并提示重启
if command -v apt >/dev/null 2>&1; then
    echo "检测到 apt，系统安装成功"
    rm -rf "$root_dir" || echo "警告：无法删除 $root_dir 目录"
else
    err "系统安装失败，未找到 apt 命令"
fi

apt-get clean all

echo "正在强制将缓存数据写入磁盘..."
sync; sync; sync
sleep 5
echo "数据同步完成"
mount -o remount,rw /
sync; sync; sync
sleep 10
echo "数据同步完成"

echo "安装完成，建议重启系统"
read -p "确认无严重错误，是否现在重启？[Y/n]: " yn
[ -z "$yn" ] && yn="y"
if [[ $yn == [Yy] ]]; then
    echo "系统正在重启..."
    reboot -f
fi
