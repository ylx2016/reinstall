#!/usr/bin/env bash
# 设置环境变量，确保脚本能正确使用系统命令
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 提醒用户更改默认密码。此处可以加强，强调安全性重要性
echo "注意：默认密码为 blog.ylx.me，请在安装后立即更改！"

# 检查是否以 root 身份运行
if [ "$(id -u)" -ne 0 ]; then
    err "此脚本需要以 root 身份运行，请使用 sudo 或切换到 root 用户"
fi

# 脚本路径和名称 (当前未使用，但保留以备将来扩展)
SCRIPT_PATH_ABSOLUTE="$(realpath "$0")"           # 脚本的绝对路径
SCRIPT_DIR="$(dirname "$SCRIPT_PATH_ABSOLUTE")"   # 脚本所在目录
SCRIPT_NAME="$(basename "$SCRIPT_PATH_ABSOLUTE")" # 脚本名

# 参数的默认值
DEFAULT_HOSTNAME="my-os-$(date +%Y%m%d)" # 默认主机名
DEFAULT_TIMEZONE="Asia/Shanghai"         # 默认时区
DEFAULT_REGION="global"                  # 默认区域: 'cn' (中国) 或 'global' (全球)

# 通过参数设置的变量 (来自新版)
authorized_keys_url=""                # SSH公钥URL
password=""                           # root密码
ssh_port=""                           # SSH端口
tmpHostName="${DEFAULT_HOSTNAME}"     # 实际使用的主机名，默认为DEFAULT_HOSTNAME
apt_mirror_url=""                     # APT软件源镜像URL
target_region="${DEFAULT_REGION}"     # 目标区域 (用于替换旧的isCN)
target_timezone="${DEFAULT_TIMEZONE}" # 目标时区

# 网络相关变量 (来自 .bak.sh，由网络函数设置)
MAINIP=""
GATEWAYIP=""
NETMASK=""
SUBNET=""
DNS1="" # 您的 .bak.sh 中 GetIp 没有显式设置DNS，但INIT_OS中用了，这里先定义
DNS2=""
HAS_IPV6=0
HAS_NATIVE_IPV6=0
NATIVE_IPV6_IFACE=""
NATIVE_IPV6_ADDR=""
NATIVE_IPV6_MASK=""
NATIVE_IPV6_GW=""
HE_TUNNEL=0
HE_CLIENT_IPV4=""
HE_SERVER_IPV4=""
HE_CLIENT_IPV6=""
HE_NETMASK=""
HE_SERVER_IPV6=""
isCN='0'   # 将由新的 SetNetwork 逻辑基于 target_region 设置，或沿用旧的 geoip 检测
isAuto='0' # 默认DHCP
NETSTR=""  # 用于向dd命令传递网络参数，但dd在新版中不直接使用
USE_NATIVE_IPV6=0
USE_HE_TUNNEL=0
network_adapter_name="eth0" # 默认网卡名

# 输出错误信息并退出
err() {
    echo "错误：$1" >&2
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
    --authorized-keys-url)
        authorized_keys_url=$2
        shift
        ;;
    --password)
        password=$2
        shift
        ;;
    --ssh-port)
        if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
            err "无效的SSH端口 '$2'，必须是1-65535之间的整数"
        fi
        ssh_port=$2
        shift
        ;;
    --hostname)
        tmpHostName=$2
        shift
        ;;
    --apt-mirror)
        apt_mirror_url="$2"
        shift
        ;;
    --region)
        if [[ "$2" != "cn" && "$2" != "global" ]]; then # 检查区域参数是否有效
            err "无效的区域 '$2'。请使用 'cn' 或 'global'."
        fi
        target_region="$2"
        shift
        ;;
    --timezone)
        target_timezone="$2"
        shift
        ;;
    --help)
        usage # 调用usage函数显示帮助
        ;;
    *)
        err "未知选项：\"$1\""
        ;;
    esac
    shift
done

# 检查bash是否在/usr/bin/bash，如果不在则创建链接
[ ! -f "/usr/bin/bash" ] && ln -s "$(which bash)" /usr/bin/bash

# 检查并安装指定工具
install_tool() {
    local tool=$1
    if ! type "$tool" >/dev/null 2>&1; then
        echo "$tool 未安装，正在安装..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install "$tool" -y
        elif command -v yum >/dev/null 2>&1; then
            yum install "$tool" -y
        else
            err "未知的包管理器，请手动安装 $tool"
        fi
    else
        echo "$tool 已安装，继续"
    fi
}

install_tool curl
install_tool wget
install_tool zip
install_tool tar

# 定义变量以便于后续使用
my_wget=$(which wget)
my_curl=$(which curl)
my_mkdir=$(which mkdir)

# 根据系统架构下载不同的Debian镜像和BusyBox
bit=$(uname -m)

# 设置下载根目录
ROOTDIR='/os'
busybox_filename="/os/busybox"

# 创建 /os 目录（如果不存在）
mkdir -p /os || err "无法创建 /os 目录"

# 让用户选择安装 Debian 或 Ubuntu
function ChooseSystem() {
    echo "请选择要安装的系统："
    echo "1. Debian"
    echo "2. Ubuntu"
    while true; do
        read -p "请输入数字 (1 或 2)： " choice
        case "$choice" in
        1)
            SYSTEM="debian"
            BASE_URL="https://images.linuxcontainers.org/images/debian"
            CN_BASE_URL="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/debian"
            break
            ;;
        2)
            SYSTEM="ubuntu"
            BASE_URL="https://images.linuxcontainers.org/images/ubuntu"
            CN_BASE_URL="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/ubuntu"
            break
            ;;
        *) echo "无效输入，请输入 1 或 2" ;;
        esac
    done
    echo "已选择系统：$SYSTEM"
}

# 获取支持的版本并提示用户选择
function GetVersions() {
    local url="$BASE_URL"
    local versions_file="versions.txt"
    # ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0"

    # 定义版本映射
    declare -A VERSION_MAP
    if [ "$SYSTEM" == "debian" ]; then
        VERSION_MAP["bookworm"]="Debian 12"
        VERSION_MAP["bullseye"]="Debian 11"
        VERSION_MAP["buster"]="Debian 10"
        VERSION_MAP["trixie"]="Debian 13 (Testing)"
    elif [ "$SYSTEM" == "ubuntu" ]; then
        VERSION_MAP["focal"]="Ubuntu 20.04 (Focal Fossa)"
        VERSION_MAP["jammy"]="Ubuntu 22.04 (Jammy Jellyfish)"
        VERSION_MAP["noble"]="Ubuntu 24.04 (Noble Numbat)"
        VERSION_MAP["oracular"]="Ubuntu 24.10 (Oracular Oriole)"
    fi

    echo "正在获取支持的 $SYSTEM 版本..."
    curl -s -L "$url" -o "$versions_file" || err "无法获取版本列表：$url"
    mapfile -t ALL_VERSIONS < <(grep -oP '[a-z]+(?=/)' "$versions_file" | sort -u)
    declare -a VERSIONS
    for version in "${ALL_VERSIONS[@]}"; do
        if [[ -n "${VERSION_MAP[$version]}" ]]; then
            VERSIONS+=("$version")
        fi
    done

    if [ ${#VERSIONS[@]} -eq 0 ]; then
        err "未检测到任何支持的 $SYSTEM 版本"
    fi

    echo "支持的 $SYSTEM 版本："
    for i in "${!VERSIONS[@]}"; do
        version_name="${VERSIONS[$i]}"
        version_number="${VERSION_MAP[$version_name]}"
        echo "$((i + 1)). $version_name ($version_number)"
    done

    while true; do
        read -p "请选择要安装的版本（输入数字 1-${#VERSIONS[@]}）： " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#VERSIONS[@]}" ]; then
            SELECTED_VERSION="${VERSIONS[$((choice - 1))]}"
            echo "已选择版本：$SELECTED_VERSION (${VERSION_MAP[$SELECTED_VERSION]})"
            break
        else
            echo "无效输入，请输入 1 到 ${#VERSIONS[@]} 之间的数字"
        fi
    done

    rm -f "$versions_file"
}

# 下载镜像和 Busybox 并验证
function DOWNLOAD_IMG() {
    local version="$SELECTED_VERSION"
    local arch=""
    local file="rootfs.tar.xz"
    local os_filename="/os/os.tar.xz"
    local attempts=3
    local timeout=10

    # 根据架构设置基础信息
    if [[ "$bit" == "x86_64" ]]; then
        arch="amd64"
        BUSYBOX='https://raw.githubusercontent.com/ylx2016/reinstall/master/busybox_1.32.1'
        CN_BUSYBOX='https://raw.sevencdn.com/ylx2016/reinstall/master/busybox-x86_64'
    elif [[ "$bit" == "aarch64" ]]; then
        arch="arm64"
        BUSYBOX='https://raw.githubusercontent.com/iweizime/static-binaries/master/arm64/linux/busybox'
        CN_BUSYBOX='https://raw.githubusercontent.com/iweizime/static-binaries/master/arm64/linux/busybox'
    else
        err "此系统架构（$bit）太特殊，不支持！"
    fi

    # 获取时间戳列表并提示用户选择
    local list_url="$BASE_URL/$version/$arch/cloud/?C=M;O=D"
    echo "正在获取可用镜像时间戳列表..."
    rm -rf /tmp/url.tmp
    curl -s -L "$list_url" -o /tmp/url.tmp || err "无法获取时间戳列表：$list_url"
    mapfile -t TIMESTAMP_LIST < <(grep -oP '2[0-9]{7}[\_]..[\:]..' /tmp/url.tmp)

    if [ ${#TIMESTAMP_LIST[@]} -eq 0 ]; then
        err "未检测到任何可用时间戳目录"
    fi

    echo "可用镜像时间戳："
    for i in "${!TIMESTAMP_LIST[@]}"; do
        echo "$((i + 1)). ${TIMESTAMP_LIST[$i]}"
    done

    while true; do
        read -p "请选择要使用的镜像时间戳（输入数字 1-${#TIMESTAMP_LIST[@]}）： " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#TIMESTAMP_LIST[@]}" ]; then
            urldata="${TIMESTAMP_LIST[$((choice - 1))]}"
            echo "已选择时间戳：$urldata"
            break
        else
            echo "无效输入，请输入 1 到 ${#TIMESTAMP_LIST[@]} 之间的数字"
        fi
    done

    # 设置下载 URL
    IMGURL="$BASE_URL/$version/$arch/cloud/$urldata/$file"
    CN_IMGURL="$CN_BASE_URL/$version/$arch/cloud/$urldata/$file"
    local url="$IMGURL"
    local checksum_url="$BASE_URL/$version/$arch/cloud/$urldata/SHA256SUMS"

    # 下载镜像文件
    echo "开始下载镜像文件：$url"
    REMOTE_SIZE=$(curl -sI -L "$url" | grep -i '^Content-Length:' | tail -n 1 | awk '{print $2}' | tr -d '\r')
    if [ -z "$REMOTE_SIZE" ]; then
        echo "警告：无法获取远程文件大小，跳过大小验证"
        SIZE_CHECK_AVAILABLE=0
    else
        echo "远程文件大小：$REMOTE_SIZE 字节"
        SIZE_CHECK_AVAILABLE=1
    fi

    if ! curl -s -L "$checksum_url" -o "SHA256SUMS" 2>/dev/null; then
        echo "警告：无法下载校验和文件 $checksum_url，跳过 SHA256 验证"
        CHECKSUM_AVAILABLE=0
    else
        CHECKSUM_AVAILABLE=1
        EXPECTED_CHECKSUM=$(grep "$file" SHA256SUMS | awk '{print $1}')
        if [ -z "$EXPECTED_CHECKSUM" ]; then
            echo "警告：SHA256SUMS 文件中未找到 $file 的校验和"
            CHECKSUM_AVAILABLE=0
        fi
    fi

    for ((i = 1; i <= attempts; i++)); do
        echo "尝试下载镜像（第 $i 次）..."
        curl -SL --retry 2 --connect-timeout "$timeout" -o "$os_filename" "$url" && break
        if [ "$i" -eq "$attempts" ]; then
            echo "原始 URL 下载失败，尝试 CN 镜像：$CN_IMGURL"
            url="$CN_IMGURL"
            checksum_url="$CN_BASE_URL/$version/$arch/cloud/$urldata/SHA256SUMS"
            for ((j = 1; j <= attempts; j++)); do
                echo "尝试下载镜像（第 $j 次）..."
                curl -SL --retry 2 --connect-timeout "$timeout" -o "$os_filename" "$url" && break
                if [ "$j" -eq "$attempts" ]; then
                    err "下载镜像失败：$url 在 $attempts 次尝试后仍未成功"
                fi
                sleep 5
            done
            if ! curl -SL "$checksum_url" -o "SHA256SUMS" 2>/dev/null; then
                CHECKSUM_AVAILABLE=0
            else
                CHECKSUM_AVAILABLE=1
                EXPECTED_CHECKSUM=$(grep "$file" SHA256SUMS | awk '{print $1}')
            fi
            break
        fi
        sleep 5
    done

    # 验证镜像文件大小
    if [ "$SIZE_CHECK_AVAILABLE" -eq 1 ]; then
        echo "验证镜像文件大小..."
        LOCAL_SIZE=$(stat -c%s "$os_filename" 2>/dev/null || wc -c <"$os_filename")
        if [ "$LOCAL_SIZE" -eq "$REMOTE_SIZE" ]; then
            echo "镜像文件大小匹配（$LOCAL_SIZE 字节）"
        else
            err "镜像文件大小不匹配，下载可能不完整！本地大小: $LOCAL_SIZE 字节，远程大小: $REMOTE_SIZE 字节"
        fi
    fi

    # 验证镜像文件 SHA256 校验和
    if [ "$CHECKSUM_AVAILABLE" -eq 1 ]; then
        echo "验证镜像文件 SHA256 校验和..."
        ACTUAL_CHECKSUM=$(sha256sum "$os_filename" | awk '{print $1}')
        if [ "$ACTUAL_CHECKSUM" == "$EXPECTED_CHECKSUM" ]; then
            echo "镜像文件 SHA256 校验和匹配，文件完整性验证通过"
        else
            err "镜像文件 SHA256 校验和不匹配，文件可能损坏！期望值: $EXPECTED_CHECKSUM，实际值: $ACTUAL_CHECKSUM"
        fi
    fi

    echo "开始下载 BusyBox (架构: $bit)..."
    local busybox_base_url_prefix=""
    local busybox_filename_arch_specific=""

    if [[ "$bit" == "x86_64" ]]; then
        busybox_filename_arch_specific="busybox-x86_64-linux-gnu"
    elif [[ "$bit" == "aarch64" ]]; then
        busybox_filename_arch_specific="busybox-aarch64-linux-gnu"
    else
        err "下载 BusyBox 失败：不支持的系统架构 ($bit)。"
    fi

    if [ "$target_region" == "cn" ]; then # target_region 由参数设置
        busybox_base_url_prefix="https://ghproxy.net/https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
        echo "检测到中国区域，将通过ghproxy.net代理下载 BusyBox。"
    else
        busybox_base_url_prefix="https://raw.githubusercontent.com/shutingrz/busybox-static-binaries-fat/main/"
    fi
    current_busybox_url="${busybox_base_url_prefix}${busybox_filename_arch_specific}"
    echo "BusyBox 下载 URL: $current_busybox_url"

    download_successful=0
    REMOTE_SIZE=$(curl -sIL "$current_busybox_url" | grep -i '^Content-Length:' | awk '{print $2}' | tr -d '\r\n')
    [ -z "$REMOTE_SIZE" ] && echo "警告：无法获取 Busybox 远程文件大小。" || echo "Busybox 远程文件大小: $REMOTE_SIZE 字节"

    for ((i = 1; i <= attempts; i++)); do
        echo "尝试下载 BusyBox (第 $i/$attempts 次)..."
        if curl -SLf --retry 2 --connect-timeout "$timeout" -o "$busybox_filename" "$current_busybox_url"; then
            echo "BusyBox 下载成功。"
            download_successful=1
            break
        else
            echo "BusyBox 下载尝试 $i 失败 (curl 退出码: $?)。"
            if [ "$target_region" == "cn" ] && [ "$i" -eq "$attempts" ]; then
                echo "通过代理下载 BusyBox 失败。请检查代理链接或网络，或尝试使用 --region global。"
            elif [ "$i" -eq "$attempts" ]; then
                echo "直接下载 BusyBox 失败。请检查链接或网络。"
            fi
            sleep 5
        fi
    done

    if [ "$download_successful" -ne 1 ]; then
        err "下载 BusyBox 失败 (URL: $current_busybox_url)。请检查链接是否正确，以及文件是否确实存在于仓库的main分支。或者尝试从 GitHub Releases 手动下载并替换链接。"
    fi

    chmod +x "$busybox_filename" || err "无法为 $busybox_filename 设置可执行权限。"
    if "$busybox_filename" --help >/dev/null 2>&1; then
        echo "BusyBox 测试成功 (执行 --help 返回正常)。"
    else
        err "BusyBox ($busybox_filename) 下载后无法执行或测试失败。请检查二进制文件兼容性或下载链接。"
    fi

    if [ -n "$REMOTE_SIZE" ] && [ "$REMOTE_SIZE" != "0" ] && [ "$REMOTE_SIZE" != "" ]; then
        LOCAL_SIZE=$(stat -c%s "$busybox_filename" 2>/dev/null || wc -c <"$busybox_filename" | awk '{print $1}')
        if [ "$LOCAL_SIZE" -eq "$REMOTE_SIZE" ]; then
            echo "BusyBox 文件大小匹配 ($LOCAL_SIZE 字节)。"
        else
            echo "警告：BusyBox 文件大小不匹配。本地: $LOCAL_SIZE, 远程: $REMOTE_SIZE。"
        fi
    fi
    echo "BusyBox 下载完成。通常不提供单独的 SHA256 校验和，请确保来源可靠。"

    # 清理临时文件
    [ -f "SHA256SUMS" ] && rm -f "SHA256SUMS"
    [ -f "/tmp/url.tmp" ] && rm -f "/tmp/url.tmp"

}

# 删除所有旧系统文件的函数
DELALL() {

    # 检查 Busybox 文件是否存在且可执行
    if [ ! -f "$busybox_filename" ]; then
        err "Busybox 文件 ($busybox_filename) 不存在"
    elif ! "$busybox_filename" --help >/dev/null 2>&1; then
        err "Busybox ($busybox_filename) 无法执行，可能是权限不足或挂载限制"
        exit 1
    fi

    cp /etc/fstab $ROOTDIR
    sysbios="0"
    sysefi="0"
    sysefifile=""
    if [ -d "/sys/firmware/efi" ]; then
        sysefi="1"
        # elif [ -f "/boot/efi/boot/grub/grub.cfg" ]; then
        # sysefi="1"
        # elif [ -f "/boot/efi/EFI/grub/grub.cfg" ]; then
        # sysefi="1"
        # elif [ -f "/boot/efi/EFI/ubuntu/grub.cfg" ]; then
        # sysefi="1"
        # elif [ -f "/boot/efi/EFI/debian/grub.cfg" ]; then
        # sysefi="1"
    else
        sysbios="1"
    fi

    if command -v chattr >/dev/null 2>&1; then
        find / -type f \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) \
            -exec chattr -i {} + 2>/dev/null || true
    fi
    find / \( ! -path '/dev/*' -and ! -path '/proc/*' -and ! -path '/sys/*' -and ! -path "$ROOTDIR/*" \) -delete 2>/dev/null || true
}

# 解压新系统镜像的函数
EXTRACT_IMG() {

    # 对于 /etc/machine-id 单独处理，因为它经常是问题点
    if [ -e "/etc/machine-id" ]; then # -e 检查文件或符号链接是否存在
        echo "尝试移除旧的 /etc/machine-id 的 chattr 保护并删除..."
        if chattr --help >/dev/null 2>&1; then
            chattr -i /etc/machine-id 2>/dev/null
        fi
        rm -f /etc/machine-id || echo "警告: 删除旧的 /etc/machine-id 仍然失败。"
    fi
    echo "预清理完成，开始解压系统镜像..."

    echo "正在解压系统镜像,请稍后..."
    # 使用BusyBox解压系统镜像
    cd $ROOTDIR
    xzcat="$ROOTDIR/busybox xzcat"
    tar="$ROOTDIR/busybox tar"
    $xzcat "$ROOTDIR/os.tar.xz" | $tar -x -C /
    mv -f $ROOTDIR/fstab /etc
}

# 初始化新系统的函数
INIT_OS() {
    cd /
    # 配置DNS
    rm -rf /etc/resolv.conf
    touch /etc/resolv.conf
    if [ "$isCN" == '1' ]; then
        echo "nameserver 114.114.114.114" >/etc/resolv.conf
        echo "nameserver 223.5.5.5" >>/etc/resolv.conf
        #sed -i 's#http://deb.debian.org#http://mirrors.163.com#g' /etc/apt/sources.list
    else
        echo "nameserver 1.1.1.1" >/etc/resolv.conf
        echo "nameserver 8.8.8.8" >>/etc/resolv.conf
        echo "nameserver 9.9.9.9" >>/etc/resolv.conf
    fi
    rm -f /root/anaconda-ks.cfg
    export LC_ALL=C.UTF-8

    echo "配置APT软件源..."
    local final_apt_mirror_url="$apt_mirror_url"
    if [ -z "$final_apt_mirror_url" ]; then
        # isCN 变量由 SetNetwork 设置 (基于 target_region 或 geoip)
        if [ "$isCN" == '1' ]; then # 使用 SetNetwork 设置的 isCN
            if [ "$SYSTEM" == "debian" ]; then
                final_apt_mirror_url="https://mirrors.ustc.edu.cn/debian"
            elif [ "$SYSTEM" == "ubuntu" ]; then
                final_apt_mirror_url="https://mirrors.ustc.edu.cn/ubuntu"
            fi
            echo "未指定 --apt-mirror，根据区域判定 (isCN=$isCN) 选择清华大学镜像: $final_apt_mirror_url"
        else
            if [ "$SYSTEM" == "debian" ]; then
                final_apt_mirror_url="http://deb.debian.org/debian"
            elif [ "$SYSTEM" == "ubuntu" ]; then
                final_apt_mirror_url="http://archive.ubuntu.com/ubuntu"
            fi
            echo "未指定 --apt-mirror，根据区域判定 (isCN=$isCN) 选择官方镜像: $final_apt_mirror_url"
        fi
    else
        echo "使用用户指定的APT镜像: $final_apt_mirror_url"
    fi

    if [ -f "/etc/apt/sources.list" ]; then
        cp /etc/apt/sources.list /etc/apt/sources.list.bak."$(date +%s)"
        echo "已备份原始 /etc/apt/sources.list 文件。"
    fi
    echo "" >/etc/apt/sources.list

    local codename="$SELECTED_VERSION"
    if [ "$SYSTEM" == "debian" ]; then
        local components="main contrib non-free"
        [[ "$codename" == "bookworm" || "$codename" == "trixie" ]] && components="main contrib non-free non-free-firmware"
        echo "deb $final_apt_mirror_url $codename $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-updates $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-backports $components" >>/etc/apt/sources.list
        local security_mirror_url="http://security.debian.org/debian-security"
        if [[ "$final_apt_mirror_url" == "http://deb.debian.org/debian" || "$final_apt_mirror_url" == "http://ftp.debian.org/debian" ]]; then
            echo "主APT源为官方源，安全更新也使用官方源: $security_mirror_url"
        else
            echo "注意: Debian 安全更新将使用官方源 ($security_mirror_url)。"
        fi
        echo "deb $security_mirror_url $codename-security $components" >>/etc/apt/sources.list
    elif [ "$SYSTEM" == "ubuntu" ]; then
        local components="main restricted universe multiverse"
        echo "deb $final_apt_mirror_url $codename $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-updates $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-backports $components" >>/etc/apt/sources.list
        echo "deb $final_apt_mirror_url $codename-security $components" >>/etc/apt/sources.list
    fi
    echo "APT软件源配置完成。 (/etc/apt/sources.list)"

    # 更新软件源
    apt-get update || err "无法更新软件源"
    # 根据架构安装软件包并检查
    bit=$(uname -m)
    # 根据系统类型（Debian 或 Ubuntu）选择内核包
    if [ "$SYSTEM" == "debian" ]; then
        if [ "$bit" == "x86_64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-cloud-amd64 htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 x86_64 软件包失败"
        elif [ "$bit" == "aarch64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-arm64 htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 aarch64 软件包失败"
        fi
    elif [ "$SYSTEM" == "ubuntu" ]; then
        if [ "$bit" == "x86_64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-virtual htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 x86_64 软件包失败"
        elif [ "$bit" == "aarch64" ]; then
            apt-get install -y systemd openssh-server passwd wget nano linux-image-virtual htop net-tools \
                isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs || err "安装 aarch64 软件包失败"
        fi
    else
        err "未知系统类型：$SYSTEM"
    fi
    echo "安装GRUB引导加载程序..."
    apt-get install -y grub2 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装 GRUB (grub2) 失败。"

    local grub_device=""
    # 磁盘检测逻辑与新版类似，但更依赖 lsblk
    mapfile -t potential_disks < <(lsblk -nd -o NAME,TYPE,RO,RM | awk '$2=="disk" && $3=="0" && $4=="0" {print "/dev/"$1}')

    if [ "${#potential_disks[@]}" -eq 0 ]; then
    grub_device=$(fdisk -l 2>/dev/null | grep -Eo '/dev/[sv]d[a-z]+|/dev/nvme[0-9]+n[0-9]+|/dev/xvd[a-z]+|/dev/vd[a-z]+' | head -1)
    if [ -z "$grub_device" ]; then
        err "无法自动检测到任何合适的磁盘设备用于GRUB安装。请手动检查。"
    else
        echo "通过旧方法检测到磁盘 $grub_device 用于GRUB安装 (lsblk未找到或无结果)。"
    fi
elif [ "${#potential_disks[@]}" -eq 1 ]; then
    grub_device="${potential_disks[0]}"
    local disk_size=$(lsblk -b -d -o SIZE "${grub_device}" | tail -n 1 | awk '{print $1/1024/1024/1024 " GB"}')
    echo "自动选择唯一的可用磁盘 $grub_device (大小: ${disk_size}) 用于GRUB安装。"
else
    echo "检测到多个可能的磁盘设备，请选择要安装GRUB的【主系统引导盘】:"
    for i in "${!potential_disks[@]}"; do
        local disk_info=$(lsblk -b -d -o SIZE,MODEL "${potential_disks[$i]}" | tail -n 1 | awk '{model=$2; for(j=3;j<=NF;j++) model=model"_"$j; printf "大小: %.2f GB, 型号: %s\n", $1/1024/1024/1024, model}')
        echo "$((i + 1)). ${potential_disks[$i]} (${disk_info})"
    done
    local choice_grub_disk
    read -p "请输入GRUB安装目标设备的数字: " choice_grub_disk
    if [[ "$choice_grub_disk" =~ ^[0-9]+$ ]] && [ "$choice_grub_disk" -ge 1 ] && [ "$choice_grub_disk" -le "${#potential_disks[@]}" ]; then
        grub_device="${potential_disks[$((choice_grub_disk - 1))]}"
    else
        err "无效选择，无法确定GRUB安装设备。"
    fi
fi
echo "GRUB将安装到: $grub_device"
read -p "确认此磁盘选择正确吗？按 Enter 键继续，按 Ctrl+C 中止。"

    if [ -d "/sys/firmware/efi" ]; then
        echo "检测到EFI模式，安装GRUB-EFI..."
        local grub_efi_pkg=""
        local grub_target=""
        if [ "$bit" == "x86_64" ]; then
            grub_efi_pkg="grub-efi-amd64"
            grub_target="x86_64-efi"
        elif [ "$bit" == "aarch64" ]; then
            grub_efi_pkg="grub-efi-arm64"
            grub_target="arm64-efi"
            apt-get install -y efibootmgr || echo "警告: efibootmgr 安装可能失败，但仍继续尝试GRUB安装。"
        else
            err "不支持的EFI架构: $bit"
        fi
        apt-get install -y "$grub_efi_pkg" || err "安装 $grub_efi_pkg 失败。"
        mkdir -p /boot/efi
        grub-install --target="$grub_target" --efi-directory=/boot/efi --bootloader-id="$SYSTEM" --recheck "$grub_device" || err "GRUB EFI 安装失败 (grub-install)。"
        
        # 【新增】验证EFI安装
    local efi_file_path="/boot/efi/EFI/$SYSTEM/grubx64.efi"
    [ "$bit" == "aarch64" ] && efi_file_path="/boot/efi/EFI/$SYSTEM/grubaa64.efi"
    if [ ! -f "$efi_file_path" ]; then
        err "【验证失败】GRUB EFI 安装后关键文件 $efi_file_path 未找到。脚本已中止，请勿重启！"
    else
        echo "【验证成功】GRUB EFI 关键文件已找到。"
    fi
        
        if [ "$bit" == "x86_64" ] && [ -f "/boot/efi/EFI/$SYSTEM/grubx64.efi" ]; then
            mkdir -p /boot/efi/EFI/BOOT
            cp "/boot/efi/EFI/$SYSTEM/grubx64.efi" /boot/efi/EFI/BOOT/BOOTX64.EFI
            echo "已复制 grubx64.efi 到 /boot/efi/EFI/BOOT/BOOTX64.EFI"
        elif [ "$bit" == "aarch64" ] && [ -f "/boot/efi/EFI/$SYSTEM/grubaa64.efi" ]; then
            mkdir -p /boot/efi/EFI/BOOT
            cp "/boot/efi/EFI/$SYSTEM/grubaa64.efi" /boot/efi/EFI/BOOT/BOOTAA64.EFI
            echo "已复制 grubaa64.efi 到 /boot/efi/EFI/BOOT/BOOTAA64.EFI"
        fi
    else
        echo "检测到BIOS模式，安装GRUB-PC到 $grub_device ..."
        # 使用 --boot-directory 明确指定 /boot 路径，增加稳健性
    grub-install --target=i386-pc --boot-directory=/boot --recheck "$grub_device" || err "GRUB BIOS 安装失败 (grub-install)。"

    # 【新增】验证BIOS安装
    if [ ! -f "/boot/grub/i386-pc/normal.mod" ]; then
        err "【验证失败】GRUB BIOS 安装后关键文件 /boot/grub/i386-pc/normal.mod 未找到。脚本已中止，请勿重启！"
    else
        echo "【验证成功】GRUB BIOS 关键文件已找到。"
    fi
    
    fi
    update-grub || err "更新GRUB配置失败 (update-grub)。"

    echo "配置SSH服务..."
    if [ ! -f "/etc/ssh/sshd_config" ]; then
        echo "警告: /etc/ssh/sshd_config 未找到。SSH可能无法正常启动。"
    else
        # 确保Port指令存在，如果不存在则添加，然后设置端口
        if ! grep -q "^Port " /etc/ssh/sshd_config; then echo "Port 22" >>/etc/ssh/sshd_config; fi
        [ -n "$ssh_port" ] && sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config || sed -i "s/^Port .*/Port 22/" /etc/ssh/sshd_config

        # PermitRootLogin: 如果存在则修改，不存在则添加 'PermitRootLogin yes'
        if grep -q "^#*PermitRootLogin" /etc/ssh/sshd_config; then
            sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        else
            echo "PermitRootLogin yes" >>/etc/ssh/sshd_config
        fi
        # PasswordAuthentication: 如果存在则修改为yes (后续可能因公钥设为no)
        if grep -q "^#*PasswordAuthentication" /etc/ssh/sshd_config; then
            sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
        else
            echo "PasswordAuthentication yes" >>/etc/ssh/sshd_config
        fi

        sed -i 's/^#*MaxAuthTries .*/MaxAuthTries 3/' /etc/ssh/sshd_config
        sed -i 's/^#*GSSAPIAuthentication .*/GSSAPIAuthentication no/' /etc/ssh/sshd_config # GSSAPI 通常不需要
        sed -i 's/^#*ClientAliveInterval .*/ClientAliveInterval 60/' /etc/ssh/sshd_config
        sed -i 's/^#*UseDNS .*/UseDNS no/' /etc/ssh/sshd_config # 推荐关闭以加快连接
    fi
    systemctl enable ssh

    echo "设置root用户密码..."
    local final_password="${password:-blog.ylx.me}"
    echo -e "$final_password\n$final_password" | passwd "root"
    if [ "$final_password" == "blog.ylx.me" ]; then
        echo "警告: root 密码已设置为默认值 'blog.ylx.me'。请务必在首次登录后更改！"
    else
        echo "root 密码已根据用户输入设置。"
    fi

    if [ -n "$authorized_keys_url" ]; then
        echo "正在从 $authorized_keys_url 下载并配置SSH公钥..."
        mkdir -p -m 0700 /root/.ssh
        if curl -sSLf --connect-timeout 10 "$authorized_keys_url" -o /root/.ssh/authorized_keys; then
            chmod 0600 /root/.ssh/authorized_keys
            sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
            echo "SSH公钥配置完成，密码登录已禁用 (PasswordAuthentication no)。"
        else
            echo "警告：无法从 \"$authorized_keys_url\" 下载SSH公钥 (curl 退出码: $?)。密码登录仍启用。"
        fi
    fi

    echo "应用系统优化配置..."
    echo "net.core.default_qdisc=fq" >/etc/sysctl.d/99-bbr.conf
    echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-bbr.conf
    # sysctl -p /etc/sysctl.d/99-bbr.conf
    if [ -f "/etc/default/grub" ]; then
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/' /etc/default/grub
        sed -i 's/GRUB_CMDLINE_LINUX="[^"]*"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /etc/default/grub
        if ! grep -q "GRUB_CMDLINE_LINUX=" /etc/default/grub; then
            echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' >>/etc/default/grub
        fi
        update-grub
    else
        echo "警告: /etc/default/grub 未找到，无法修改内核启动参数。"
    fi

    # 网络配置
    systemctl enable networking
    network_adapter_name="eth0"

    if [ "$isAuto" == '1' ]; then
        cat >/etc/network/interfaces <<EOFILE
auto lo
iface lo inet loopback

auto $network_adapter_name
iface $network_adapter_name inet static
    address $MAINIP
    netmask $NETMASK
    gateway $GATEWAYIP
EOFILE
        # 如果启用原生 IPv6，添加静态配置
        if [ "$USE_NATIVE_IPV6" == "1" ]; then
            cat >>/etc/network/interfaces <<EOFILE
iface $network_adapter_name inet6 static
    address $NATIVE_IPV6_ADDR
    netmask $NATIVE_IPV6_MASK
    gateway $NATIVE_IPV6_GW
EOFILE
        fi
    else
        cat >/etc/network/interfaces <<EOFILE
auto lo
iface lo inet loopback

auto $network_adapter_name
iface $network_adapter_name inet dhcp
iface $network_adapter_name inet6 dhcp
EOFILE
    fi

    # 如果使用 HE.net 隧道，添加到网络配置
    if [ "$USE_HE_TUNNEL" == "1" ]; then
        cat >>/etc/network/interfaces <<EOFILE
auto he-ipv6
iface he-ipv6 inet6 v4tunnel
    address $HE_CLIENT_IPV6
    netmask $HE_NETMASK
    endpoint $HE_SERVER_IPV4
    local $HE_CLIENT_IPV4
    ttl 255
    gateway $HE_SERVER_IPV6
EOFILE
    fi

    # 系统限制
    cat >>/etc/security/limits.conf <<EOFILE
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOFILE

    $(which mkdir) -p /etc/systemd/system/networking.service.d/
    echo -e "[Service]\nTimeoutStartSec=15sec" >/etc/systemd/system/networking.service.d/timeout.conf

    # DNS 和其他配置
    if [[ "$isCN" == '1' ]]; then
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
    [ -n "$tmpHostName" ] && echo "$tmpHostName" >/etc/hostname || echo "debian-$(date +%Y%m%d)" >/etc/hostname
    echo "127.0.0.1 $(cat /etc/hostname)" >>/etc/hosts

    echo "配置时区: $target_timezone ..."
    if [ -f "/usr/share/zoneinfo/$target_timezone" ]; then
        echo "$target_timezone" >/etc/timezone
        ln -sf "/usr/share/zoneinfo/$target_timezone" /etc/localtime
        dpkg-reconfigure -f noninteractive tzdata || echo "警告: dpkg-reconfigure tzdata 失败，但时区文件已链接。"
    else
        echo "警告: 时区文件 /usr/share/zoneinfo/$target_timezone 未找到。将默认使用 Etc/UTC。"
        echo "Etc/UTC" >/etc/timezone
        ln -sf "/usr/share/zoneinfo/Etc/UTC" /etc/localtime
        dpkg-reconfigure -f noninteractive tzdata || echo "警告: dpkg-reconfigure tzdata 失败 (UTC回退)。"
    fi

    echo "尝试下载并设置 tcpx.sh ..."
    # local tcpx_sh_url="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
    if [ "$target_region" == "cn" ]; then # target_region 由参数设置
        tcpx_sh_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
        echo "检测到中国区域，将通过ghproxy.net代理下载 BusyBox。"
    else
        tcpx_sh_url="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
    fi
    if wget --connect-timeout=15 -T 10 -O /root/tcpx.sh "$tcpx_sh_url"; then
        chmod +x /root/tcpx.sh
        echo "tcpx.sh 下载成功。您可以在系统启动后手动运行 /root/tcpx.sh。"
    else
        echo "警告: tcpx.sh 下载失败 (wget 退出码: $?)。跳过此步骤。"
    fi

    ln -fs /usr/bin/bash /usr/bin/sh

}

# 获取当前系统的IP信息
function GetIp() {
    # 获取主IP（优先选择与默认路由关联的接口）
    MAINIP=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
    if [ -z "$MAINIP" ]; then
        # 如果默认路由失败，尝试从接口获取第一个全局IP
        MAINIP=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)
    fi
    if [ -z "$MAINIP" ]; then
        echo "警告：无法自动检测主IP"
        return 1
    fi

    # 获取网关
    GATEWAYIP=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -1)
    if [ -z "$GATEWAYIP" ]; then
        echo "警告：无法自动检测网关"
        return 1
    fi

    # 获取子网掩码
    SUBNET=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+/\d+' | head -1 | cut -d'/' -f2)
    if [ -z "$SUBNET" ]; then
        echo "警告：无法自动检测子网掩码，假设为24"
        SUBNET=24
    fi
    # 计算点分十进制的子网掩码
    value=$((0xffffffff ^ ((1 << (32 - $SUBNET)) - 1)))
    NETMASK="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"

    return 0
}

# 检查当前系统是否已有 IPv6 地址（原生或隧道）
function CheckIPv6() {
    # 检查全局 IPv6 地址
    IPV6_ADDR=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+/[0-9]+' | head -1)
    if [ -n "$IPV6_ADDR" ]; then
        echo "检测到现有 IPv6 地址：$IPV6_ADDR"
        HAS_IPV6=1
    else
        echo "未检测到 IPv6 地址"
        HAS_IPV6=0
    fi

    # 检查原生 IPv6（绑定到物理接口如 eth0）
    NATIVE_IPV6_IFACE=$(ip -6 addr show scope global | grep -B1 "$IPV6_ADDR" | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -E '^(eth|en)' | head -1)
    if [ -n "$NATIVE_IPV6_IFACE" ]; then
        echo "检测到原生 IPv6（接口：$NATIVE_IPV6_IFACE）"
        HAS_NATIVE_IPV6=1
        NATIVE_IPV6_ADDR=$(echo "$IPV6_ADDR" | cut -d'/' -f1)
        NATIVE_IPV6_MASK=$(echo "$IPV6_ADDR" | cut -d'/' -f2)
        NATIVE_IPV6_GW=$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)
        echo "原生 IPv6 信息："
        echo "地址: $NATIVE_IPV6_ADDR"
        echo "掩码: $NATIVE_IPV6_MASK"
        echo "网关: $NATIVE_IPV6_GW"
    else
        HAS_NATIVE_IPV6=0
    fi

    # 检查 HE.net 6in4 隧道
    if [ "$HAS_IPV6" == "1" ]; then
        TUNNEL_IFACE=$(ip -6 addr show scope global | grep -B1 "$IPV6_ADDR" | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -v -E '^(eth|en)' | head -1)
        if [ -n "$TUNNEL_IFACE" ] && ip tunnel show "$TUNNEL_IFACE" | grep -q "ipv6/ip"; then
            if echo "$IPV6_ADDR" | grep -q "^2001:470:"; then
                echo "检测到 HE.net 6in4 隧道（接口：$TUNNEL_IFACE）"
                HE_TUNNEL=1
                HE_CLIENT_IPV4=$(ip tunnel show "$TUNNEL_IFACE" | grep -oP 'local \K[\d.]+')
                HE_SERVER_IPV4=$(ip tunnel show "$TUNNEL_IFACE" | grep -oP 'remote \K[\d.]+')
                HE_CLIENT_IPV6=$(echo "$IPV6_ADDR" | cut -d'/' -f1)
                HE_NETMASK=$(echo "$IPV6_ADDR" | cut -d'/' -f2)
                HE_SERVER_IPV6=$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)
                if [ -z "$HE_SERVER_IPV6" ]; then
                    HE_SERVER_IPV6=$(echo "$HE_CLIENT_IPV6" | sed 's/::2$/::1/')
                fi
                echo "隧道信息："
                echo "客户端 IPv4: $HE_CLIENT_IPV4"
                echo "服务器 IPv4: $HE_SERVER_IPV4"
                echo "客户端 IPv6: $HE_CLIENT_IPV6"
                echo "服务器 IPv6: $HE_SERVER_IPV6"
            else
                echo "检测到 6in4 隧道，但非 HE.net 的地址范围"
                HE_TUNNEL=0
            fi
        else
            HE_TUNNEL=0
        fi
    else
        HE_TUNNEL=0
    fi

    [ "$HAS_IPV6" == "0" ] && [ "$HE_TUNNEL" == "0" ] && [ "$HAS_NATIVE_IPV6" == "0" ] && return 1
    return 0
}

# 测试 IPv6 连通性
function TestIPv6() {
    ping6 -c 4 2001:4860:4860::8888 >/dev/null 2>&1 # Google IPv6 DNS
    if [ $? -eq 0 ]; then
        echo "IPv6 连通性测试成功"
        return 0
    else
        echo "IPv6 连通性测试失败"
        return 1
    fi
}

# 检查IP配置的完整性和合法性
function ipCheck() {
    local isLegal=0
    for addr in "$MAINIP" "$GATEWAYIP" "$NETMASK"; do
        if [ -z "$addr" ]; then
            echo "错误：IP、网关或子网掩码为空"
            isLegal=1
        elif ! isValidIp "$addr"; then
            echo "错误：无效的IP地址 '$addr'"
            isLegal=1
        fi
    done
    return $isLegal
}

# 检查IP地址是否合法
function isValidIp() {
    local ip=$1
    # 检查是否符合IPv4格式
    if [[ ! $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        return 1
    fi
    # 分割IP为四个八位字节并检查范围
    IFS='.' read -r -a octets <<<"$ip"
    for octet in "${octets[@]}"; do
        # 移除前导零后检查是否在0-255之间
        octet=$((10#$octet)) # 防止前导零导致八进制解析
        [ "$octet" -lt 0 ] || [ "$octet" -gt 255 ] && return 1
    done
    return 0
}

# 更新IP信息的函数
function UpdateIp() {
    read -r -p "请输入您的IP地址: " MAINIP
    read -r -p "请输入网关地址: " GATEWAYIP
    read -r -p "请输入子网掩码: " NETMASK
}

# 设置网络参数并检测 IPv6
function SetNetwork() {
    # isCN='0'
    # geoip=$(wget -qO- https://api.ip.sb/geoip -T 10 | grep "\"country_code\":\"CN\"")
    # if [[ "$geoip" != "" ]]; then
    #     isCN='1'
    # fi

    # isCN的判断现在主要基于 target_region 参数
    if [ "$target_region" == "cn" ]; then
        isCN='1'
        echo "根据 --region cn 参数，判定为中国区域。"
    else
        isCN='0' # 默认为 global
        echo "根据 --region ${target_region} (或默认) 参数，判定为非中国大陆区域。"
    fi

    isAuto='0'
    if [[ -f '/etc/network/interfaces' ]]; then
        [[ ! -z "$(sed -n '/iface.*inet static/p' /etc/network/interfaces)" ]] && isAuto='1'
        [[ -d /etc/network/interfaces.d ]] && {
            cfgNum="$(find /etc/network/interfaces.d -name '*.cfg' | wc -l)" || cfgNum='0'
            [[ "$cfgNum" -ne '0' ]] && {
                for netConfig in $(ls -1 /etc/network/interfaces.d/*.cfg); do
                    [[ ! -z "$(cat $netConfig | sed -n '/iface.*inet static/p')" ]] && isAuto='1'
                done
            }
        }
    fi

    if [[ -d '/etc/sysconfig/network-scripts' ]]; then
        cfgNum="$(find /etc/sysconfig/network-scripts -name 'ifcfg-*' | grep -v 'lo$' | wc -l)" || cfgNum='0'
        [[ "$cfgNum" -ne '0' ]] && {
            for netConfig in $(ls -1 /etc/sysconfig/network-scripts/ifcfg-* | grep -v 'lo$' | grep -v ':[0-9]\{1,\}'); do
                [[ ! -z "$(cat $netConfig | sed -n '/BOOTPROTO.*[sS][tT][aA][tT][iI][cC]/p')" ]] && isAuto='1'
            done
        }
    fi

    # 检查 IPv6 和 HE.net 隧道
    CheckIPv6
}

# 设置网络模式并处理 IPv6
function NetMode() {
    # IPv4 配置
    if [ "$isAuto" == '0' ]; then
        read -p "设置网络为动态获取IP吗(DHCP) [Y/n] :" input
        [ -z "${input}" ] && input="y"
        case $input in
        [yY][eE][sS] | [yY]) NETSTR='' ;;
        [nN][oO] | [nN]) isAuto='1' ;;
        *) err "用户取消操作" ;;
        esac
    fi

    if [ "$isAuto" == '1' ]; then
        GetIp
        if ipCheck; then
            echo "自动检测的IPv4配置："
            echo "IP: $MAINIP"
            echo "Gateway: $GATEWAYIP"
            echo "Netmask: $NETMASK"
            read -p "确认使用以上配置？[Y/n] :" input
            [ -z "${input}" ] && input="y"
            case $input in
            [yY][eE][sS] | [yY]) ;;
            [nN][oO] | [nN])
                UpdateIp
                ipCheck || err "输入的IPv4配置无效"
                ;;
            *) err "用户取消操作" ;;
            esac
        else
            echo "检测IPv4时发生错误，请手动输入："
            UpdateIp
            ipCheck || err "输入的IPv4配置无效"
        fi
        NETSTR="--ip-addr ${MAINIP} --ip-gate ${GATEWAYIP} --ip-mask ${NETMASK}"
    fi

    # 如果检测到原生 IPv6
    if [ "$HAS_NATIVE_IPV6" == "1" ]; then
        USE_NATIVE_IPV6=1
    fi

    # 如果检测到 HE.net 隧道，询问是否启用
    if [ "$HE_TUNNEL" == "1" ]; then
        read -p "检测到现有的 HE.net IPv6 隧道，是否在新系统中启用？[Y/n] :" input
        [ -z "${input}" ] && input="y"
        case $input in
        [yY][eE][sS] | [yY]) USE_HE_TUNNEL=1 ;;
        [nN][oO] | [nN]) USE_HE_TUNNEL=0 ;;
        *) err "用户取消操作" ;;
        esac
    fi
}

# 执行网络设置、下载、删除、解压和初始化操作

SetNetwork
NetMode

ChooseSystem
GetVersions
DOWNLOAD_IMG
DELALL
EXTRACT_IMG
INIT_OS

# 清理安装后的临时文件并提示重启
# 检查 apt 是否存在
if command -v apt >/dev/null 2>&1; then
    echo "检测到 apt，系统安装成功"
    # 删除 /os 目录
    rm -rf $ROOTDIR || echo "警告：无法删除 /os 目录"
else
    err "系统安装失败，未找到 apt 命令"
    exit 1
fi

apt-get clean all
sync
mount -o remount,rw /
sleep 2
sync
mount -o remount,rw /
echo "安装完成，建议重启系统。"

read -p "确认上面没有严重的错误信息，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
    echo -e "${Info} VPS 重启中..."
    reboot -f
fi
