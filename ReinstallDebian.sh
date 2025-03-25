#!/usr/bin/env bash
# 设置环境变量，确保脚本能正确使用系统命令
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 提醒用户更改默认密码。此处可以加强，强调安全性重要性
echo "注意：默认密码为 blog.ylx.me，请在安装后立即更改！"

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

# 创建 /os 目录（如果不存在）
mkdir -p /os || err "无法创建 /os 目录"

# 获取支持的 Debian 版本并提示用户选择
function GetDebianVersions() {
	local url="https://cf-image.ylx.workers.dev/images/debian"
	local versions_file="debian_versions.txt"

	# 定义代号到版本号的映射（只包含有效版本）
	declare -A VERSION_MAP
	VERSION_MAP["bookworm"]="Debian 12"
	VERSION_MAP["bullseye"]="Debian 11"
	VERSION_MAP["buster"]="Debian 10"
	VERSION_MAP["trixie"]="Debian 13 (Testing)"

	echo "正在获取支持的 Debian 版本..."
	wget -q "$url" -O "$versions_file" || err "无法获取版本列表：$url"

	# 提取版本名称并过滤有效版本
	mapfile -t ALL_VERSIONS < <(grep -oP '[a-z]+(?=/)' "$versions_file" | sort -u)
	declare -a VERSIONS
	for version in "${ALL_VERSIONS[@]}"; do
		if [[ -n "${VERSION_MAP[$version]}" ]]; then
			VERSIONS+=("$version")
		fi
	done

	if [ ${#VERSIONS[@]} -eq 0 ]; then
		err "未检测到任何支持的 Debian 版本"
	fi

	# 显示版本并包含版本号
	echo "支持的 Debian 版本："
	for i in "${!VERSIONS[@]}"; do
		version_name="${VERSIONS[$i]}"
		version_number="${VERSION_MAP[$version_name]}"
		echo "$((i + 1)). $version_name ($version_number)"
	done

	# 获取用户输入
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
	local base_url="https://cf-image.ylx.workers.dev/images/debian"
	local cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/debian"
	local version="$SELECTED_VERSION"
	local arch=""
	local file="rootfs.tar.xz"
	local os_filename="/os/os.tar.xz"
	local busybox_filename="/os/busybox"
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
	local list_url="https://cf-image.ylx.workers.dev/images/debian/$version/$arch/cloud/?C=M;O=D"
	echo "正在获取可用镜像时间戳列表..."
	rm -rf /tmp/url.tmp
	curl -s -o /tmp/url.tmp "$list_url" || err "无法获取时间戳列表：$list_url"
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
	IMGURL="$base_url/$version/$arch/cloud/$urldata/$file"
	CN_IMGURL="$cn_base_url/$version/$arch/cloud/$urldata/$file"
	local url="$IMGURL"
	local checksum_url="$base_url/$version/$arch/cloud/$urldata/SHA256SUMS"

	# 下载镜像文件
	echo "开始下载镜像文件：$url"
	REMOTE_SIZE=$(wget --spider "$url" 2>&1 | grep -oP 'Length: \K\d+' | head -1)
	if [ -z "$REMOTE_SIZE" ]; then
		echo "警告：无法获取远程文件大小，跳过大小验证"
		SIZE_CHECK_AVAILABLE=0
	else
		echo "远程文件大小：$REMOTE_SIZE 字节"
		SIZE_CHECK_AVAILABLE=1
	fi

	if ! wget -q "$checksum_url" -O "SHA256SUMS" 2>/dev/null; then
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
		wget --timeout="$timeout" --tries=1 --continue -O "$os_filename" "$url" && break
		if [ "$i" -eq "$attempts" ]; then
			echo "原始 URL 下载失败，尝试 CN 镜像：$CN_IMGURL"
			url="$CN_IMGURL"
			checksum_url="$cn_base_url/$version/$arch/cloud/$urldata/SHA256SUMS"
			for ((j = 1; j <= attempts; j++)); do
				echo "尝试下载镜像（第 $j 次）..."
				wget --timeout="$timeout" --tries=1 --continue -O "$os_filename" "$url" && break
				if [ "$j" -eq "$attempts" ]; then
					err "下载镜像失败：$url 在 $attempts 次尝试后仍未成功"
				fi
				sleep 5
			done
			if ! wget -q "$checksum_url" -O "SHA256SUMS" 2>/dev/null; then
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

	# 下载 Busybox
	url="$BUSYBOX"
	echo "开始下载 Busybox：$url"
	REMOTE_SIZE=$(wget --spider "$url" 2>&1 | grep -oP 'Length: \K\d+' | head -1)
	if [ -z "$REMOTE_SIZE" ]; then
		echo "警告：无法获取 Busybox 远程文件大小，跳过大小验证"
		SIZE_CHECK_AVAILABLE=0
	else
		echo "Busybox 远程文件大小：$REMOTE_SIZE 字节"
		SIZE_CHECK_AVAILABLE=1
	fi

	for ((i = 1; i <= attempts; i++)); do
		echo "尝试下载 Busybox（第 $i 次）..."
		wget --timeout="$timeout" --tries=1 --continue -O "$busybox_filename" "$url" && break
		if [ "$i" -eq "$attempts" ]; then
			echo "原始 URL 下载 Busybox 失败，尝试 CN 镜像：$CN_BUSYBOX"
			url="$CN_BUSYBOX"
			for ((j = 1; j <= attempts; j++)); do
				echo "尝试下载 Busybox（第 $j 次）..."
				wget --timeout="$timeout" --tries=1 --continue -O "$busybox_filename" "$url" && break
				if [ "$j" -eq "$attempts" ]; then
					err "下载 Busybox 失败：$url 在 $attempts 次尝试后仍未成功"
				fi
				sleep 5
			done
			break
		fi
		sleep 5
	done

	# 验证 Busybox 文件大小
	if [ "$SIZE_CHECK_AVAILABLE" -eq 1 ]; then
		echo "验证 Busybox 文件大小..."
		LOCAL_SIZE=$(stat -c%s "$busybox_filename" 2>/dev/null || wc -c <"$busybox_filename")
		if [ "$LOCAL_SIZE" -eq "$REMOTE_SIZE" ]; then
			echo "Busybox 文件大小匹配（$LOCAL_SIZE 字节）"
		else
			err "Busybox 文件大小不匹配，下载可能不完整！本地大小: $LOCAL_SIZE 字节，远程大小: $REMOTE_SIZE 字节"
		fi
	fi

	echo "Busybox 下载完成，未提供 SHA256 校验和，跳过校验和验证"

	# 清理临时文件
	[ -f "SHA256SUMS" ] && rm -f "SHA256SUMS"
	[ -f "/tmp/url.tmp" ] && rm -f "/tmp/url.tmp"
        #权限
	chmod +x $busybox_filename
}

# 删除所有旧系统文件的函数
DELALL() {
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
		sed -i 's#http://deb.debian.org#http://mirrors.163.com#g' /etc/apt/sources.list
	else
		echo "nameserver 1.1.1.1" >/etc/resolv.conf
		echo "nameserver 8.8.8.8" >>/etc/resolv.conf
		echo "nameserver 9.9.9.9" >>/etc/resolv.conf
	fi
	rm -f /root/anaconda-ks.cfg
	export LC_ALL=C.UTF-8
	# 更新软件源
	apt-get update || err "无法更新软件源"
	# 根据架构安装软件包并检查
	bit=$(uname -m)
	if [ "$bit" == "x86_64" ]; then
		apt-get install -y systemd openssh-server passwd wget nano linux-image-cloud-amd64 htop net-tools \
			isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils || err "安装x86_64软件包失败"
	elif [ "$bit" == "aarch64" ]; then
		apt-get install -y systemd openssh-server passwd wget nano linux-image-arm64 htop net-tools \
			isc-dhcp-client ifupdown ifmetric ethtool fdisk coreutils curl sudo || err "安装aarch64软件包失败"
	fi
	# 安装GRUB并检查分区表
	DEBIAN_FRONTEND=noninteractive apt-get install -y grub2* -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装GRUB失败"

	device=$(fdisk -l | grep -o '/dev/[a-z]\+da' | head -1)
	if [ -z "$device" ]; then
		echo "错误：未检测到磁盘设备，请手动指定"
		read -p "请输入GRUB安装目标设备（例如 /dev/sda）：" device
	fi

	if [ -d "/sys/firmware/efi" ]; then
		# EFI模式安装
		echo "检测到EFI模式，安装GRUB..."
		if [ "$bit" == "x86_64" ]; then
			apt-get install -y grub-efi-amd64 err "安装grub-efi-amd64失败"
			grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck "$device" || err "GRUB EFI安装失败"
			mkdir -p /boot/efi/EFI/boot
			cp /boot/efi/EFI/debian/grubx64.efi /boot/efi/EFI/boot/bootx64.efi
		elif [ "$bit" == "aarch64" ]; then
			apt-get install -y grub2-common efivar grub-efi-arm64 efibootmgr || err "安装grub-efi-arm64失败"
			grub-install --target=arm64-efi --efi-directory=/boot/efi --bootloader-id=debian --recheck "$device" || err "GRUB EFI安装失败"
		fi
	else
		# BIOS模式安装
		echo "检测到BIOS模式，安装GRUB到 $device ..."
		apt-get install -y grub-pc || "安装grub-pc失败"
		grub-install --target=i386-pc "$device" || "GRUB BIOS安装失败"
	fi
	update-grub || err "更新GRUB配置失败"

	# 配置SSH
	sed -i '/Port /d' /etc/ssh/sshd_config
	sed -i '/^#PermitRootLogin\s/s/.*/&\nPermitRootLogin yes/' /etc/ssh/sshd_config
	sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
	sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
	sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 30/' /etc/ssh/sshd_config
	sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
	[ -n "$ssh_port" ] && sed -i "/Port\s/s/.*/Port ${ssh_port}/" /etc/ssh/sshd_config
	systemctl enable ssh

	# 设置默认密码并支持自定义
	echo -e "blog.ylx.me\nblog.ylx.me" | passwd "root"
	[ -n "$password" ] && echo -e "$password\n$password" | passwd "root"

	[ -n "$authorized_keys_url" ] && wget -q "$authorized_keys_url" -O /dev/null || err "无法下载SSH公钥从 \"$authorized_keys_url\""
	[ -n "$authorized_keys_url" ] && mkdir -m 0700 -p /root/.ssh && wget -O /root/.ssh/authorized_keys $authorized_keys_url && sed -i '/PasswordAuthentication\s/s/.*/PasswordAuthentication no/' /etc/ssh/sshd_config

	# 系统优化
	echo "net.core.default_qdisc=fq" >>/etc/sysctl.d/99-sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >>/etc/sysctl.d/99-sysctl.conf
	sed -i '/GRUB_CMDLINE_LINUX=/d' /etc/default/grub
	echo "GRUB_CMDLINE_LINUX=\"net.ifnames=0 biosdevname=0\"" >>/etc/default/grub
	$(which update-grub)

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

	$(which wget) -O /root/tcpx.sh "https://github.000060000.xyz/tcpx.sh" && $(which chmod) +x /root/tcpx.sh
	ln -fs /usr/bin/bash /usr/bin/sh
	# 设置时区
	echo "Asia/Shanghai" >/etc/timezone

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
	isCN='0'
	geoip=$(wget -qO- https://api.ip.sb/geoip -T 10 | grep "\"country_code\":\"CN\"")
	if [[ "$geoip" != "" ]]; then
		isCN='1'
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

GetDebianVersions
DOWNLOAD_IMG
DELALL
EXTRACT_IMG
INIT_OS

# 清理安装后的临时文件并提示重启
rm -rf $ROOTDIR
apt-get clean all
sync
echo "安装完成，建议重启系统。"

read -p "确认上面没有严重的错误信息，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
	echo -e "${Info} VPS 重启中..."
	reboot -f
fi
