#!/usr/bin/env bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

DEFAULT_HOSTNAME="my-os-$(date +%Y%m%d)"
DEFAULT_TIMEZONE="Asia/Shanghai"
DEFAULT_REGION="global"

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
base_url=""
cn_base_url=""
arch="$(uname -m)"

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
use_local_dns=0

grub_device=""
GRUB_STRATEGY="standard"
IS_EFI=0

busybox_filename=""
busybox_url=""
cn_busybox_url=""

err() {
	echo "错误：$1" >&2
	exit 1
}

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
	--apt-mirror)
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
		err "未知选项：'$1'"
		;;
	esac
done

[ ! -f "/usr/bin/bash" ] && ln -s "$(command -v bash)" /usr/bin/bash

install_tool() {
	local tool="$1"
	if command -v "$tool" >/dev/null 2>&1; then
		echo "$tool 已安装，继续执行"
		return 0
	fi

	echo "正在安装 $tool..."
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update && apt-get install -y "$tool"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y "$tool"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y "$tool"
	elif command -v apk >/dev/null 2>&1; then
		apk add "$tool"
	else
		err "未知的包管理器，请手动安装 $tool"
	fi
}

require_tools() {
	install_tool curl
	install_tool wget
	install_tool zip
	install_tool tar
}

set_arch_vars() {
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

	busybox_url="https://raw.githubusercontent.com/ylx2016/busybox-static-binaries-fat/main/${busybox_filename}"
	cn_busybox_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/busybox-static-binaries-fat/main/${busybox_filename}"
}

choose_system() {
	echo "请选择要安装的系统："
	echo "1. Debian"
	echo "2. Ubuntu"

	while true; do
		read -r -p "请输入数字 (1 或 2)： " choice
		case "$choice" in
		1)
			system="debian"
			base_url="https://images.linuxcontainers.org/images/debian"
			cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/debian"
			break
			;;
		2)
			system="ubuntu"
			base_url="https://images.linuxcontainers.org/images/ubuntu"
			cn_base_url="https://mirrors.tuna.tsinghua.edu.cn/lxc-images/images/ubuntu"
			break
			;;
		*)
			echo "无效输入，请输入 1 或 2"
			;;
		esac
	done

	echo "已选择系统：$system"
}

get_versions() {
	local versions_file="/tmp/versions.txt"
	declare -A version_map

	if [ "$system" = "debian" ]; then
		version_map=(
			["buster"]="Debian 10"
			["bullseye"]="Debian 11"
			["bookworm"]="Debian 12"
			["trixie"]="Debian 13"
			["forky"]="Debian 14"
		)
	else
		version_map=(
			["focal"]="Ubuntu 20.04 (Focal Fossa)"
			["jammy"]="Ubuntu 22.04 (Jammy Jellyfish)"
			["noble"]="Ubuntu 24.04 (Noble Numbat)"
			["oracular"]="Ubuntu 24.10 (Oracular Oriole)"
			["plucky"]="Ubuntu 25.04 (Plucky Puffin)"
			["questing"]="Ubuntu 25.10 (Questing Quokka)"
		)
	fi

	echo "正在获取支持的 $system 版本..."
	curl -fsSL "$base_url" -o "$versions_file" || err "无法获取版本列表：$base_url"

	mapfile -t all_versions < <(grep -oP '[a-z]+(?=/)' "$versions_file" | sort -u)
	versions=()

	for version in "${all_versions[@]}"; do
		[ -n "${version_map[$version]}" ] && versions+=("$version")
	done

	[ "${#versions[@]}" -eq 0 ] && err "未检测到支持的 $system 版本"

	echo "支持的 $system 版本："
	for i in "${!versions[@]}"; do
		echo "$((i + 1)). ${versions[$i]} (${version_map[${versions[$i]}]})"
	done

	while true; do
		read -r -p "请选择要安装的版本（输入数字 1-${#versions[@]}）： " choice
		if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#versions[@]}" ]; then
			selected_version="${versions[$((choice - 1))]}"
			echo "已选择版本：$selected_version (${version_map[$selected_version]})"
			break
		fi
		echo "无效输入，请输入 1 到 ${#versions[@]} 之间的数字"
	done

	rm -f "$versions_file"
}

get_local_resolv_source() {
	if [ -f "/etc/resolv.conf" ] && grep -q "127.0.0.53" /etc/resolv.conf && [ -f "/run/systemd/resolve/resolv.conf" ]; then
		echo "/run/systemd/resolve/resolv.conf"
		return 0
	fi

	if [ -f "/etc/resolv.conf" ]; then
		echo "/etc/resolv.conf"
		return 0
	fi

	return 1
}

backup_dns() {
	local resolv_src
	echo "备份 DNS"
	if resolv_src="$(get_local_resolv_source)"; then
		echo "备份 $resolv_src"
		cat "$resolv_src"
		cp "$resolv_src" "${root_dir}/resolv.conf.bak"
	else
		echo "警告：未找到可用 resolv.conf，跳过 DNS 备份"
	fi
}

get_recommended_dns() {
	local dns_content=""
	local has_v4_net=0

	if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -W 2 114.114.114.114 >/dev/null 2>&1; then
		has_v4_net=1
	fi

	if [ "$has_v4_net" -eq 0 ]; then
		dns_content="nameserver 2001:67c:2b0::4
nameserver 2a00:1098:2c::1
nameserver 2001:4860:4860::8888
nameserver 2001:4860:4860::8844"
	else
		if [ "$is_cn" -eq 1 ]; then
			dns_content="nameserver 114.114.114.114
nameserver 223.5.5.5"
		else
			dns_content="nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver 2001:67c:2b0::4"
		fi
	fi

	printf '%s\n' "$dns_content"
}

apply_dns_config() {
	local target_file="$1"

	rm -f "$target_file"
	touch "$target_file"

	if [ "$use_local_dns" -eq 1 ] && [ -f "${root_dir}/resolv.conf.bak" ]; then
		echo "使用用户选择的本地原 DNS 配置..."
		cat "${root_dir}/resolv.conf.bak" >"$target_file"
		cp "${root_dir}/resolv.conf.bak" "${target_file}.bak"
	else
		echo "使用脚本自动推荐的 DNS 配置..."
		get_recommended_dns >"$target_file"
	fi

	echo "当前 $target_file 内容："
	cat "$target_file"
}

download_with_retry() {
	local primary_url="$1"
	local fallback_url="$2"
	local output_file="$3"
	local attempts="${4:-3}"
	local timeout="${5:-10}"

	local ok=0
	local current_url="$primary_url"

	for ((i = 1; i <= attempts; i++)); do
		echo "尝试下载（第 $i/$attempts 次）：$current_url"
		if curl -SLf --retry 2 --connect-timeout "$timeout" -o "$output_file" "$current_url"; then
			ok=1
			break
		fi
		sleep 5
	done

	if [ "$ok" -ne 1 ] && [ -n "$fallback_url" ] && [ "$fallback_url" != "$primary_url" ]; then
		current_url="$fallback_url"
		for ((i = 1; i <= attempts; i++)); do
			echo "尝试备用地址下载（第 $i/$attempts 次）：$current_url"
			if curl -SLf --retry 2 --connect-timeout "$timeout" -o "$output_file" "$current_url"; then
				ok=1
				break
			fi
			sleep 5
		done
	fi

	[ "$ok" -ne 1 ] && err "下载失败：$primary_url"
}

download_text_with_fallback() {
	local primary_url="$1"
	local fallback_url="$2"
	local output_file="$3"

	if curl -fsSL "$primary_url" -o "$output_file"; then
		return 0
	fi

	if [ -n "$fallback_url" ] && [ "$fallback_url" != "$primary_url" ] && curl -fsSL "$fallback_url" -o "$output_file"; then
		return 0
	fi

	return 1
}

get_remote_size() {
	local url="$1"
	curl -sIL "$url" | awk 'BEGIN{IGNORECASE=1} /^Content-Length:/ {gsub("\r","",$2); print $2; exit}'
}

verify_size_if_needed() {
	local file="$1"
	local remote_size="$2"

	[ -z "$remote_size" ] && return 0
	[ "$remote_size" = "0" ] && return 0

	local local_size
	local_size=$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")

	if [ "$local_size" -eq "$remote_size" ]; then
		echo "文件大小匹配：$local_size 字节"
	else
		err "文件大小不匹配，本地大小: $local_size，远程大小: $remote_size"
	fi
}

download_image() {
	local file="rootfs.tar.xz"
	local os_filename="${root_dir}/os.tar.xz"
	local attempts=3
	local timeout=10
	local list_url="$base_url/$selected_version/$image_arch/cloud/?C=M;O=D"

	mkdir -p "$root_dir" || err "无法创建 $root_dir 目录"

	backup_dns

	echo "正在获取可用镜像时间戳列表..."
	curl -fsSL "$list_url" -o /tmp/url.tmp || err "无法获取时间戳列表：$list_url"

	mapfile -t timestamp_list < <(grep -oE '2[0-9]{7}_[0-9]{2}:[0-9]{2}' /tmp/url.tmp | sort -r)
	[ "${#timestamp_list[@]}" -eq 0 ] && err "未检测到任何可用时间戳目录"

	local timestamp="${timestamp_list[0]}"
	echo "找到最新的镜像时间戳：$timestamp"

	local img_url="$base_url/$selected_version/$image_arch/cloud/$timestamp/$file"
	local cn_img_url="$cn_base_url/$selected_version/$image_arch/cloud/$timestamp/$file"
	local checksum_url="$base_url/$selected_version/$image_arch/cloud/$timestamp/SHA256SUMS"
	local cn_checksum_url="$cn_base_url/$selected_version/$image_arch/cloud/$timestamp/SHA256SUMS"

	local preferred_img_url="$img_url"
	local fallback_img_url="$cn_img_url"
	local preferred_checksum_url="$checksum_url"
	local fallback_checksum_url="$cn_checksum_url"

	if [ "$region" = "cn" ]; then
		preferred_img_url="$cn_img_url"
		fallback_img_url="$img_url"
		preferred_checksum_url="$cn_checksum_url"
		fallback_checksum_url="$checksum_url"
	fi

	echo "开始下载镜像文件：$preferred_img_url"

	local remote_size=""
	remote_size="$(get_remote_size "$preferred_img_url")"
	[ -z "$remote_size" ] && remote_size="$(get_remote_size "$fallback_img_url")"
	[ -z "$remote_size" ] && echo "警告：无法获取远程文件大小，可能会跳过大小校验"

	local checksum_available=0
	local expected_checksum=""

	if download_text_with_fallback "$preferred_checksum_url" "$fallback_checksum_url" "SHA256SUMS"; then
		expected_checksum="$(grep " $file$" SHA256SUMS | awk '{print $1}')"
		[ -n "$expected_checksum" ] && checksum_available=1
	fi

	download_with_retry "$preferred_img_url" "$fallback_img_url" "$os_filename" "$attempts" "$timeout"

	if [ "$checksum_available" -eq 1 ]; then
		echo "验证镜像文件 SHA256 校验和..."
		local actual_checksum
		actual_checksum="$(sha256sum "$os_filename" | awk '{print $1}')"
		[ "$actual_checksum" = "$expected_checksum" ] || err "镜像文件 SHA256 校验和不匹配！期望值: $expected_checksum，实际值: $actual_checksum"
		echo "镜像文件 SHA256 校验和匹配，文件完整性验证通过"
	else
		echo "未获取到可用 SHA256，改为校验文件大小"
		verify_size_if_needed "$os_filename" "$remote_size"
	fi

	local current_busybox_url="$busybox_url"
	local fallback_busybox_url="$cn_busybox_url"

	if [ "$region" = "cn" ]; then
		current_busybox_url="$cn_busybox_url"
		fallback_busybox_url="$busybox_url"
	fi

	echo "开始下载 BusyBox：$current_busybox_url"
	local busybox_remote_size=""
	busybox_remote_size="$(get_remote_size "$current_busybox_url")"
	[ -z "$busybox_remote_size" ] && busybox_remote_size="$(get_remote_size "$fallback_busybox_url")"
	[ -z "$busybox_remote_size" ] && echo "警告：无法获取 BusyBox 远程文件大小"

	download_with_retry "$current_busybox_url" "$fallback_busybox_url" "$busybox_path" "$attempts" "$timeout"

	chmod +x "$busybox_path" || err "无法为 $busybox_path 设置可执行权限"
	"$busybox_path" --help >/dev/null 2>&1 || err "BusyBox 测试失败：$busybox_path"

	if [ -n "$busybox_remote_size" ] && [ "$busybox_remote_size" != "0" ]; then
		local local_size
		local_size=$(stat -c%s "$busybox_path" 2>/dev/null || wc -c <"$busybox_path")
		if [ "$local_size" -eq "$busybox_remote_size" ]; then
			echo "BusyBox 文件大小匹配：$local_size 字节"
		else
			echo "警告：BusyBox 文件大小不匹配。本地: $local_size，远程: $busybox_remote_size"
		fi
	fi

	rm -f SHA256SUMS /tmp/url.tmp
}

delete_old_system() {
	[ -f "$busybox_path" ] || err "BusyBox 文件缺失：$busybox_path"
	"$busybox_path" --help >/dev/null 2>&1 || err "BusyBox 不可执行：$busybox_path"

	cp /etc/fstab "$root_dir" 2>/dev/null || echo "警告：无法备份 fstab"

	if command -v chattr >/dev/null 2>&1; then
		find / -type f \
			\( ! -path '/dev/*' -a ! -path '/proc/*' -a ! -path '/sys/*' -a ! -path "$root_dir/*" \) \
			-exec chattr -i {} + 2>/dev/null || true
	fi

	find / \
		\( ! -path '/dev/*' -a ! -path '/proc/*' -a ! -path '/sys/*' -a ! -path "$root_dir/*" \) \
		-delete 2>/dev/null || true
}

extract_image() {
	if [ -e "/etc/machine-id" ]; then
		echo "尝试移除旧的 /etc/machine-id..."
		command -v chattr >/dev/null 2>&1 && chattr -i /etc/machine-id 2>/dev/null || true
		rm -f /etc/machine-id || echo "警告：无法删除旧的 /etc/machine-id"
	fi

	echo "开始解压系统镜像..."
	cd "$root_dir" || err "无法进入 $root_dir"
	"$busybox_path" xzcat "$root_dir/os.tar.xz" | "$busybox_path" tar -x -C /

	[ -f "$root_dir/fstab" ] && mv -f "$root_dir/fstab" /etc
	[ -f "${root_dir}/resolv.conf.bak" ] && cp "${root_dir}/resolv.conf.bak" /etc/resolv.conf.old
}

get_default_apt_mirror() {
	if [ "$is_cn" -eq 1 ]; then
		if [ "$system" = "debian" ]; then
			echo "https://mirrors.ustc.edu.cn/debian"
		else
			echo "https://mirrors.ustc.edu.cn/ubuntu"
		fi
	else
		if [ "$system" = "debian" ]; then
			echo "http://deb.debian.org/debian"
		else
			echo "http://archive.ubuntu.com/ubuntu"
		fi
	fi
}

write_apt_sources() {
	local mirror_url="$1"
	local codename="$2"

	: >/etc/apt/sources.list

	if [ "$system" = "debian" ]; then
		local components="main contrib non-free"
		[[ "$codename" == "bookworm" || "$codename" == "trixie" ]] && components="main contrib non-free non-free-firmware"

		cat >>/etc/apt/sources.list <<EOF
deb $mirror_url $codename $components
deb $mirror_url $codename-updates $components
deb $mirror_url $codename-backports $components
deb http://security.debian.org/debian-security $codename-security $components
EOF
	else
		local components="main restricted universe multiverse"

		cat >>/etc/apt/sources.list <<EOF
deb $mirror_url $codename $components
deb $mirror_url $codename-updates $components
deb $mirror_url $codename-backports $components
deb $mirror_url $codename-security $components
EOF
	fi
}

configure_ssh() {
	echo "配置 SSH 服务..."

	if [ ! -f "/etc/ssh/sshd_config" ]; then
		echo "警告：/etc/ssh/sshd_config 未找到，SSH 可能无法启动"
		return 0
	fi

	grep -q "^Port " /etc/ssh/sshd_config || echo "Port 22" >>/etc/ssh/sshd_config

	if [ -n "$ssh_port" ]; then
		sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config
	else
		sed -i "s/^Port .*/Port 22/" /etc/ssh/sshd_config
	fi

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

	if grep -q "^#*MaxAuthTries" /etc/ssh/sshd_config; then
		sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
	else
		echo "MaxAuthTries 3" >>/etc/ssh/sshd_config
	fi

	if grep -q "^#*GSSAPIAuthentication" /etc/ssh/sshd_config; then
		sed -i 's/^#*GSSAPIAuthentication.*/GSSAPIAuthentication no/' /etc/ssh/sshd_config
	else
		echo "GSSAPIAuthentication no" >>/etc/ssh/sshd_config
	fi

	if grep -q "^#*ClientAliveInterval" /etc/ssh/sshd_config; then
		sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 60/' /etc/ssh/sshd_config
	else
		echo "ClientAliveInterval 60" >>/etc/ssh/sshd_config
	fi

	if grep -q "^#*UseDNS" /etc/ssh/sshd_config; then
		sed -i 's/^#*UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
	else
		echo "UseDNS no" >>/etc/ssh/sshd_config
	fi

	systemctl enable ssh
}

configure_root_password() {
	echo "设置 root 用户密码..."
	local final_password="${password:-blog.ylx.me}"
	echo -e "${final_password}\n${final_password}" | passwd root

	if [ "$final_password" = "blog.ylx.me" ]; then
		echo "警告：root 密码设置为默认值 'blog.ylx.me'，请在首次登录后更改！"
	else
		echo "root 密码已根据用户输入设置"
	fi
}

configure_authorized_keys() {
	[ -z "$authorized_keys_url" ] && return 0

	echo "从 $authorized_keys_url 下载并配置 SSH 公钥..."
	mkdir -p -m 0700 /root/.ssh

	if curl -sSLf --connect-timeout 10 "$authorized_keys_url" -o /root/.ssh/authorized_keys; then
		chmod 0600 /root/.ssh/authorized_keys
		sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
		echo "SSH 公钥配置完成，密码登录已禁用"
	else
		echo "警告：无法下载 SSH 公钥：$authorized_keys_url"
	fi
}

write_network_interfaces() {
	if [ -d /etc/netplan ]; then
		rm -f /etc/netplan/*.yaml
		echo "已移除 Netplan 配置以确保 ifupdown 生效"
	fi

	if [ "$is_auto" -eq 1 ]; then
		cat >/etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $network_adapter
iface $network_adapter inet static
    address $main_ip
    netmask $netmask
    gateway $gateway_ip
EOF

		if [ "$use_native_ipv6" -eq 1 ]; then
			cat >>/etc/network/interfaces <<EOF
iface $network_adapter inet6 static
    address $native_ipv6_addr
    netmask $native_ipv6_mask
    gateway $native_ipv6_gw
EOF
		fi
	else
		cat >/etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $network_adapter
iface $network_adapter inet dhcp
iface $network_adapter inet6 dhcp
EOF
	fi

	if [ "$use_he_tunnel" -eq 1 ]; then
		cat >>/etc/network/interfaces <<EOF
auto he-ipv6
iface he-ipv6 inet6 v4tunnel
    address $he_client_ipv6
    netmask $he_netmask
    endpoint $he_server_ipv4
    local $he_client_ipv4
    ttl 255
    gateway $he_server_ipv6
EOF
	fi
}

install_base_packages() {
	export DEBIAN_FRONTEND=noninteractive
	export DEBCONF_NONINTERACTIVE_SEEN=true

	if command -v debconf-set-selections >/dev/null 2>&1; then
		echo "tzdata tzdata/Areas select Etc" | debconf-set-selections
		echo "tzdata tzdata/Zones/Etc select UTC" | debconf-set-selections
		echo "keyboard-configuration keyboard-configuration/layout select English (US)" | debconf-set-selections
		echo "keyboard-configuration keyboard-configuration/layoutcode select us" | debconf-set-selections
	fi

	local APT_OPTS="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
	local DHCP_CLIENT="isc-dhcp-client"

	if ! apt-get -s install isc-dhcp-client >/dev/null 2>&1; then
		DHCP_CLIENT="dhcpcd-base"
	fi

	local BASE_PACKAGES="systemd openssh-server passwd wget nano htop net-tools ${DHCP_CLIENT} ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs"

	if [ "$system" = "debian" ]; then
		if [ "$arch" = "x86_64" ]; then
			apt-get install $APT_OPTS linux-image-cloud-amd64 $BASE_PACKAGES || err "安装 x86_64 软件包失败"
		elif [ "$arch" = "aarch64" ]; then
			apt-get install $APT_OPTS linux-image-arm64 $BASE_PACKAGES || err "安装 aarch64 软件包失败"
		fi
	elif [ "$system" = "ubuntu" ]; then
		apt-get install $APT_OPTS linux-image-virtual $BASE_PACKAGES || err "安装 $arch 软件包失败"
	else
		err "未知系统类型：$system"
	fi
}

install_grub() {
	echo "安装 GRUB 引导加载程序..."
	apt-get install -y grub2 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装 GRUB 失败"

	case "$GRUB_STRATEGY" in
	efi)
		echo "检测到 EFI 策略，安装 GRUB-EFI..."
		local grub_efi_pkg=""
		local grub_target=""

		if [ "$arch" = "x86_64" ]; then
			grub_efi_pkg="grub-efi-amd64"
			grub_target="x86_64-efi"
		elif [ "$arch" = "aarch64" ]; then
			grub_efi_pkg="grub-efi-arm64"
			grub_target="arm64-efi"
			apt-get install -y efibootmgr || echo "警告: efibootmgr 安装失败，但继续尝试"
		else
			err "不支持的 EFI 架构: $arch"
		fi

		apt-get install -y "$grub_efi_pkg" || err "安装 $grub_efi_pkg 失败"
		mkdir -p /boot/efi
		grub-install --target="$grub_target" --efi-directory=/boot/efi --bootloader-id="$system" --recheck "$grub_device" || err "GRUB EFI 安装失败"

		local efi_file_path="/boot/efi/EFI/$system/grubx64.efi"
		[ "$arch" = "aarch64" ] && efi_file_path="/boot/efi/EFI/$system/grubaa64.efi"

		if [ -f "$efi_file_path" ]; then
			mkdir -p /boot/efi/EFI/BOOT
			if [ "$arch" = "x86_64" ]; then
				cp "$efi_file_path" /boot/efi/EFI/BOOT/BOOTX64.EFI
			else
				cp "$efi_file_path" /boot/efi/EFI/BOOT/BOOTAA64.EFI
			fi
			echo "EFI 引导文件备份成功"
		else
			err "验证失败：未找到 EFI 核心文件 $efi_file_path"
		fi
		;;

	standard)
		echo "执行标准 BIOS 模式安装..."
		grub-install --target=i386-pc --boot-directory=/boot --recheck "$grub_device" || {
			echo "警告：标准安装遇到分区校验阻碍，尝试强制模式自救..."
			grub-install --target=i386-pc --boot-directory=/boot --recheck --force "$grub_device" || err "GRUB BIOS 强制自救失败"
		}
		;;

	force_embed)
		echo "执行强制嵌入模式 (适配 Legacy+GPT 无 BIOS Boot 分区)..."
		grub-install --target=i386-pc --boot-directory=/boot --recheck --force "$grub_device" || err "GRUB 强制嵌入安装失败"
		;;
	esac

	if command -v update-grub >/dev/null 2>&1; then
		update-grub || err "更新 GRUB 配置失败"
	else
		grub-mkconfig -o /boot/grub/grub.cfg || err "更新 GRUB 配置失败"
	fi
}

init_os() {
	cd / || err "无法进入根目录"

	rm -f /etc/resolv.conf
	touch /etc/resolv.conf
	apply_dns_config "/etc/resolv.conf"

	rm -f /root/anaconda-ks.cfg
	export LC_ALL=C.UTF-8

	echo "配置 APT 软件源..."
	local final_apt_mirror_url="${apt_mirror_url:-$(get_default_apt_mirror)}"
	echo "使用 APT 镜像：$final_apt_mirror_url"

	[ -f "/etc/apt/sources.list" ] && cp /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)"
	write_apt_sources "$final_apt_mirror_url" "$selected_version"

	echo "APT 软件源配置完成"
	apt-get update || err "无法更新软件源"

	install_base_packages
	install_grub

	echo "正在强制将缓存数据写入磁盘..."
	sync
	sync
	sync
	sleep 5
	echo "数据同步完成"

	configure_ssh
	configure_root_password
	configure_authorized_keys

	echo "应用系统优化配置..."
	cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

	if [ -f "/etc/default/grub" ]; then
		sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet"/' /etc/default/grub
		sed -i 's/GRUB_CMDLINE_LINUX="[^"]*"/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' /etc/default/grub
		grep -q '^GRUB_CMDLINE_LINUX=' /etc/default/grub || echo 'GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"' >>/etc/default/grub
		update-grub
	else
		echo "警告：/etc/default/grub 未找到，无法修改内核参数"
	fi

	systemctl enable networking
	write_network_interfaces

	cat >>/etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF

	mkdir -p /etc/systemd/system/networking.service.d/
	printf "[Service]\nTimeoutStartSec=15sec\n" >/etc/systemd/system/networking.service.d/timeout.conf

	echo "配置最终系统 DNS..."
	apply_dns_config "/etc/resolv.conf"
	echo "老的 DNS 备份在 /etc/resolv.conf.old"

	echo "precedence ::ffff:0:0/96 100" >>/etc/gai.conf

	echo "$hostname" >/etc/hostname
	grep -q "127.0.0.1 $hostname" /etc/hosts 2>/dev/null || echo "127.0.0.1 $hostname" >>/etc/hosts

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

	echo "尝试下载 tcpx.sh ..."
	local tcpx_sh_url="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
	[ "$region" = "cn" ] && tcpx_sh_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"

	if wget --connect-timeout=15 -T 10 -O /root/tcpx.sh "$tcpx_sh_url"; then
		chmod +x /root/tcpx.sh
		echo "tcpx.sh 下载成功，可在系统启动后运行 /root/tcpx.sh"
	else
		echo "警告：tcpx.sh 下载失败，跳过此步骤"
	fi
}

get_ip() {
	main_ip=$(ip -4 route get 1 2>/dev/null | grep -oP 'src \K[\d.]+' | head -1)
	[ -z "$main_ip" ] && main_ip=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+' | head -1)

	if [ -z "$main_ip" ]; then
		echo "警告：无法自动检测主 IP"
		return 1
	fi

	gateway_ip=$(ip -4 route show default 2>/dev/null | awk '{print $3}' | head -1)
	if [ -z "$gateway_ip" ]; then
		echo "警告：无法自动检测网关"
		return 1
	fi

	subnet=$(ip -4 addr show scope global | grep -oP 'inet \K[\d.]+/\d+' | head -1 | cut -d'/' -f2)
	[ -z "$subnet" ] && subnet=24

	local value=$((0xffffffff ^ ((1 << (32 - subnet)) - 1)))
	netmask="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"
	return 0
}

check_ipv6() {
	local ipv6_addr
	ipv6_addr=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+/[0-9]+' | head -1)

	if [ -n "$ipv6_addr" ]; then
		echo "检测到 IPv6 地址：$ipv6_addr"
		has_ipv6=1
	else
		echo "未检测到 IPv6 地址"
		has_ipv6=0
	fi

	native_ipv6_iface=$(ip -6 addr show scope global | grep -B1 "$ipv6_addr" 2>/dev/null | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -E '^(eth|en)' | head -1)

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

	if [ "$has_ipv6" -eq 1 ]; then
		local tunnel_iface
		tunnel_iface=$(ip -6 addr show scope global | grep -B1 "$ipv6_addr" 2>/dev/null | grep -oP '^\d+:\s+\K\S+' | sed 's/@.*$//' | grep -v -E '^(eth|en)' | head -1)

		if [ -n "$tunnel_iface" ] && ip tunnel show "$tunnel_iface" 2>/dev/null | grep -q "ipv6/ip"; then
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

	[ "$has_ipv6" -eq 0 ] && [ "$he_tunnel" -eq 0 ] && [ "$has_native_ipv6" -eq 0 ] && return 1
	return 0
}

test_ipv6() {
	if ping6 -c 4 2001:4860:4860::8888 >/dev/null 2>&1; then
		echo "IPv6 连通性测试成功"
		return 0
	fi
	echo "IPv6 连通性测试失败"
	return 1
}

is_valid_ip() {
	local ip="$1"

	[[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1

	IFS='.' read -r -a octets <<<"$ip"
	for octet in "${octets[@]}"; do
		octet=$((10#$octet))
		[ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
	done
	return 0
}

ip_check() {
	local invalid=0
	for addr in "$main_ip" "$gateway_ip" "$netmask"; do
		if [ -z "$addr" ]; then
			echo "错误：IP、网关或子网掩码为空"
			invalid=1
		elif ! is_valid_ip "$addr"; then
			echo "错误：无效的 IP 地址 '$addr'"
			invalid=1
		fi
	done
	return "$invalid"
}

update_ip() {
	read -r -p "请输入 IP 地址: " main_ip
	read -r -p "请输入网关地址: " gateway_ip
	read -r -p "请输入子网掩码: " netmask
}

set_network() {
	if [ "$region" = "cn" ]; then
		is_cn=1
		echo "根据 --region cn 参数，判定为中国区域"
	else
		is_cn=0
		echo "根据 --region ${region} 参数，判定为非中国区域"
	fi

	is_auto=0

	if [ -f /etc/network/interfaces ]; then
		grep -q 'iface.*inet static' /etc/network/interfaces && is_auto=1

		if [ -d /etc/network/interfaces.d ]; then
			for net_config in /etc/network/interfaces.d/*.cfg; do
				[ -f "$net_config" ] || continue
				grep -q 'iface.*inet static' "$net_config" && is_auto=1
			done
		fi
	fi

	if [ -d /etc/sysconfig/network-scripts ]; then
		for net_config in /etc/sysconfig/network-scripts/ifcfg-*; do
			[ -f "$net_config" ] || continue
			echo "$net_config" | grep -q 'lo$' && continue
			grep -qi 'BOOTPROTO.*static' "$net_config" && is_auto=1
		done
	fi

	check_ipv6 || true
}

show_dns_choices() {
	echo "------------------------------------------------"
	echo "正在检测 DNS 配置..."
	echo "1. 原系统 DNS (/etc/resolv.conf):"
	local resolv_src
	if resolv_src="$(get_local_resolv_source)"; then
		cat "$resolv_src"
	else
		echo "未检测到"
	fi
	echo
	echo "2. 脚本建议 DNS (基于当前网络环境自动生成):"
	get_recommended_dns
	echo "------------------------------------------------"
}

net_mode() {
	if [ "$is_auto" -eq 0 ]; then
		read -r -p "是否设置为动态获取 IP (DHCP)？[Y/n]: " input
		[ -z "$input" ] && input="y"
		case "$input" in
		[yY][eE][sS] | [yY]) ;;
		[nN][oO] | [nN]) is_auto=1 ;;
		*) err "用户取消操作" ;;
		esac
	fi

	if [ "$is_auto" -eq 1 ]; then
		get_ip || true
		if ip_check; then
			echo "自动检测的 IPv4 配置："
			echo "IP: $main_ip"
			echo "网关: $gateway_ip"
			echo "子网掩码: $netmask"
			read -r -p "确认使用以上配置？[Y/n]: " input
			[ -z "$input" ] && input="y"
			case "$input" in
			[yY][eE][sS] | [yY]) ;;
			[nN][oO] | [nN])
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

	[ "$has_native_ipv6" -eq 1 ] && use_native_ipv6=1

	if [ "$he_tunnel" -eq 1 ]; then
		read -r -p "检测到 HE.net IPv6 隧道，是否在新系统中启用？[Y/n]: " input
		[ -z "$input" ] && input="y"
		case "$input" in
		[yY][eE][sS] | [yY]) use_he_tunnel=1 ;;
		[nN][oO] | [nN]) use_he_tunnel=0 ;;
		*) err "用户取消操作" ;;
		esac
	fi

	show_dns_choices

	read -r -t 18 -p "是否强制使用原系统 DNS (选项1)? 输入 y 使用原版，输入 n 或回车使用脚本建议 [y/N] (18秒后默认N): " dns_choice
	if [ -z "$dns_choice" ]; then
		echo
		echo "等待超时，默认使用脚本建议配置。"
		dns_choice="n"
	fi

	case "$dns_choice" in
	[yY][eE][sS] | [yY])
		use_local_dns=1
		echo "已选择：保留原系统 DNS"
		;;
	*)
		use_local_dns=0
		echo "已选择：使用脚本建议 DNS"
		;;
	esac
}

detect_disk() {
	echo "正在检测目标磁盘..."
	mapfile -t potential_disks < <(lsblk -nd -o NAME,TYPE,RO,RM | awk '$2=="disk" && $3=="0" && $4=="0" {print "/dev/"$1}')

	if [ "${#potential_disks[@]}" -eq 0 ]; then
		grub_device=$(fdisk -l 2>/dev/null | grep -Eo '/dev/[sv]d[a-z]+|/dev/nvme[0-9]+n[0-9]+|/dev/xvd[a-z]+|/dev/vd[a-z]+' | head -1)
		[ -z "$grub_device" ] && err "无法自动检测到合适的磁盘设备用于 GRUB 安装"
		echo "检测到磁盘 $grub_device 用于 GRUB 安装"
	elif [ "${#potential_disks[@]}" -eq 1 ]; then
		grub_device="${potential_disks[0]}"
		local disk_size
		disk_size=$(lsblk -b -d -o SIZE "$grub_device" | tail -n 1 | awk '{printf "%.2f GB", $1/1024/1024/1024}')
		echo "自动选择磁盘 $grub_device (大小: $disk_size) 用于 GRUB 安装"
	else
		echo "检测到多个磁盘设备，请选择安装 GRUB 的主系统引导盘:"
		for i in "${!potential_disks[@]}"; do
			local disk_info
			disk_info=$(lsblk -b -d -o SIZE,MODEL "${potential_disks[$i]}" | tail -n 1 | awk '{model=$2; for(j=3;j<=NF;j++) model=model"_"$j; printf "大小: %.2f GB, 型号: %s", $1/1024/1024/1024, model}')
			echo "$((i + 1)). ${potential_disks[$i]} (${disk_info})"
		done

		read -r -p "请输入 GRUB 安装目标设备的数字: " choice_grub_disk
		if [[ "$choice_grub_disk" =~ ^[0-9]+$ ]] && [ "$choice_grub_disk" -ge 1 ] && [ "$choice_grub_disk" -le "${#potential_disks[@]}" ]; then
			grub_device="${potential_disks[$((choice_grub_disk - 1))]}"
		else
			err "无效选择，无法确定 GRUB 安装设备"
		fi
	fi

	echo "GRUB 目标磁盘已锁定为: $grub_device"
}

auto_detect_grub_mode() {
	echo "------------------------------------------------"
	echo "正在深度扫描磁盘与引导拓扑结构..."

	local target_disk="$grub_device"
	GRUB_STRATEGY="standard"

	if [ -d /sys/firmware/efi ]; then
		IS_EFI=1
		echo "[检测结果] 固件模式: UEFI"
	else
		IS_EFI=0
		echo "[检测结果] 固件模式: Legacy BIOS"
	fi

	local label_type=""
	label_type=$(fdisk -l "$target_disk" 2>/dev/null | grep -oP 'Disklabel type: \K\w+')
	echo "[检测结果] 分区表类型: $label_type"

	if [ "$IS_EFI" -eq 1 ]; then
		GRUB_STRATEGY="efi"
	elif [ "$label_type" = "gpt" ]; then
		if fdisk -l "$target_disk" 2>/dev/null | grep -q "BIOS boot"; then
			echo "[状态] 发现标准 BIOS Boot 分区，使用标准模式。"
			GRUB_STRATEGY="standard"
		else
			echo "[警告] GPT 磁盘缺失 BIOS Boot 分区！"
			echo "[决策] 将在安装时启用 '--force' 暴力嵌入模式（原系统兼容方案）。"
			GRUB_STRATEGY="force_embed"
		fi
	else
		echo "[状态] 标准 MBR 结构，使用标准模式。"
		GRUB_STRATEGY="standard"
	fi
	echo "------------------------------------------------"
}

finalize_install() {
	if command -v apt >/dev/null 2>&1; then
		echo "检测到 apt，系统安装成功"
		rm -rf "$root_dir" || echo "警告：无法删除 $root_dir 目录"
	else
		err "系统安装失败，未找到 apt 命令"
	fi

	apt-get clean all

	echo "正在强制将缓存数据写入磁盘..."
	sync
	sync
	sync
	sleep 5
	echo "数据同步完成"

	mount -o remount,rw / || true
	sync
	sync
	sync
	sleep 10
	echo "数据同步完成"
}

reboot_prompt() {
	echo "安装完成，建议重启系统"
	echo "确认无严重错误，请选择重启方式："
	echo "1: 性能机 - 10秒后重启"
	echo "2: 一般机 - 30秒后重启"
	echo "3: 钻石机 - 2分钟后重启"

	read -r -t 10 -p "请输入选项（1/2/3，10s后默认2）: " choice
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

main() {
	require_tools
	set_arch_vars
	set_network
	net_mode
	choose_system
	get_versions
	detect_disk
	auto_detect_grub_mode
	download_image
	delete_old_system
	extract_image
	init_os
	finalize_install
	reboot_prompt
}

main "$@"
