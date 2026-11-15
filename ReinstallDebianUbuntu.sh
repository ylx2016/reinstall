#!/usr/bin/env bash

PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

# 管道中任意一段失败都必须暴露出来，否则 xzcat | tar 解到一半仍会被当作成功
set -o pipefail

# GRUB/磁盘探测依赖 fdisk 的英文输出，提前固定 locale
export LC_ALL=C

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
# --image-version：非交互指定发行代号（bookworm/trixie/noble…）。
# 为空时仍然交互选择；指定值会先与受支持列表比对，不在列表里直接失败。
image_version=""
base_url=""
cn_base_url=""
arch="$(uname -m)"

is_cn=0
is_auto=0

network_adapter="eth0"
# 当前系统的 IP 获取方式：dhcp / static / unknown。
# 重装默认沿用同一方式（当前 DHCP 就默认 DHCP，当前静态就默认静态），
# 只有在识别不出时才询问。
ip_mode="unknown"
# 主网卡（带默认路由的那块）与它的 MAC。新系统靠 .link 文件把这块网卡
# 固定命名为 eth0，避免多网卡机器上枚举顺序变化导致配置绑到错的网卡。
primary_nic=""
primary_nic_mac=""
nic_count=0
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

# 抹盘前从旧系统采集的 IPv6 细节。只记「一个地址一个掩码一个网关」不够：
# 提供商常给 /64 里的一段 + 额外路由，重装后丢失就会掉 IPv6 连通性。
ipv6_addrs=()
ipv6_gw=""
ipv6_routes=()
# 1 = 地址由 RA/DHCPv6 自动获得（那就继续用 auto，写死反而会在网络变更后失效）
ipv6_dynamic=0

# DHCP 身份。很多 VPS 按 client-id / DUID / hostname 分配固定 IP：
# 重装后这三样一变，拿到的地址就可能不同，甚至拿不到地址直接失联。
dhcp_client_id=""
dhcp6_client_id=""
dhcp_hostname=""
dhcp_id_source=""

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
# 构建产物所在 ref。
# 默认钉死到具体 commit：分支名（main）会随每次构建前移，等于「哈希清单和二进制
# 一起漂移」，SHA256SUMS 就退化成只能防传输损坏。40 位 commit SHA 才是不可变指针。
# 更新方式：上游仓库出现新构建后，取 `git rev-parse main` 的结果替换此处。
# 需要临时回到可变行为时：--busybox-ref main（会触发显著告警）。
BUSYBOX_DEFAULT_REF="3a7b23ad5a5ed498f6e22f94578f6067e78be668"
busybox_ref="$BUSYBOX_DEFAULT_REF"
# 操作者是否显式改了 ref（显式改 = 认可失去内置指纹，允许零校验继续）
busybox_ref_explicit=0
busybox_base_url=""
cn_busybox_base_url=""
busybox_url=""
cn_busybox_url=""

# 完整性固定值 / 行为开关。为空表示未固定，脚本会显著告警或拒绝继续。
expected_image_sha256=""
busybox_sha256=""
allow_size_only=0
assume_yes=0
# 上次运行在抹盘阶段中断（$root_dir/WIPE_STARTED 存在）时，必须显式加
# --resume-partial 才允许继续；否则脚本会拒绝，避免在半新半旧系统上误操作
resume_partial=0
# --dry-run：跑完所有探测/下载/预检，把将要执行的动作打印出来就退出，
# 绝不进入 delete_old_system。想先确认"这台机器上到底会抹哪块盘"时用。
dry_run=0
# 1 = 抹盘前把新系统必需软件包（内核/initramfs-tools/DHCP 客户端…）预下载到
# $root_dir/offline-debs，抹盘后网络异常也能 dpkg -i 救回可引导状态。
# 0 = --no-offline-stage，跳过预下载（宿主没有 apt 或跨架构时也会自动跳过）。
offline_stage=1
# 1 = /os 是本次运行新建的，dry-run 退出时应整体删除；0 = 原本就存在，只删下载产物
root_dir_created=0
download_tcpx=0
password_file=""
password_stdin=0
work_dir=""
# 抹盘前的挂载点列表（路径）。抹盘后 /usr/bin/findmnt 已被删除，
# 每次重建排除表达式都会拿不到挂载点，把 /boot/efi 这类必留的挂载点当成残留。
WIPE_MOUNTS=()
final_password=""
# 已通过校验的镜像 SHA256，供解压前二次复核（缩窄 TOCTOU 窗口）
verified_image_sha256=""
# 是否已进入破坏窗口（抹盘开始后置 1）。信号 trap 据此给出不同文案：
# 抹盘前中断是安全的，抹盘后中断意味着系统可能半新半旧
wipe_phase=0
# 镜像选择开关。
# 默认取镜像站"最新"的 timestamp：linuxcontainers.org 会轮转清理旧 timestamp 目录，
# 把某次固定链接当默认值，几天后就会 404，脚本等于默认坏掉。
# 内置指纹表因此降级为"已知良好记录"：最新 timestamp 恰好命中某条指纹时，用它做
# 独立于镜像源的交叉校验；没命中就只用镜像站自己的 SHA256SUMS（同源，仅防传输损坏）。
# 需要可复现的旧镜像时才显式 --pin-image（此时指纹指向的目录若已清理，直接失败，不静默降级）。
use_pinned_image=0
print_image_pins=0
# Legacy BIOS + GPT 缺 BIOS Boot 分区时，grub-install 只能 --force 硬塞。
# 那会写到 GPT 保护扇区附近、有破坏分区表的可能，所以默认直接拒绝，
# 必须显式加 --force-embed 才进入该模式（--yes 不能代替这个决定）。
force_embed_optin=0
# 由 preflight_image 设置：/boot 是独立分区且被保留（EFI 场景）时为 1，
# 此时它会被写进新 fstab，且不参与「必须与 / 同设备」的检查
boot_separate=0
# 内核类型。auto（默认）= 按抹盘前探测到的根磁盘驱动自动选：
#   根盘走 virtio → 用 cloud 精简内核；其余（ahci/nvme/megaraid/…）→ 用通用内核。
# 原因：Debian 的 linux-image-cloud-amd64 里没有 ahci.ko / nvme.ko，
# 装到 SATA/NVMe/vSphere 机器上开机会找不到根设备、掉进 initramfs 救援 shell。
# generic / cloud 可手工覆盖 auto 的判断。
kernel_flavor="auto"

# 所有 curl 调用统一使用：强制 HTTPS、禁止重定向降级到 HTTP、最低 TLS 1.2
CURL_TLS_OPTS=(--proto '=https' --proto-redir '=https' --tlsv1.2)

# SSH 策略默认值。装上可用公钥后会被收紧为 no / prohibit-password
sshd_policy_password_auth="yes"
sshd_policy_permit_root="yes"

err() {
	echo "错误：$1" >&2
	exit 1
}

ask_confirm() {
	local prompt="$1"
	local answer=""

	[ "$assume_yes" -eq 1 ] && return 0
	if [ ! -t 0 ]; then
		err "非交互环境执行危险操作需要显式加 --yes：$prompt"
	fi
	read -r -p "$prompt [y/N]: " answer
	case "$answer" in
	[yY][eE][sS] | [yY]) return 0 ;;
	*) return 1 ;;
	esac
}

usage() {
	cat <<EOF
用法: $0 [选项]
选项:
  --authorized-keys-url URL  设置 SSH 公钥 URL (仅支持 https)
  --password PASS           设置 root 密码（会出现在进程表中，建议改用 --password-file）
  --password-file FILE      从文件读取 root 密码（首行）
  --password-stdin          从标准输入读取 root 密码
  --ssh-port PORT           设置 SSH 端口 (1-65535)
  --hostname NAME           设置主机名
  --apt-mirror URL          设置 APT 镜像 URL
  --region {cn|global}      设置区域
  --image-version NAME      直接指定发行代号（如 bookworm、trixie、noble），跳过交互选择
  --timezone ZONE           设置时区
  --expect-image-sha256 HEX 固定 rootfs.tar.xz 的 SHA256，不匹配则中止
  --busybox-sha256 HEX      固定 BusyBox 动态二进制的 SHA256，不匹配则中止
  --busybox-ref REF         构建产物所在 ref。默认已固定到某次构建的 40 位 commit SHA；
                            传分支名（main）或 tag 会使来源可变并在运行时告警
  --allow-size-only         允许在拿不到 SHA256SUMS 时仅用文件大小校验（默认拒绝）
  --use-latest-image        兼容旧参数：等价于默认行为（取镜像站最新 timestamp）
  --pin-image               改用脚本内置指纹表中的 timestamp（可复现的旧镜像）。
                            该 timestamp 被镜像站清理时会直接失败，不会静默回落最新
  --force-embed             允许 Legacy BIOS + GPT 且没有 BIOS Boot 分区时用
                            grub-install --force 硬嵌入引导代码。会写入 GPT 保护
                            扇区附近、可能破坏分区表，默认拒绝该模式
  --print-image-pins        打印内置镜像指纹表后退出，便于维护
  --resume-partial          上次在抹盘阶段中断（存在 /os/WIPE_STARTED）时继续运行。
                            默认拒绝，因为此时系统可能已半新半旧
  环境变量 ALLOW_DIRTY_WIPE=1
                            抹盘后 /etc /usr /root 等安全敏感位置仍有残留时强制继续。
                            默认中止：这些位置的旧文件会把持久化带进新系统
  --dry-run                 只做检测/下载/预检并打印将要执行的动作，然后退出。
                            不会抹盘，也不进入任何破坏性步骤
  --no-offline-stage        不预下载新系统必需软件包（内核/initramfs-tools/DHCP
                            客户端）。默认会预下载到 /os/offline-debs，抹盘后网络
                            异常时可用它 dpkg -i 救回可引导状态
  --with-tcpx               额外下载 tcpx.sh 到 /root（默认不下载）
  --kernel {auto|generic|cloud}
                            内核类型。auto（默认）= 按检测到的根磁盘驱动自动选：根盘
                            走 virtio 用 cloud 精简内核，否则用通用内核。generic = 强制
                            通用内核（含 ahci/nvme/virtio 全量驱动）；cloud = 强制精简
                            内核（Debian cloud 内核不含 ahci.ko/nvme.ko，只适合纯 virtio）
  --yes, -y                 跳过销毁确认与交互式确认
  --help                    显示此帮助信息

环境变量:
  REINSTALL_PASSWORD        等价于 --password，但不进入命令行
EOF
	exit 0
}

need_value() {
	# $1=选项名，$2=剩余参数个数。缺值时直接报错，避免 shift 2 原地打转的死循环。
	[ "$2" -ge 2 ] || err "选项 '$1' 缺少参数值"
}

require_sha256() {
	[[ "$2" =~ ^[0-9a-fA-F]{64}$ ]] || err "无效的 SHA256 '$2'，必须为 64 位十六进制"
}

if [ -n "${REINSTALL_PASSWORD:-}" ]; then
	password="$REINSTALL_PASSWORD"
fi

while [ $# -gt 0 ]; do
	case "$1" in
	--authorized-keys-url)
		need_value "$1" $#
		[[ "$2" =~ ^https://[^[:space:]]+$ ]] || err "SSH 公钥 URL 必须是 https 地址：'$2'"
		authorized_keys_url="$2"
		shift 2
		;;
	--password)
		need_value "$1" $#
		password="$2"
		echo "警告：--password 会把口令暴露在进程表中，建议改用 --password-file 或 REINSTALL_PASSWORD" >&2
		shift 2
		;;
	--password-file)
		need_value "$1" $#
		password_file="$2"
		shift 2
		;;
	--password-stdin)
		password_stdin=1
		shift
		;;
	--ssh-port)
		need_value "$1" $#
		if ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
			err "无效的 SSH 端口 '$2'，必须为 1-65535 之间的整数"
		fi
		ssh_port="$2"
		shift 2
		;;
	--hostname)
		need_value "$1" $#
		[[ "$2" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || err "无效的主机名 '$2'"
		hostname="$2"
		shift 2
		;;
	--apt-mirror)
		need_value "$1" $#
		[[ "$2" =~ ^https?://[^[:space:]]+$ ]] || err "APT 镜像 URL 无效：'$2'"
		# 明文 http 镜像上的 Release/Packages 可被链路上任何人改写，apt 校验签名前
		# 就已按它建好 sources.list；这里不硬拒（内网镜像常见），但必须显著告警。
		case "$2" in
		http://*) echo "警告：APT 镜像 '$2' 使用明文 http，链路上的任何人都能替换软件包索引" >&2 ;;
		esac
		apt_mirror_url="$2"
		shift 2
		;;
	--image-version)
		need_value "$1" $#
		# 只接受小写字母数字的发行代号（bookworm/trixie/noble…），
		# 之后还会在 get_versions 里对照受支持列表校验，避免把任意字符串
		# 拼进下载 URL。
		if ! [[ "$2" =~ ^[a-z][a-z0-9]{1,15}$ ]]; then
			err "无效的发行代号 '$2'（示例：bookworm、trixie、noble）"
		fi
		image_version="$2"
		shift 2
		;;
	--region)
		need_value "$1" $#
		if [[ "$2" != "cn" && "$2" != "global" ]]; then
			err "无效的区域 '$2'，请使用 'cn' 或 'global'"
		fi
		region="$2"
		shift 2
		;;
	--timezone)
		need_value "$1" $#
		# 字符集放行 '.'：'..' 这样的段会让 /etc/localtime 指到 zoneinfo 之外
		[[ "$2" =~ ^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$ ]] || err "无效的时区 '$2'"
		case "/$2/" in
		*/../*) err "无效的时区 '$2'：不允许出现 '..' 路径段" ;;
		esac
		timezone="$2"
		shift 2
		;;
	--expect-image-sha256)
		need_value "$1" $#
		require_sha256 "$1" "$2"
		expected_image_sha256="$2"
		shift 2
		;;
	--busybox-sha256)
		need_value "$1" $#
		require_sha256 "$1" "$2"
		busybox_sha256="$2"
		shift 2
		;;
	--busybox-ref)
		need_value "$1" $#
		# 只允许 ref 字符集，防止把 '/../' 之类拼进 URL
		[[ "$2" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ ]] || err "无效的 --busybox-ref '$2'"
		# 字符集放行了 '.' 和 '/'，还得单独挡路径段：'..' 能让拼出的 URL 改变层次，
		# 末尾 '/' 会让文件名拼成 '...//busybox-x86_64-linux-gnu'。
		case "$2" in
		*..*) err "无效的 --busybox-ref '$2'：不允许出现 '..'" ;;
		*/) err "无效的 --busybox-ref '$2'：不允许以 '/' 结尾" ;;
		esac
		busybox_ref="$2"
		busybox_ref_explicit=1
		shift 2
		;;
	--allow-size-only)
		allow_size_only=1
		shift
		;;
	--resume-partial)
		resume_partial=1
		shift
		;;
	--dry-run)
		dry_run=1
		shift
		;;
	--no-offline-stage)
		offline_stage=0
		shift
		;;
	--use-latest-image)
		# 旧参数：默认行为已经是"取最新"，保留以免已有调用方报未知选项
		use_pinned_image=0
		shift
		;;
	--pin-image)
		use_pinned_image=1
		shift
		;;
	--force-embed)
		force_embed_optin=1
		shift
		;;
	--print-image-pins)
		print_image_pins=1
		shift
		;;
	--with-tcpx)
		download_tcpx=1
		shift
		;;
	--kernel)
		need_value "$1" $#
		case "$2" in
		auto | generic | cloud) kernel_flavor="$2" ;;
		*) err "无效的 --kernel '$2'：只能是 auto / generic / cloud" ;;
		esac
		shift 2
		;;
	--no-tcpx)
		download_tcpx=0
		shift
		;;
	--yes | -y)
		assume_yes=1
		shift
		;;
	--help)
		usage
		;;
	*)
		err "未知选项：'$1'"
		;;
	esac
done

# 注意：这里曾经在参数解析之后、require_root 之前无条件执行
# `[ ! -f /usr/bin/bash ] && ln -s ...`，导致 --print-image-pins 这种只读查询也会写
# /usr/bin（非 root 时静默失败，root 时产生意外副作用）。改到 main() 里 require_root 之后。
ensure_usr_bin_bash() {
	[ -e /usr/bin/bash ] && return 0
	local target
	target="$(command -v bash)" || return 0
	[ -n "$target" ] && ln -sf "$target" /usr/bin/bash 2>/dev/null
	return 0
}

require_root() {
	[ "$(id -u)" -eq 0 ] || err "必须以 root 身份运行本脚本"
	[ -d /proc/1 ] || err "未检测到可用的 /proc，无法继续"
}

cleanup_work_dir() {
	# 抹盘后 /bin/rm 已经不存在，直接调用会刷 "No such file or directory"。
	# 那时 work_dir 在 /tmp（tmpfs），重启即消失，不必强删。
	if [ "${wipe_phase:-0}" -eq 1 ]; then
		work_dir=""
		return 0
	fi
	if [ -n "${busybox_path:-}" ] && [ -x "$busybox_path" ]; then
		[ -n "$work_dir" ] && [ -d "$work_dir" ] && "$busybox_path" rm -rf "$work_dir" 2>/dev/null
	elif [ -n "$work_dir" ] && [ -d "$work_dir" ] && command -v rm >/dev/null 2>&1; then
		rm -rf "$work_dir"
	fi
	work_dir=""
}

init_work_dir() {
	# 所有中间文件都放私有临时目录，避免固定路径被同机用户预置符号链接
	work_dir="$(mktemp -d)" || err "无法创建临时目录"
	chmod 700 "$work_dir"
	trap 'cleanup_work_dir' EXIT
}

install_tool() {
	local tool="$1"
	if command -v "$tool" >/dev/null 2>&1; then
		echo "$tool 已安装，继续执行"
		return 0
	fi

	echo "正在安装 $tool..."
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "$tool"
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y "$tool"
	elif command -v yum >/dev/null 2>&1; then
		yum install -y "$tool"
	elif command -v apk >/dev/null 2>&1; then
		apk add "$tool"
	else
		err "未知的包管理器，请手动安装 $tool"
	fi || err "安装 $tool 失败"
}

require_tools() {
	install_tool curl
	install_tool wget
	install_tool tar
	# fdisk / findmnt 缺失时先尝试自动装（Debian 上分别是 fdisk 与 util-linux，
	# 包名与命令名一致），装不上再交给下面的硬校验报错。
	command -v fdisk >/dev/null 2>&1 || install_tool fdisk
	# findmnt 属于 util-linux，包名与命令名不同，不能直接 install_tool findmnt
	command -v findmnt >/dev/null 2>&1 || install_tool util-linux

	# 脚本在抹盘前/后实际依赖但从不安装、也不检查的工具。缺一个就会在删盘之后
	# 才炸（例如 sha256sum 缺失 = 校验分支直接跳过），所以这里提前硬校验。
	# fdisk：分区表类型与 "BIOS boot" 探测（fdisk 缺失时 label_type 为空，
	# 会退化成让用户手选引导模式，属于抹盘前的误导性交互）。
	# findmnt：独立挂载点检测、根设备/UUID 采集，抹盘阶段全靠它。
	local required=(sha256sum od awk sed grep find mktemp df stat lsblk ip fdisk findmnt)
	local missing=()
	local t
	for t in "${required[@]}"; do
		command -v "$t" >/dev/null 2>&1 || missing+=("$t")
	done
	# grep -P（版本列表解析、归档成员检查）不是所有实现都有。
	# 必须给一段能真正匹配的输入：空模式配空输入时 grep 退出 1（无匹配），
	# 会被误判成"不支持 -P"。
	printf 'a1\n' | grep -qP 'a\d' 2>/dev/null || missing+=("grep -P")
	if [ "${#missing[@]}" -gt 0 ]; then
		err "缺少必需命令：${missing[*]}（请先手动安装后再运行）"
	fi
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

	busybox_base_url="https://raw.githubusercontent.com/ylx2016/busybox-static-binaries-fat/${busybox_ref}"
	cn_busybox_base_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/busybox-static-binaries-fat/${busybox_ref}"
	busybox_url="${busybox_base_url}/${busybox_filename}"
	cn_busybox_url="${cn_busybox_base_url}/${busybox_filename}"
}

choose_system() {
	echo "请选择要安装的系统："
	echo "1. Debian"
	echo "2. Ubuntu"

	while true; do
		# read 在 EOF（非交互 stdin）时返回非零且不改变 choice；不处理就会死循环
		if ! read -r -p "请输入数字 (1 或 2)： " choice; then
			err "读取标准输入失败（stdin 已结束），请交互运行或检查调用方式"
		fi
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
	local versions_file="${work_dir}/versions.html"
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
			["resolute"]="Ubuntu 26.04 (Resolute Raccoon)"
		)
	fi

	echo "正在获取支持的 $system 版本..."
	# region=cn 时先打清华镜像，主站可能根本连不通
	local ver_url="$base_url"
	local ver_fallback=""
	if [ "$region" = "cn" ]; then
		ver_url="$cn_base_url"
		ver_fallback="$base_url"
	fi
	if ! curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 60 "$ver_url" -o "$versions_file" || [ ! -s "$versions_file" ]; then
		if [ -n "$ver_fallback" ]; then
			echo "警告：$ver_url 获取失败，尝试 $ver_fallback"
			curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 60 "$ver_fallback" -o "$versions_file" ||
				err "无法获取版本列表：$ver_url"
		else
			err "无法获取版本列表：$ver_url"
		fi
	fi

	mapfile -t all_versions < <(grep -oP '[a-z]+(?=/)' "$versions_file" | sort -u)
	versions=()

	for version in "${all_versions[@]}"; do
		[ -n "${version_map[$version]}" ] && versions+=("$version")
	done

	[ "${#versions[@]}" -eq 0 ] && err "未检测到支持的 $system 版本"

	# 非交互指定：必须在受支持列表里，否则直接失败（避免拿错代号装上不去）。
	if [ -n "$image_version" ]; then
		local supported=0 v
		for v in "${versions[@]}"; do
			[ "$v" = "$image_version" ] && supported=1
		done
		if [ "$supported" -ne 1 ]; then
			err "不支持的发行代号 '$image_version'（可用：${versions[*]}）"
		fi
		selected_version="$image_version"
		echo "已按 --image-version 选择版本：$selected_version (${version_map[$selected_version]})"
		rm -f "$versions_file"
		return 0
	fi

	echo "支持的 $system 版本："
	for i in "${!versions[@]}"; do
		echo "$((i + 1)). ${versions[$i]} (${version_map[${versions[$i]}]})"
	done

	while true; do
		if ! read -r -p "请选择要安装的版本（输入数字 1-${#versions[@]}）： " choice; then
			err "读取标准输入失败（stdin 已结束），请交互运行或检查调用方式"
		fi
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

# 头部开了 set -o pipefail，`producer | grep -q PAT` 这种写法是陷阱：
# grep -q 一命中就退出，producer 继续往已关闭的管道写会吃 SIGPIPE（退出码 141），
# pipefail 于是把"命中"判成失败。lsinitramfs 输出 70KB 时必现，
# 结论是「initramfs 里没有根磁盘驱动」—— 一个完全错误的致命判断。
# 统一走这个 helper：先把输出完整收进来，再在内存里匹配。
pipe_grep_q() {
	local pattern="$1"
	shift
	local out=""
	out="$("$@" 2>/dev/null)" || return 1
	grep -qE -- "$pattern" <<<"$out"
}

# 同上，但忽略大小写（efibootmgr 的 Label 大小写不固定）
pipe_grep_qi() {
	local pattern="$1"
	shift
	local out=""
	out="$("$@" 2>/dev/null)" || return 1
	grep -qiE -- "$pattern" <<<"$out"
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
	# 用「接口上有没有 IPv4 地址 + 有没有默认路由」判断，不用 ICMP。
	# ping 8.8.8.8 在大量机房/云安全组/容器网络里被直接丢弃，据此判定"没有 IPv4"
	# 会写出只有 IPv6 nameserver 的 resolv.conf，而机器根本没有全局 IPv6，
	# 于是新系统一条域名都解析不出来，apt-get update 全 Ign，装内核失败。
	local dns_content=""
	local has_v4_net=0
	local has_v6_net=0

	if pipe_grep_q '.' ip -4 route show default 2>/dev/null ||
		pipe_grep_q 'inet ' ip -4 addr show scope global 2>/dev/null; then
		has_v4_net=1
	fi
	if pipe_grep_q 'inet6 ' ip -6 addr show scope global 2>/dev/null ||
		pipe_grep_q '.' ip -6 route show default 2>/dev/null; then
		has_v6_net=1
	fi

	if [ "$has_v4_net" -eq 0 ] && [ "$has_v6_net" -eq 1 ]; then
		# 真的只有 IPv6，才写纯 IPv6 解析器
		dns_content="nameserver 2001:4860:4860::8888
nameserver 2001:67c:2b0::4"
	elif [ "$is_cn" -eq 1 ]; then
		dns_content="nameserver 114.114.114.114
nameserver 223.5.5.5"
		if [ "$has_v6_net" -eq 1 ]; then
			dns_content="$dns_content
nameserver 2001:4860:4860::8888"
		fi
	else
		dns_content="nameserver 1.1.1.1
nameserver 8.8.8.8"
		if [ "$has_v6_net" -eq 1 ]; then
			dns_content="$dns_content
nameserver 2001:4860:4860::8888
nameserver 2001:67c:2b0::4"
		fi
	fi

	printf '%s\n' "$dns_content"
}

# 真的去解析一个域名，而不是"文件里有 nameserver 就算成功"。
# 新系统里 getent 由 libc-bin 提供；busybox 的 nslookup 走同一份 resolv.conf。
dns_probe() {
	local host="${1:-deb.debian.org}"
	if command -v getent >/dev/null 2>&1; then
		getent hosts "$host" >/dev/null 2>&1 && return 0
	fi
	if [ -n "${busybox_path:-}" ] && [ -x "${busybox_path:-}" ]; then
		"$busybox_path" nslookup "$host" >/dev/null 2>&1 && return 0
	fi
	command -v nslookup >/dev/null 2>&1 && nslookup "$host" >/dev/null 2>&1 && return 0
	return 1
}

# 抹盘后如果主板 RTC 不准（VPS 常见：时区被当成本地时间、或长期离线跑偏），
# 新系统里还没有任何时间同步服务，apt 会直接拒绝整个索引：
#   E: Release file for ... is not valid yet (invalid for another 7h ...)
# 这不是网络问题，装不上下文就装出一台没内核的机器。用镜像站响应头里的 Date
# 校正系统时间（偏差 >5 分钟才动），不改时区。
# 用任意 URL 的响应头 Date 校正系统时间；RTC 偏差过大时连 HTTPS 证书都验不过，
# 所以下载阶段之前就要先校正一次。
sync_clock_from_url() {
	local url="$1" hdr epoch now skew
	[ -n "$url" ] || return 0
	# 不用 head 截断：pipefail 下 head 提前退出会让整条管道带 SIGPIPE 状态
	if command -v curl >/dev/null 2>&1; then
		hdr="$(curl -sI --max-time 15 "${CURL_TLS_OPTS[@]}" "$url" 2>/dev/null |
			sed -n 's/^[Dd]ate:[[:space:]]*//p' | tr -d '\r')"
	elif command -v wget >/dev/null 2>&1; then
		hdr="$(wget -S --spider --timeout=15 "$url" 2>&1 |
			sed -n 's/^[[:space:]]*[Dd]ate:[[:space:]]*//p' | tr -d '\r')"
	fi
	hdr="${hdr%%$'\n'*}"
	[ -n "$hdr" ] || return 0
	# 旧系统可能是 Alpine（busybox date 不认 -d "RFC1123" 的默认格式），两路都试
	epoch="$(date -d "$hdr" +%s 2>/dev/null)"
	case "$epoch" in
	'' | *[!0-9]*)
		command -v busybox >/dev/null 2>&1 &&
			epoch="$(busybox date -D '%a, %d %b %Y %H:%M:%S %Z' -d "$hdr" +%s 2>/dev/null)"
		;;
	esac
	case "$epoch" in '' | *[!0-9]*) return 0 ;; esac
	now="$(date +%s)"
	skew=$((epoch - now))
	[ "${skew#-}" -lt 300 ] && return 0
	echo "警告：系统时间与镜像服务器相差 $((skew / 60)) 分钟（$(date -u '+%FT%TZ') → $(date -u -d "@$epoch" '+%FT%TZ')），按镜像时间校正"
	if date -u -s "@$epoch" >/dev/null 2>&1; then
		echo "系统时间已校正"
	elif command -v busybox >/dev/null 2>&1 && busybox date -u -s "@$epoch" >/dev/null 2>&1; then
		echo "系统时间已校正（busybox）"
	else
		echo "警告：无法校正系统时间，apt 可能因 Release 文件来自未来而失败"
	fi
	return 0
}

# 按 APT 镜像的 Release 文件校时（此时已知系统版本）
sync_clock_from_mirror() {
	local mirror="$1"
	[ -n "$mirror" ] || return 0
	sync_clock_from_url "$mirror/dists/$selected_version/Release"
}

apply_dns_config() {
	local target_file="$1"

	rm -f "$target_file"
	touch "$target_file"

	# 备份只是"存在"不够：空文件、只有 systemd-resolved 的 127.0.0.53 桩、
	# 写入失败的残留都会让新系统解析全死，而 init_os 里紧接着就是 apt-get update，
	# 失败会直接中止在 install_grub 之前 —— 盘已抹、无引导。
	local bak_ok=0
	if [ -f "${root_dir}/resolv.conf.bak" ]; then
		if grep -qE '^[[:space:]]*nameserver[[:space:]]+[0-9a-fA-F:.]' "${root_dir}/resolv.conf.bak" &&
			! grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.53([[:space:]]|$)' "${root_dir}/resolv.conf.bak"; then
			bak_ok=1
		else
			echo "警告：原 DNS 备份为空或只有 127.0.0.53 桩，改用脚本推荐的 DNS" >&2
		fi
	fi

	if [ "$use_local_dns" -eq 1 ] && [ "$bak_ok" -eq 1 ]; then
		echo "使用用户选择的本地原 DNS 配置..."
		cat "${root_dir}/resolv.conf.bak" >"$target_file"
		cp "${root_dir}/resolv.conf.bak" "${target_file}.bak"
	else
		echo "使用脚本自动推荐的 DNS 配置..."
		get_recommended_dns >"$target_file"
	fi

	# 写完必须复核：目标不可替换（只读挂载、属主异常）时前面的重定向会失败，
	# 但函数照样返回 0，于是带着空 resolv.conf 继续 apt-get update
	if ! grep -qE '^[[:space:]]*nameserver[[:space:]]' "$target_file" 2>/dev/null; then
		err "写入 $target_file 失败或内容为空，拒绝在无 DNS 的状态下继续"
	fi

	echo "当前 $target_file 内容："
	cat "$target_file"

	# 内容合法 ≠ 能解析。DNS 配错时 apt-get update 只会打印一串 Ign，
	# 真正报错发生在 install_base_packages，此时盘已经抹了。
	# 先探测一次，失败就换公共 IPv4 解析器再探，仍失败只警告不中止
	# （此时中止只会把机器留在"已抹空、无引导"状态，让 apt 自己报错更有信息量）。
	if ! dns_probe; then
		echo "警告：当前 DNS 无法解析域名，尝试回退到公共 IPv4 解析器"
		printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' >"$target_file"
		if dns_probe; then
			echo "已回退到 1.1.1.1 / 8.8.8.8，域名解析正常"
		else
			echo "警告：回退后仍无法解析域名，后续 apt 操作可能失败（请检查网络/防火墙）"
		fi
	fi
}

# curl 的 --max-filesize 只在服务端给了 Content-Length 时生效；chunked 响应
# 可以完全绕过它，在天花乱坠的"正常传输"里把 / 写满（此时旧系统还在跑、
# 校验还没做）。所以再按"实际落盘字节数"卡一道：管道交给 head -c，超出部分
# 根本不会写进文件。
curl_download_capped() {
	local url="$1"
	local out="$2"
	local max_bytes="$3"
	local timeout="$4"
	local st=0
	local got=0

	# 先落到同目录的临时文件，成功后再 mv 覆盖：
	#  1) 直接 `: >"$out"` 会在下载失败时把已经存在的好文件（例如上一次运行留下的
	#     busybox）截成 0 字节；
	#  2) 目标文件若正被某个进程执行，open(O_TRUNC) 会返回 ETXTBSY（"Text file busy"），
	#     下载必然失败；rename 只是换目录项，不受执行状态影响。
	# --speed-limit/--speed-time：连接建立后源站"半死不活"（TCP 不断、速率趋零）
	# 时 --max-time 3600 等于无限等。实测 raw.githubusercontent.com 会在传了一半后
	# 彻底停住，脚本永远卡在下载里，连 ghproxy 回退都轮不到。低于 1KB/s 持续 60s
	# 即判本次尝试失败，让 download_with_retry 正常重试或走备用地址。
	local tmp_out="${out}.part.$$"
	rm -f "$tmp_out"
	curl "${CURL_TLS_OPTS[@]}" -SLf --retry 2 --connect-timeout "$timeout" \
		--max-time 3600 --speed-limit 1024 --speed-time 60 \
		--max-filesize "$max_bytes" -o - "$url" 2>/dev/null |
		head -c "$max_bytes" >"$tmp_out" || st=1
	got="$(stat -c%s "$tmp_out" 2>/dev/null || echo 0)"
	if [ "$got" -ge "$max_bytes" ]; then
		rm -f "$tmp_out"
		err "下载内容达到体积上限 $max_bytes 字节（源站未声明长度或文件异常巨大），拒绝继续：$url"
	fi
	if [ "$st" -eq 0 ] && [ "$got" -gt 0 ]; then
		mv -f "$tmp_out" "$out" || {
			rm -f "$tmp_out"
			return 1
		}
		return 0
	fi
	rm -f "$tmp_out"
	return 1
}

download_with_retry() {
	local primary_url="$1"
	local fallback_url="$2"
	local output_file="$3"
	local attempts="${4:-3}"
	local timeout="${5:-10}"
	# 体积上限：不设的话，一个恶意/被篡改的镜像可以把 / 写满 —— 而这时旧系统
	# 还在运行、校验还没做（写入位置就在根分区上）。4GiB 对 rootfs.tar.xz 足够。
	local max_bytes="${6:-4294967296}"

	local ok=0
	local current_url="$primary_url"

	for ((i = 1; i <= attempts; i++)); do
		echo "尝试下载（第 $i/$attempts 次）：$current_url"
		if curl_download_capped "$current_url" "$output_file" "$max_bytes" "$timeout"; then
			ok=1
			break
		fi
		sleep 5
	done

	if [ "$ok" -ne 1 ] && [ -n "$fallback_url" ] && [ "$fallback_url" != "$primary_url" ]; then
		current_url="$fallback_url"
		for ((i = 1; i <= attempts; i++)); do
			echo "尝试备用地址下载（第 $i/$attempts 次）：$current_url"
			if curl_download_capped "$current_url" "$output_file" "$max_bytes" "$timeout"; then
				ok=1
				break
			fi
			sleep 5
		done
	fi

	[ "$ok" -ne 1 ] && err "下载失败：$primary_url"
	[ -s "$output_file" ] || err "下载内容为空：$output_file"
}

download_text_with_fallback() {
	local primary_url="$1"
	local fallback_url="$2"
	local output_file="$3"

	# 文本清单（SHA256SUMS/versions.html）同样要限时限量：无上限的写盘等于把
	# "还没校验就能写满 /"这条路留给对方。
	if curl "${CURL_TLS_OPTS[@]}" -fsSL --connect-timeout 10 --max-time 120 \
		--max-filesize 10485760 "$primary_url" -o "$output_file" && [ -s "$output_file" ]; then
		return 0
	fi

	if [ -n "$fallback_url" ] && [ "$fallback_url" != "$primary_url" ] &&
		curl "${CURL_TLS_OPTS[@]}" -fsSL --connect-timeout 10 --max-time 120 \
			--max-filesize 10485760 "$fallback_url" -o "$output_file" && [ -s "$output_file" ]; then
		return 0
	fi

	return 1
}

get_remote_size() {
	local url="$1"
	curl "${CURL_TLS_OPTS[@]}" -sIL "$url" 2>/dev/null |
		awk 'BEGIN{IGNORECASE=1} /^Content-Length:/ {gsub("\r","",$2); print $2; exit}' |
		grep -E '^[0-9]+$' || true
}

verify_size_if_needed() {
	local file="$1"
	local remote_size="$2"

	# 返回 1 表示"无法校验"，由调用方决定是否 fail-closed
	if [ -z "$remote_size" ] || [ "$remote_size" = "0" ]; then
		return 1
	fi

	local local_size
	local_size=$(stat -c%s "$file" 2>/dev/null || wc -c <"$file")
	[ -n "$local_size" ] || return 1

	if [ "$local_size" -eq "$remote_size" ]; then
		echo "文件大小匹配：$local_size 字节"
		return 0
	fi

	err "文件大小不匹配，本地大小: $local_size，远程大小: $remote_size"
}

is_immutable_ref() {
	# 只有 40 位十六进制 commit SHA 才是不可变指针。
	# 分支名（main）和 tag 都能被 force push 改写，不能拿来做完整性锚点。
	# 大小写都认：git 输出的 SHA 可能被用户复制成大写，判成可变会静默放宽校验。
	[[ "$1" =~ ^[0-9a-fA-F]{40}$ ]]
}

# BusyBox 二进制指纹表：arch|sha256
#
# 为什么需要：SHA256SUMS 由同一次构建产出、与二进制放在同一仓库同一 ref 下，
# 仓库（或代理）被控时两者会被一起改写，校验等于自证。把确认过的哈希固化进脚本，
# 就有了独立于分发渠道的第二个锚点。
# 更新方式：上游重新构建后，本地下载二进制、sha256sum，再与仓库 SHA256SUMS 比对，
# 一致才替换此处（两处都改 = 没有独立锚点，必须本地算）。
busybox_pin_table() {
	cat <<'EOF'
# 格式：arch|busybox 文件名|sha256
# 对应 ref：3a7b23ad5a5ed498f6e22f94578f6067e78be668
x86_64|busybox-x86_64-linux-gnu|8a2920638205b35041fc1cf67b965e432b3ae12d13189cc7d331567689d21347
aarch64|busybox-aarch64-linux-gnu|11166e3dd148f330f21c44c929b1eef17e342c841fa46067cb0efb3bc453daf1
EOF
}

lookup_busybox_pin() {
	busybox_pin_table | awk -F'|' -v a="$arch" -v f="$busybox_filename" '
		/^[[:space:]]*#/ { next }
		NF < 3 { next }
		$1 == a && $2 == f { print $3 }
	' | head -1
}

resolve_busybox_sha256_from_sums() {
	# 构建流程会把 sha256sum busybox-* 的输出提交成同目录的 SHA256SUMS。
	# ref 一旦固定成 commit SHA，该文件路径和内容都不可变，可据此 fail-closed。
	local sums_file="${work_dir}/busybox.SHA256SUMS"
	local sums_url="${busybox_base_url}/SHA256SUMS"
	local sums_fallback="${cn_busybox_base_url}/SHA256SUMS"
	local got=""

	# 独立锚点优先：脚本内置指纹（不在分发渠道内）。
	# 指纹绑定的是 BUSYBOX_DEFAULT_REF 这一次构建，ref 被改走时不能套用。
	if [ "$busybox_ref" = "$BUSYBOX_DEFAULT_REF" ]; then
		got="$(lookup_busybox_pin)"
		if [ -n "$got" ]; then
			busybox_sha256="$got"
			echo "BusyBox 指纹：使用脚本内置哈希（独立于下载渠道）"
			return 0
		fi
	fi

	if [ "$region" = "cn" ]; then
		sums_url="${cn_busybox_base_url}/SHA256SUMS"
		sums_fallback="${busybox_base_url}/SHA256SUMS"
	fi

	if curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 30 "$sums_url" -o "$sums_file" 2>/dev/null ||
		curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 30 "$sums_fallback" -o "$sums_file" 2>/dev/null; then
		got="$(awk -v f="$busybox_filename" '
			{ sub(/\r$/, "", $2) }
			$1 ~ /^[0-9a-fA-F]{64}$/ && ($2 == f || $2 == "*" f) { print $1; exit }
		' "$sums_file")"
		if [ -n "$got" ]; then
			busybox_sha256="$got"
			echo "已从 SHA256SUMS 取得 $busybox_filename 的期望哈希：$busybox_sha256"
			echo "警告：该清单与二进制同源（同一仓库/同一代理），只能防传输损坏" >&2
			return 0
		fi
		echo "警告：SHA256SUMS 中没有 $busybox_filename 的合法条目"
	fi

	# 固定在 commit 上却取不到清单：说明清单被删或路径变了，无从判断二进制真伪，拒绝。
	# 用分支名/tag 时保留旧行为（告警后继续），因为这类指针本就可变，不能假装有保证。
	if is_immutable_ref "$busybox_ref"; then
		err "已固定在 commit ${busybox_ref}，却取不到对应的 SHA256SUMS，拒绝在零校验状态下执行 BusyBox"
	fi
	return 0
}

verify_busybox_binary() {
	local remote_size="$1"
	local actual_hash=""
	local magic=""
	local machine=""

	[ -s "$busybox_path" ] || err "BusyBox 下载内容为空：$busybox_path"

	# ELF 魔数：拒绝把 HTML 错误页/空文件当成二进制去执行
	magic="$(head -c 4 "$busybox_path" | od -An -tx1 | tr -d ' \n')"
	[ "$magic" = "7f454c46" ] || err "BusyBox 不是 ELF 可执行文件（魔数: $magic）"

	# e_machine（ELF 头偏移 18，小端 16 位）校验架构，防止拿错架构的二进制
	machine="$(od -An -tu2 -j18 -N2 "$busybox_path" | tr -d ' \n')"
	case "$arch" in
	x86_64) [ "$machine" = "62" ] || err "BusyBox 架构不匹配（e_machine=$machine，期望 x86_64=62）" ;;
	aarch64) [ "$machine" = "183" ] || err "BusyBox 架构不匹配（e_machine=$machine，期望 aarch64=183）" ;;
	esac

	# 没有显式 --busybox-sha256 时，尝试用仓库里随构建产物一起提交的 SHA256SUMS
	[ -z "$busybox_sha256" ] && resolve_busybox_sha256_from_sums

	actual_hash="$(sha256sum "$busybox_path" | awk '{print $1}')"

	if [ -n "$busybox_sha256" ]; then
		[ "${actual_hash,,}" = "${busybox_sha256,,}" ] || err "BusyBox SHA256 不匹配！期望: $busybox_sha256，实际: $actual_hash"
		echo "BusyBox SHA256 校验通过：$actual_hash"
	elif [ "$busybox_ref_explicit" -eq 1 ]; then
		# 只有操作者显式改了 ref 才允许零校验（他知道自己在做什么）
		echo "警告：未取得可核对的 BusyBox SHA256（当前文件哈希：$actual_hash）"
		echo "警告：--busybox-ref '$busybox_ref' 不是内置指纹覆盖的版本，二进制来源无法独立确认"
	else
		err "未取得可核对的 BusyBox SHA256（当前文件哈希：$actual_hash），拒绝以 root 执行未校验的二进制"
	fi

	if [ -n "$remote_size" ] && [ "$remote_size" != "0" ]; then
		verify_size_if_needed "$busybox_path" "$remote_size" || echo "警告：无法核对 BusyBox 远程大小"
	fi
}

# 已固化的镜像指纹表。每行：system|version|arch|timestamp|sha256
#
# 为什么需要：镜像站会同时提供 rootfs.tar.xz 和同目录的 SHA256SUMS，两者同源，
# 镜像站被控时会被一起改写，校验等于自证。把某次确认过的 timestamp + 哈希固化进
# 脚本，校验就有了独立于镜像源的第二个锚点；镜像站若回头改写同一 timestamp 目录
# 下的文件，哈希比对会直接失败。
#
# 追加条目：curl -fsSL "<镜像站>/<version>/<arch>/cloud/<timestamp>/SHA256SUMS"
# 取其 rootfs.tar.xz 那一行填进来即可。
# 修改既有条目的哈希必须查清原因 —— 正常镜像站不会改写已发布的 timestamp 目录。
image_pin_table() {
	cat <<'EOF'
# 格式：system|version|arch|timestamp|sha256（本行是注释，不会参与匹配）
#
# 以下条目取自 images.linuxcontainers.org，并于 2026-11-13 与清华镜像
# (mirrors.tuna.tsinghua.edu.cn/lxc-images) 的同名 SHA256SUMS 交叉核对一致。
# 脚本默认取最新 timestamp；本表只在"最新 timestamp 恰好等于某条记录"时提供
# 独立交叉校验，或用 --pin-image 显式锁定某个已记录的旧镜像时使用。
# 表是历史记录，不要求长期有效：条目指向的 timestamp 迟早会被镜像站清理，
# 那只是让该条失效，不影响默认取最新的行为。
debian|bookworm|amd64|20261112_05:24|89cfb4d6a1728a9d2af17a212f48e1944c63b6b381e63fba6353dce79d966cbf
debian|bookworm|arm64|20261112_05:24|0dba5aaf175c37d26fc1ea65f04e9fbb748708a5b659a0657b0ccc5f0ab22e92
debian|trixie|amd64|20261112_05:24|2edf3295e719391c323e23aa4e8979d85891edb00ec92fc03e7065559a302fb0
debian|trixie|arm64|20261112_05:24|dbe98a9bf948e5df9b068873a973f2997b1e563a19eef0991e84799efd215b8c
ubuntu|jammy|amd64|20261112_07:42|20af9d3409eb9b167e9e3d5e36ae7ac79df532929c92ca969d7d4048365346e9
ubuntu|jammy|arm64|20261112_07:42|ca5318d2e96837b7d270feb1a91caa554c4d9b46314a5832cd88cd1fc63c8bf8
ubuntu|noble|amd64|20261112_07:42|b2316508632159132a0cb8dc628230114bba6789621c28c21f38dce4bdd04dce
ubuntu|noble|arm64|20261112_07:42|e5d9cf0f2590bae349cd1eb3edcf035aaf88b98f569ce240256f74e080db7fca
EOF
}

# 查询某 system/version/arch 的内置指纹，输出 "<timestamp> <sha256>"，未命中输出空。
# 同一组合有多条时取 timestamp 最新的一条（timestamp 形如 YYYYMMDD_HHMM，字典序即时间序）。
lookup_image_pin() {
	local sys="$1"
	local ver="$2"
	local arch="$3"

	image_pin_table | awk -F'|' -v s="$sys" -v v="$ver" -v a="$arch" '
		/^[[:space:]]*#/ { next }
		NF < 5 { next }
		$1 == s && $2 == v && $3 == a { print $4 " " $5 }
	' | sort -r | head -1
}

download_image() {
	local file="rootfs.tar.xz"
	local os_filename="${root_dir}/os.tar.xz"
	local attempts=3
	local timeout=10
	# 列表页必须取自已选的镜像：region=cn 时打主站可能直接不通，
	# 而且两站的 timestamp 集合未必一致（取到列表却下不到文件）
	local list_base_url="$base_url"
	local list_fallback_url=""
	if [ "$region" = "cn" ]; then
		list_base_url="$cn_base_url"
		list_fallback_url="$base_url"
	fi
	local list_url="$list_base_url/$selected_version/$image_arch/cloud/?C=M;O=D"

	# 700：$root_dir 里放的是待解压的 rootfs.tar.xz，默认 755 会让同机其他用户
	# 在校验完成到解压之间把它换掉（umask 000/002 时更糟），
	# 且 $root_dir 本身不在 -xdev 排除名单之外——它必须不属于任何其他用户
	if [ -L "$root_dir" ]; then
		err "$root_dir 是符号链接，拒绝使用"
	fi
	# 记录 /os 是不是本次新建的：dry-run 退出时只能删自己的东西，
	# 不能把用户已有的 /os 目录一起删掉。
	if [ -d "$root_dir" ]; then
		root_dir_created=0
	else
		root_dir_created=1
	fi
	mkdir -p "$root_dir" || err "无法创建 $root_dir 目录"
	chmod 700 "$root_dir" || err "无法收紧 $root_dir 权限"
	[ -O "$root_dir" ] || err "$root_dir 不属于当前用户，拒绝使用"

	backup_dns

	local timestamp=""
	local pinned_checksum=""

	# 默认走"最新"：镜像站会轮转清理旧 timestamp，钉死某一天的目录过几天就是 404。
	# 只有显式 --pin-image 才用指纹里的 timestamp（需要可复现的特定旧镜像时）。
	if [ "$use_pinned_image" -eq 1 ]; then
		local pin=""
		pin="$(lookup_image_pin "$system" "$selected_version" "$image_arch")"
		if [ -z "$pin" ]; then
			err "内置指纹表里没有 $selected_version/$image_arch 的条目，--pin-image 无法使用。去掉 --pin-image 取最新镜像，或先用 --print-image-pins 查看已有条目"
		fi
		timestamp="${pin%% *}"
		pinned_checksum="${pin##* }"
		echo "使用脚本内置的镜像指纹（--pin-image）：$selected_version/$image_arch @ $timestamp"
	fi

	# 指纹里的 timestamp 可能已被镜像站清理（404）。这里探测一次，但必须区分
	# "确实被清理" 和 "网络不通"：把探测失败一律当成 404 会让任何能在链路上打断
	# 探测的人把独立锚点降级成镜像源自证。探测要打实际下载用的那台镜像。
	if [ -n "$pinned_checksum" ]; then
		local probe_urls=("$base_url/$selected_version/$image_arch/cloud/$timestamp/$file")
		if [ "$region" = "cn" ]; then
			probe_urls=("$cn_base_url/$selected_version/$image_arch/cloud/$timestamp/$file" "${probe_urls[@]}")
		fi
		local probe_code="" probe_url="" probe_state=""
		for probe_url in "${probe_urls[@]}"; do
			# 目录列表是 302 站点，必须 -L 才能看到真实的 200/404
			probe_code="$(curl "${CURL_TLS_OPTS[@]}" -sL -o /dev/null -w '%{http_code}' \
				--connect-timeout 10 --max-time 30 "$probe_url" 2>/dev/null)"
			case "$probe_code" in
			200) probe_state="ok"; break ;;
			404 | 410) probe_state="gone" ;;
			*)
				if [ -z "$probe_state" ]; then probe_state="unknown"; fi
				echo "警告：探测 $probe_url 返回 HTTP ${probe_code:-无响应}"
				;;
			esac
		done

		case "$probe_state" in
		ok) ;;
		gone)
			# 显式要求某个可复现镜像却已不存在：静默换成别的镜像等于换掉用户要装的东西，
			# 直接失败，让人自己决定是换 pin 还是取最新。
			err "内置指纹对应的镜像 $timestamp 已被镜像站清理（HTTP 404）。去掉 --pin-image 取最新镜像，或把指纹表更新到仍存在的 timestamp"
			;;
		*)
			err "无法确认内置指纹指向的镜像 $timestamp 是否仍存在（HTTP ${probe_code:-无响应}）：网络或镜像站异常。确认镜像站可用后重试"
			;;
		esac
	fi

	if [ -z "$timestamp" ]; then
		echo "正在获取可用镜像时间戳列表..."
		if ! curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 120 "$list_url" -o "${work_dir}/index.html" || [ ! -s "${work_dir}/index.html" ]; then
			if [ -n "$list_fallback_url" ]; then
				echo "警告：$list_base_url 列表获取失败，尝试 $list_fallback_url"
				curl "${CURL_TLS_OPTS[@]}" -fsSL --max-time 120 \
					"$list_fallback_url/$selected_version/$image_arch/cloud/?C=M;O=D" -o "${work_dir}/index.html" ||
					err "无法获取时间戳列表：$list_url"
			else
				err "无法获取时间戳列表：$list_url"
			fi
		fi

		mapfile -t timestamp_list < <(grep -oE '2[0-9]{7}_[0-9]{2}:[0-9]{2}' "${work_dir}/index.html" | sort -r)
		[ "${#timestamp_list[@]}" -eq 0 ] && err "未检测到任何可用时间戳目录"

		timestamp="${timestamp_list[0]}"
		echo "找到最新的镜像时间戳：$timestamp"

		# 最新 timestamp 若正好命中内置指纹，说明这一版曾经人工确认过：
		# 用它做独立于镜像源的锚点。镜像站若回头改写同一 timestamp 目录，
		# 下面的交叉校验会立刻失败 —— 既拿到新鲜镜像，又保留防篡改能力。
		local pin_hit=""
		pin_hit="$(image_pin_table | awk -F'|' -v s="$system" -v v="$selected_version" -v a="$image_arch" -v t="$timestamp" '
			/^[[:space:]]*#/ { next }
			NF < 5 { next }
			$1 == s && $2 == v && $3 == a && $4 == t { print $5; exit }
		')"
		if [ -n "$pin_hit" ]; then
			pinned_checksum="$pin_hit"
			echo "该 timestamp 命中脚本内置指纹：将用它交叉校验镜像站的 SHA256SUMS"
		elif [ -z "$expected_image_sha256" ]; then
			echo "提示：最新镜像尚无内置指纹（新镜像本来如此），校验锚点来自镜像站自身的 SHA256SUMS"
		fi
	fi

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
	local checksum_file="${work_dir}/SHA256SUMS"

	if download_text_with_fallback "$preferred_checksum_url" "$fallback_checksum_url" "$checksum_file"; then
		# 只接受严格的 "<64 位十六进制><空格>[* ]rootfs.tar.xz" 行
		expected_checksum="$(grep -E "^[0-9a-fA-F]{64} [ *]${file}\$" "$checksum_file" | awk '{print $1}' | head -1 | tr 'A-F' 'a-f')"
		[ -n "$expected_checksum" ] && checksum_available=1
	fi

	# 锚点优先级：--expect-image-sha256 > 内置指纹 > 镜像站 SHA256SUMS > 大小(需 --allow-size-only)
	# 命令行显式给出的哈希就是操作者的最终判断，不再拿内置指纹去否决它
	# （否则指纹过期时 --expect-image-sha256 这个补救手段本身会被挡住）。
	if [ -n "$expected_image_sha256" ]; then
		expected_checksum="${expected_image_sha256,,}"
		checksum_available=1
		echo "校验锚点：命令行固定的镜像 SHA256：$expected_checksum"
	elif [ -n "$pinned_checksum" ]; then
		# 内置指纹与镜像站清单交叉验证：两者都拿到却不一致，说明镜像被改写或指纹过期。
		# 这一步是整条链上唯一独立于镜像源的判断，不能省。
		if [ "$checksum_available" -eq 1 ] && [ "${expected_checksum,,}" != "${pinned_checksum,,}" ]; then
			err "内置指纹与镜像站 SHA256SUMS 不一致（内置 ${pinned_checksum}，镜像站 ${expected_checksum}）：镜像可能已被改写，或内置指纹已过期。确认后用 --expect-image-sha256 显式指定"
		fi
		expected_checksum="$pinned_checksum"
		checksum_available=1
		echo "校验锚点：脚本内置指纹（独立于镜像源）"
	elif [ "$checksum_available" -eq 1 ]; then
		echo "警告：校验锚点来自镜像站自身的 SHA256SUMS，与该镜像同源，无法防御镜像站被控"
	fi

	download_with_retry "$preferred_img_url" "$fallback_img_url" "$os_filename" "$attempts" "$timeout"

	if [ "$checksum_available" -eq 1 ]; then
		echo "验证镜像文件 SHA256 校验和..."
		local actual_checksum
		actual_checksum="$(sha256sum "$os_filename" | awk '{print $1}')"
		[ "$actual_checksum" = "$expected_checksum" ] || err "镜像文件 SHA256 校验和不匹配！期望值: $expected_checksum，实际值: $actual_checksum"
		echo "镜像文件 SHA256 校验和匹配，文件完整性验证通过"
		verified_image_sha256="$expected_checksum"
	elif [ "$allow_size_only" -eq 1 ]; then
		echo "警告：未获取到可用 SHA256，按 --allow-size-only 改用文件大小校验"
		verify_size_if_needed "$os_filename" "$remote_size" || err "文件大小也无法获取，拒绝在零校验状态下继续"
		echo "警告：大小校验只能发现传输截断，不能防止镜像被替换"
	else
		err "未获取到镜像 SHA256，拒绝在零校验状态下继续。修复镜像源，或确认风险后加 --allow-size-only"
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

	# BusyBox 是 wipe 之前唯一以 root 执行的第三方二进制，必须先验哈希/ELF 头
	verify_busybox_binary "$busybox_remote_size"

	chmod +x "$busybox_path" || err "无法为 $busybox_path 设置可执行权限"
	# busybox 不带参数会打印版本横幅并以 1 退出，这里只取第一行用于对账
	echo "BusyBox 版本：$("$busybox_path" 2>&1 | head -1)"
	"$busybox_path" --help >/dev/null 2>&1 || err "BusyBox 测试失败：$busybox_path"
}

preflight_image() {
	local archive_list="${work_dir}/archive.list"
	local mirror=""

	echo "预检：开始确认镜像归档与 APT 源可用（此步骤失败不会破坏现有系统）..."

	# 1) 归档能被完整解开，并且确实是一个可用系统
	"$busybox_path" xzcat "$root_dir/os.tar.xz" | "$busybox_path" tar -tf - >"$archive_list" || err "镜像归档损坏，无法读取，已中止（现有系统未改动）"
	[ -s "$archive_list" ] || err "镜像归档为空，已中止（现有系统未改动）"

	# 成员路径必须都是相对且不逃逸的：解压目标是 /，绝对路径成员会被写成新的
	# 绝对路径、".." 成员可能写到 root_dir 之外。这里用 grep -P 一次性拒绝
	if grep -qP '^/' "$archive_list"; then
		err "镜像归档含绝对路径成员（例如 $(grep -m1 -P '^/' "$archive_list")），已中止（现有系统未改动）"
	fi
	if grep -qP '(^|/)\.\.(/|$)' "$archive_list"; then
		err "镜像归档含 .. 路径成员（例如 $(grep -m1 -P '(^|/)\.\.(/|$)' "$archive_list")），已中止（现有系统未改动）"
	fi

	grep -qE '(^|/)etc/passwd$' "$archive_list" || err "镜像归档缺少 /etc/passwd，已中止（现有系统未改动）"
	grep -qE '(^|/)usr/bin/apt-get$' "$archive_list" || err "镜像归档缺少 apt-get，已中止（现有系统未改动）"
	echo "归档校验通过：$(wc -l <"$archive_list") 个条目"

	# 1a) 根分区若是 LUKS 加密，脚本无法为它生成 crypttab 与密钥（旧机密钥在旧系统里），
	#     抹盘后新系统开机根本解不开根分区。这类机器必须在抹盘前拒绝，
	#     而不是等重启后掉进 initramfs 救援 shell。
	local root_dev="" root_type=""
	root_dev="$(readlink -f "$(findmnt -no SOURCE / 2>/dev/null)" 2>/dev/null || true)"
	if [ -n "$root_dev" ] && command -v lsblk >/dev/null 2>&1; then
		root_type="$(lsblk -dno TYPE "$root_dev" 2>/dev/null | head -1)"
	fi
	if [ "$root_type" = "crypt" ]; then
		err "根文件系统在 LUKS 加密卷（$root_dev）上：脚本无法为加密根生成 crypttab 与密钥，抹盘后新系统将无法开机。已中止（现有系统未改动）"
	fi

	# 1c) Secure Boot：启用时固件只肯执行有签名的引导程序。脚本装的是未签名的
	#     grubx64.efi（没有 shim 与 MOK 注册），抹盘重启后固件直接拒绝启动，
	#     连内核都进不去。这种情况必须在抹盘前停下，让操作者在固件里关掉它。
	if [ -d /sys/firmware/efi ]; then
		local sb_var="" sb_on=0
		sb_var="$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | head -1)"
		if [ -n "$sb_var" ]; then
			# efivar 前 4 字节是属性，第 5 字节才是值：0x01 = 启用
			sb_on="$(od -An -tu1 -j4 -N1 "$sb_var" 2>/dev/null | tr -d ' ')"
			[ "$sb_on" = "1" ] || sb_on=0
		fi
		if [ "$sb_on" = "1" ]; then
			err "固件开启了 Secure Boot：脚本安装的是未签名的 GRUB（无 shim/MOK），抹盘重启后固件会拒绝引导。请在固件设置里关闭 Secure Boot（或改用你自己签名过的引导链）后重试。已中止（现有系统未改动）"
		fi
	fi

	# 1b) 独立 /boot 保留原布局。预检只记录，不卸载、不删除旧内核：
	#     否则用户取消或后续预检失败，旧系统也已经不可引导。
	#     清理移到最终确认之后，并始终保留 ESP/EFI 目录。
	boot_separate=0
	if [ "$(findmnt -rno TARGET /boot 2>/dev/null)" = "/boot" ]; then
		local boot_fs="" boot_nested="" boot_nested_fs=""
		boot_fs="$(findmnt -rno FSTYPE /boot 2>/dev/null)"
		boot_nested="$(findmnt -rno TARGET 2>/dev/null | awk '$0 ~ "^/boot/" { print; exit }')"
		[ -n "$boot_nested" ] && boot_nested_fs="$(findmnt -rno FSTYPE "$boot_nested" 2>/dev/null)"

		case "$boot_fs" in
		vfat | fat32 | msdos)
			# /boot 本身就是 ESP：必须保留挂载，grub-install 要往里写
			echo "/boot 是 EFI 系统分区（$boot_fs），保留挂载交给 grub-install 处理"
			boot_separate=1
			;;
		*)
			if [ -n "$boot_nested" ]; then
				# 典型：EFI + 独立 /boot(ext4) + ESP 挂在 /boot/efi。
				# 此时既不能 umount /boot（ESP 在用），也不该把旧内核留着
				# （update-grub 会把它们枚举进菜单）。做法：保留分区，
				# 只清空 /boot 内容（ESP 目录除外），并把 /boot 写进新 fstab。
				case "$boot_nested_fs" in
				vfat | fat32 | msdos)
					echo "/boot 是独立分区（${boot_fs:-未知}），其下 $boot_nested 是 ESP：保留分区、清空旧内核"
					echo "确认抹盘后才清理 /boot（保留 $boot_nested），并把 /boot 写入新 fstab"
					boot_separate=1
					;;
				*)
					err "/boot 是独立分区，且其下还有挂载点 $boot_nested（$boot_nested_fs）。请先手工 umount $boot_nested 与 /boot 后重试"
					;;
				esac
			else
				# 保留布局，避免把 /boot 搬到 GRUB 未必能读取的根文件系统。
				echo "/boot 是独立分区（${boot_fs:-未知}）：保持挂载，确认抹盘后清理旧内核，写入新 fstab"
				boot_separate=1
			fi
			;;
		esac

		if [ "$boot_separate" -eq 1 ]; then
			findmnt -no SOURCE,FSTYPE /boot >"${root_dir}/boot.dev.src" 2>/dev/null || true
			findmnt -no UUID /boot >"${root_dir}/boot.uuid.src" 2>/dev/null || true
			# /boot 本身就是 ESP（vfat）时，grub-install 的 --efi-directory 应该是
			# /boot 而不是 /boot/efi。把这一点记下来交给 install_grub。
			case "$boot_fs" in
			vfat | fat32 | msdos) echo "/boot" >"${root_dir}/esp.src" ;;
			esac
		fi
	fi

	# 2) 关键目录必须是根文件系统的一部分：删除时用了 -xdev，独立挂载会被跳过，
	#    留下旧系统残留并与新系统混杂，后果比直接报错更糟。
	#    名单必须覆盖所有会被新 rootfs 覆盖的目录：漏掉 /root 会让旧 authorized_keys
	#    活到新系统，漏掉 /boot 会让 update-grub 枚举到旧内核。
	local root_dev="" critical_dir=""
	root_dev="$(stat -c %d / 2>/dev/null)"
	for critical_dir in /etc /usr /var /lib /lib64 /bin /sbin /boot /root /home /opt /srv; do
		[ -e "$critical_dir" ] || continue
		# 独立 /boot 已登记为确认后单独清理，这里不再要求同设备
		if [ "$critical_dir" = "/boot" ] && [ "${boot_separate:-0}" -eq 1 ]; then
			continue
		fi
		if [ "$(stat -c %d "$critical_dir" 2>/dev/null)" != "$root_dev" ]; then
			err "$critical_dir 是独立挂载点，删除阶段会跳过它并留下旧系统文件。请先合并该挂载后重试"
		fi
	done

	# 2b) 任何其它挂载在 / 之下的路径同样会残留：只允许伪文件系统与 ESP
	local mnt="" mnt_fs=""
	while read -r mnt mnt_fs; do
		[ -n "$mnt" ] || continue
		case "$mnt" in
		/ | /dev | /dev/* | /proc | /proc/* | /sys | /sys/* | /run | /run/*) continue ;;
		/boot)
			[ "${boot_separate:-0}" -eq 1 ] && continue
			;;
		/boot/efi | /efi)
			case "$mnt_fs" in vfat | fat32 | msdos) continue ;; esac
			err "$mnt 不是 FAT ESP，不能作为 EFI 系统分区使用"
			;;
		"$root_dir" | "$root_dir"/*) continue ;;
		esac
		if [ -n "$work_dir" ] && { [ "$mnt" = "$work_dir" ] || [[ "$mnt" == "$work_dir"/* ]]; }; then
			continue
		fi
		# tmpfs 上的 /tmp、/dev/shm 之类：跳过它无副作用（重启即失效），
		# 强制用户改分区没有意义，只告警。
		case "$mnt_fs" in
		tmpfs | devtmpfs | ramfs)
			echo "警告：$mnt（$mnt_fs）不会被清理，重启后随挂载失效"
			continue
			;;
		esac
		err "$mnt 是独立挂载点，删除阶段（-xdev）会跳过它，其内容将残留在新系统中。请先卸载或合并后重试"
	done < <(findmnt -rno TARGET,FSTYPE 2>/dev/null)

	# 确认前后须保持同一套 /boot 挂载；防止在等待交互期间换盘/新增子挂载。
	findmnt -rno TARGET,SOURCE,FSTYPE >"${work_dir}/mounts.preflight" || err "无法记录挂载拓扑"
	awk '$1 == "/boot" || index($1, "/boot/") == 1 || $1 == "/efi"' \
		"${work_dir}/mounts.preflight" >"${work_dir}/boot.mounts.preflight"

	# 3) 目标 APT 源可达，避免删完旧系统后 apt-get update 才失败
	mirror="${apt_mirror_url:-$(get_default_apt_mirror)}"
	# 这里的探测必须和后面真正下载走同样的传输约束，否则「探测通过」不代表
	# 抹盘后 apt 能用（TLS 握手失败、重定向被降级都会在这一关被提前发现）。
	# 明文 http 镜像不加 --proto https（会全灭），但用户已在参数解析时收到告警。
	local -a mirror_tls=()
	case "$mirror" in
	https://*) mirror_tls=("${CURL_TLS_OPTS[@]}") ;;
	esac
	if ! curl "${mirror_tls[@]}" -fsI --connect-timeout 10 --max-time 30 "$mirror/dists/$selected_version/Release" >/dev/null 2>&1; then
		err "APT 镜像不可达：$mirror/dists/$selected_version/Release（已在删除旧系统前中止）"
	fi
	echo "APT 镜像可用：$mirror"

	# 3b) 新系统将使用的 DNS 必须能真的解析域名。抹盘后 resolv.conf 会被
	#     apply_dns_config 重写，若那份配置解析不了，apt-get update 只会刷 Ign，
	#     真正失败落在装内核那一步 —— 此时盘已抹空。
	#     这里用 busybox nslookup 显式指定待选 nameserver 探一次，不动当前系统。
	local probe_host="deb.debian.org"
	local -a dns_candidates=()
	local ns
	if [ "${use_local_dns:-0}" -eq 1 ] && [ -f "${root_dir}/resolv.conf.bak" ]; then
		while read -r ns; do dns_candidates+=("$ns"); done < <(
			awk '/^[[:space:]]*nameserver[[:space:]]+/{print $2}' "${root_dir}/resolv.conf.bak" 2>/dev/null
		)
	fi
	while read -r ns; do dns_candidates+=("$ns"); done < <(get_recommended_dns | awk '{print $2}')
	if [ "${#dns_candidates[@]}" -gt 0 ]; then
		local dns_ok=0
		for ns in "${dns_candidates[@]}"; do
			if "$busybox_path" nslookup "$probe_host" "$ns" >/dev/null 2>&1; then
				echo "DNS 预检通过：$ns 可解析 $probe_host"
				dns_ok=1
				break
			fi
		done
		if [ "$dns_ok" -eq 0 ]; then
			echo "警告：${dns_candidates[*]} 都无法解析 $probe_host，抹盘后 apt 可能失败（继续，但请确认网络允许 DNS）"
		fi
	fi

	# 4) 归档所属目录至少有剩余空间（解压后大致等于解压体积，仅作粗略门槛）
	local avail_kb
	avail_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
	if [ -n "$avail_kb" ] && [ "$avail_kb" -lt 2097152 ]; then
		echo "警告：根分区剩余空间不足 2GB（$avail_kb KB），解压可能失败"
	fi
}

# 抹盘前停掉还在往磁盘写的服务。journald/rsyslog 会在 find -delete 期间不断
# 重建 /var/log/journal 下的文件，与删除竞态：文件刚删掉又被写出来，最后
# /var 目录非空、rmdir 失败，于是抹完盘才报「仍残留 /var」——这是真实云主机
# 上复现到的失败，Alpine 测试机上没有 journald 所以一直没暴露。
stop_disk_writers() {
	command -v systemctl >/dev/null 2>&1 || return 0
	local unit t
	for unit in systemd-journald.service systemd-journald.socket \
		systemd-journald-dev-log.socket systemd-journald-audit.socket \
		rsyslog.service syslog-ng.service cron.service crond.service atd.service \
		systemd-tmpfiles-clean.service systemd-tmpfiles-clean.timer; do
		systemctl stop "$unit" >/dev/null 2>&1 || true
	done
	# 定时器会在删除过程中重建 /var/lib/systemd/timers/stamp-*（dpkg-db-backup、
	# apt-daily、logrotate 都是 daily 定时器），/var 于是永远删不干净、复查必然失败。
	while IFS= read -r t; do
		[ -n "$t" ] || continue
		systemctl stop "$t" >/dev/null 2>&1 || true
	done < <(systemctl list-units --type=timer --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}')
	systemctl daemon-reload >/dev/null 2>&1 || true
	# systemd 的日志服务是 socket 激活的，socket 没停干净会被一次写入重新拉起来
	pkill -TERM -x systemd-journal 2>/dev/null || true
	pkill -TERM -x rsyslogd 2>/dev/null || true
	return 0
}

# 返回第一个未被排除且仍存在的路径（空 = 已清空）。必须用 busybox find：
# /usr/bin/find 在删除过程中已被删掉。排除表达式每次重建，保证与 -delete 一致。
wipe_leftovers() {
	local -a expr=()
	# 生产者用 printf '%s\0'，这里必须用 -d '' 同分隔符；否则整个表达式会被当成
	# 一个巨大的路径 pattern，find 不报错却什么都匹配不到 —— 复查会假绿。
	mapfile -d '' -t expr < <(wipe_exclude_expr)
	[ "${#expr[@]}" -gt 0 ] || {
		echo "内部错误：无法构造 find 排除表达式，拒绝继续" >&2
		return 1
	}
	local errf="${work_dir:-/tmp}/wipe-verify.err" n=0
	# 不复用 2>/dev/null：表达式坏了必须看得见，不能表现成「没有残留」
	"$busybox_path" find / -xdev -mindepth 1 \( "${expr[@]}" \) -print 2>"$errf" |
		while IFS= read -r p; do
			local is_ancestor=0 keep_path
			for keep_path in "$root_dir" "$work_dir"; do
				[ -n "$keep_path" ] || continue
				case "$keep_path" in "$p"/*) is_ancestor=1 ;; esac
			done
			[ "$is_ancestor" -eq 1 ] && continue
			printf '%s\n' "$p"
			n=$((n + 1))
			[ "$n" -ge 50 ] && {
				printf '%s\n' "  ...（仅列出前 50 条）"
				break
			}
		done
	if [ -s "$errf" ]; then
		echo "警告：残留复查 find 报错（结果可能不可信）：$(head -c 400 "$errf")" >&2
	fi
	return 0
}

# 残留位置是否安全敏感：这些地方留下旧文件 = 攻击者的持久化随新系统活下来。
# /var 下的 cron 与 systemd/dpkg 状态单列，其余 /var 视为数据/日志，只告警。
# 目录里除了「保持不变的挂载点」以外什么都没有 = 无害（典型是 /boot 下只挂着
# /boot/efi）。不能用 find -xdev -print -quit 判断：-xdev 只阻止下降，挂载点
# 目录本身照样会被打印，于是 /boot 永远被判成「有残留」。
wipe_leftover_is_mount_only_dir() {
	local d="$1" child mnt is_mnt=0
	[ -d "$d" ] && [ ! -L "$d" ] || return 1
	[ -n "${busybox_path:-}" ] || return 1
	while IFS= read -r child; do
		[ -n "$child" ] || continue
		is_mnt=0
		for mnt in "${WIPE_MOUNTS[@]}"; do
			if [ "$child" = "$mnt" ]; then
				is_mnt=1
				break
			fi
		done
		[ "$is_mnt" -eq 1 ] || return 1
	done < <("$busybox_path" find "$d" -mindepth 1 -maxdepth 1 2>/dev/null)
	return 0
}

wipe_leftover_is_sensitive() {
	case "$1" in
	# 只放行 systemd 会自己重建的零字节 stamp：目录本身与 stamp-* 文件。
	# 同一目录下的其它文件（攻击者放进去的持久化内容）仍然算敏感 ——
	# 豁免范围过宽等于把整条抹盘复查关掉。
	/var/lib/systemd/timers) return 1 ;;
	/var/lib/systemd/timers/stamp-*)
		[ -f "$1" ] && [ ! -s "$1" ] && return 1
		return 0
		;;
	/etc | /etc/* | /root | /root/* | /home | /home/* | /bin | /bin/* | /sbin | /sbin/* \
		| /lib | /lib/* | /lib32 | /lib32/* | /lib64 | /lib64/* | /libx32 | /libx32/* \
		| /usr | /usr/* | /boot | /boot/* | /opt | /opt/* | /srv | /srv/* \
		| /var/spool/cron | /var/spool/cron/* | /var/lib/systemd | /var/lib/systemd/* \
		| /var/lib/dpkg | /var/lib/dpkg/*)
		return 0
		;;
	esac
	return 1
}

# 拼出 find 的排除条件（! -path A -a ! -path B ...），两个调用点共用，避免规则漂移。
# work_dir 在 /tmp 下、抹盘后还要继续使用，必须排除，否则后续步骤在空目录上失败。
# 抹盘前把新系统必需软件包预下载到保留目录（尽力而为，失败只告警）。
#
# 要解决的问题：抹盘之后 apt 装不上内核 = 装出一台开不了机的机器，而那时旧系统
# 已经没了。预先把 .deb 落到 $root_dir（抹盘时唯一被整体排除的目录），
# 网络再出问题也还有一份能 dpkg -i 的兜底；网络正常时 apt 直接复用本地缓存，
# 少下一份。
#
# 局限（明确声明，不当保证用）：
#  - 宿主机不是 Debian/Ubuntu（没有 apt/dpkg）→ 跳过；
#  - 跨架构（x86 宿主机装 arm64）→ apt 不支持，跳过；
#  - 下载失败只告警，后续仍走联网安装。
offline_stage_dir=""
stage_offline_packages() {
	offline_stage_dir=""
	[ "${offline_stage:-1}" -eq 1 ] || return 0
	command -v apt-get >/dev/null 2>&1 || {
		echo "宿主机没有 apt，跳过离线包预下载"
		return 0
	}
	local host_arch=""
	host_arch="$(dpkg --print-architecture 2>/dev/null)"
	if [ -n "$host_arch" ] && [ "$host_arch" != "$image_arch" ]; then
		echo "宿主机架构 $host_arch 与新系统 $image_arch 不同，跳过离线包预下载（跨架构 apt 不支持）"
		return 0
	fi

	local mirror="" suite="$selected_version"
	mirror="${apt_mirror_url:-$(get_default_apt_mirror)}"
	local stage="${work_dir}/aptstage" dir="${root_dir}/offline-debs"
	# var/lib/dpkg 必须一起建：下面 `: >status` 需要该目录存在，缺了会在
	# 「确认抹盘」之后才报 No such file or directory（真实 VPS 上踩过）
	mkdir -p "$stage/etc/apt/apt.conf.d" "$stage/var/lib/apt/lists/partial" \
		"$stage/var/cache/apt/archives/partial" "$stage/var/lib/dpkg" "$dir" || return 0
	: >"$stage/var/lib/dpkg/status" || {
		echo "警告：无法创建临时 dpkg 状态文件，跳过离线包预下载"
		return 0
	}

	if [ "$system" = "debian" ]; then
		{
			echo "deb $mirror $suite main contrib non-free non-free-firmware"
			echo "deb https://security.debian.org/debian-security $suite-security main contrib non-free non-free-firmware"
		} >"$stage/sources.list"
	else
		{
			echo "deb $mirror $suite main restricted universe multiverse"
			echo "deb $mirror $suite-updates main restricted universe multiverse"
			echo "deb $mirror $suite-security main restricted universe multiverse"
		} >"$stage/sources.list"
	fi

	# 把 apt 的全部状态指向临时目录：解析的是**新发行版**的索引，装的是**新架构**的包，
	# 不会污染宿主机的 apt 状态。
	local -a aptroot=(
		-o "Dir::Etc::sourcelist=$stage/sources.list"
		-o "Dir::Etc::sourceparts=/dev/null"
		-o "Dir::State::lists=$stage/var/lib/apt/lists"
		-o "Dir::State::status=$stage/var/lib/dpkg/status"
		-o "Dir::Cache=$stage/var/cache/apt"
		-o "Dir::Cache::archives=$dir"
		-o "APT::Install-Recommends=0"
		-o "APT::Install-Suggests=0"
		-o "Acquire::Languages=none"
		-o "Debug::NoLocking=1"
	)

	echo "预下载新系统必需软件包（$kernel_pkg、initramfs-tools、DHCP 客户端等）到 ${dir} ..."
	# 旧机的时钟同样可能偏（RTC 不准），这里不校正的话索引会整批被判成"来自未来"
	sync_clock_from_mirror "$mirror"
	if ! apt-get "${aptroot[@]}" update >"${work_dir}/aptstage.log" 2>&1; then
		echo "警告：预下载阶段无法读取 $suite 的软件源索引，已跳过（后续仍会联网安装，不影响流程）"
		return 0
	fi
	# 不同发行版/版本的包名不一样（Debian 14 已移除 isc-dhcp-client），
	# 逐个做 -s 模拟探测，缺的跳过，别让一个包把整批预下载拖垮。
	local -a want=("$kernel_pkg" initramfs-tools ifupdown openssh-server)
	local cand pkg
	for cand in isc-dhcp-client dhcpcd-base udhcpc; do
		if apt-get "${aptroot[@]}" -s install "$cand" >/dev/null 2>&1; then
			want+=("$cand")
			break
		fi
	done
	local -a got=()
	for pkg in "${want[@]}"; do
		if apt-get "${aptroot[@]}" -s install "$pkg" >/dev/null 2>&1; then
			got+=("$pkg")
		else
			echo "提示：$pkg 在 $suite 里不可用，跳过预下载"
		fi
	done
	if [ "${#got[@]}" -eq 0 ]; then
		echo "警告：$suite 源里没有可预下载的软件包，已跳过（后续联网安装）"
		return 0
	fi
	if ! apt-get "${aptroot[@]}" -d --yes --no-install-recommends install "${got[@]}" \
		>>"${work_dir}/aptstage.log" 2>&1; then
		echo "警告：预下载软件包失败，已跳过（不影响后续联网安装）。apt 报错末尾："
		tail -n 20 "${work_dir}/aptstage.log" 2>/dev/null | sed 's/^/  | /' || true
		return 0
	fi

	local n=0
	n="$(find "$dir" -maxdepth 1 -name '*.deb' 2>/dev/null | wc -l)"
	if [ "$n" -eq 0 ]; then
		echo "警告：预下载没有取到任何 .deb，已跳过"
		return 0
	fi
	offline_stage_dir="$dir"
	echo "已预下载 $n 个软件包（$(du -sh "$dir" 2>/dev/null | awk '{print $1}')）：网络异常时可离线安装"
	return 0
}

# 抹盘后 apt 取不到索引时的兜底：用预下载的 .deb 直接把内核和 initramfs 装上。
# 装上了就还能开机/SSH，剩下的包等网络恢复再补；装不上就交还给调用方按致命错误处理。
offline_package_rescue() {
	local d="/var/cache/apt/archives" k="" i=""
	[ -d "$d" ] || return 1
	k="$(find "$d" -maxdepth 1 -name '*.deb' 2>/dev/null | sort)"
	[ -n "$k" ] || return 1
	echo "警告：软件源不可用，改用抹盘前预下载的 $(printf '%s\n' "$k" | wc -l) 个包离线安装"
	# shellcheck disable=SC2086
	DEBIAN_FRONTEND=noninteractive dpkg -i $k >/dev/null 2>&1 ||
		DEBIAN_FRONTEND=noninteractive dpkg --configure -a >/dev/null 2>&1 || true
	k="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -print -quit 2>/dev/null)"
	i="$(find /boot -maxdepth 1 \( -name 'initrd.img-*' -o -name 'initramfs-*.img' \) -print -quit 2>/dev/null)"
	if [ -n "$k" ] && [ -n "$i" ]; then
		echo "警告：已离线装上内核（${k##*/}）与 initramfs，但软件包集合可能不完整。网络恢复后请执行：apt-get update && apt-get -f install"
		return 0
	fi
	echo "警告：离线安装后仍未得到可引导的内核/initramfs"
	return 1
}

wipe_exclude_expr() {
	# 注意 "*" 必须留在引号内（"${root_dir}/*"）。写成 "$root_dir"/* 会被 shell
	# 先展开成 /os 下的现有条目，通配符消失，find 只剩 `! -path /os/os.tar.xz`
	# 这类精确路径，于是 /os 下更深层的内容（如 reinstall-backup-stage/payload/*
	# 与 backup.tar.gz）全部被删掉 —— 备份会静默变成空壳。
	local -a paths=(/dev /dev/'*' /proc /proc/'*' /sys /sys/'*' /run /run/'*' "$root_dir" "${root_dir:?}/*")
	[ -n "$work_dir" ] && paths+=("$work_dir" "${work_dir}/*")

	# 挂载点目录本身也必须排除。-xdev 只是阻止 find 下降，它仍会访问并尝试
	# rmdir 每个挂载点（/dev /proc /sys /run 恒为挂载点，rmdir 必 EBUSY；/boot/efi
	# 的 vfat 同理）。旧版靠 `|| true` 把这些失败静默掉，现在删除与复查共用
	# 同一份 expr 且硬失败，漏掉它们就会在盘已经抹空之后误报「仍有残留」。
	local mnt
	if [ "${#WIPE_MOUNTS[@]}" -gt 0 ]; then
		paths+=("${WIPE_MOUNTS[@]}")
	else
		while IFS= read -r mnt; do
			[ -n "$mnt" ] || continue
			[ "$mnt" = "/" ] && continue
			paths+=("$mnt")
		done < <(findmnt -rno TARGET 2>/dev/null || true)
	fi

	local -a expr=()
	local p
	for p in "${paths[@]}"; do
		[ "${#expr[@]}" -gt 0 ] && expr+=(-a)
		expr+=('!' -path "$p")
	done
	printf '%s\0' "${expr[@]}"
}

# 实时探测「承载 / 的那块盘由哪个内核驱动」，只输出驱动名，不写文件。
# 用在预先的选型决策上（kexec/重启后无法再探测），以及 dry-run 摘要里。
probe_root_driver() {
	local src="" dev="" disk="" drvpath="" drv=""
	src="$(findmnt -no SOURCE / 2>/dev/null)" || src=""
	[ -n "$src" ] || return 0
	dev="$(readlink -f "$src" 2>/dev/null)" || dev="$src"
	disk="$(basename "$dev")"
	if command -v lsblk >/dev/null 2>&1; then
		local pk=""
		pk="$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n 1)"
		[ -n "$pk" ] && disk="$pk"
	fi
	[ -e "/sys/block/$disk" ] || return 0
	drvpath="$(readlink -f "/sys/block/$disk/device/driver" 2>/dev/null)" || drvpath=""
	drv="$(basename "${drvpath:-none}")"
	[ "$drv" = "none" ] && drv=""
	printf '%s\n' "$drv"
	return 0
}

record_root_drivers() {
	# 抹盘前记录：根磁盘靠哪个内核模块驱动。重启前用它核对新内核是否真的带这个驱动。
	# 已踩过的坑：Debian linux-image-cloud-amd64 里没有 ahci.ko/nvme.ko，
	# 装完重启内核压根看不到 SATA 磁盘，只能掉进 initramfs 救援 shell。
	local src="" dev="" disk="" drv="" drvpath="" fstype="" drv_list=""
	local path="" m=""
	: >"${root_dir}/root.driver.src" 2>/dev/null || return 0

	[ -s "${root_dir}/root.dev.src" ] || return 0
	read -r src _ <"${root_dir}/root.dev.src" || true
	[ -n "$src" ] || return 0

	dev="$(readlink -f "$src" 2>/dev/null)" || dev="$src"
	disk="$(basename "$dev")"
	if command -v lsblk >/dev/null 2>&1; then
		local pk=""
		pk="$(lsblk -no PKNAME "$dev" 2>/dev/null | head -n 1)"
		[ -n "$pk" ] && disk="$pk"
	fi

	# 根文件系统类型也要记：ext4/xfs/btrfs 对应的模块同样必须在新内核里存在
	fstype="$(lsblk -no FSTYPE "$dev" 2>/dev/null | head -n 1)"
	if [ -z "$fstype" ]; then
		fstype="$(findmnt -no FSTYPE / 2>/dev/null)"
	fi

	[ -e "/sys/block/$disk" ] || return 0
	# /sys/block/sda/device/driver -> .../drivers/sd；虚拟机里则是 virtio_blk / nvme
	drvpath="$(readlink -f "/sys/block/$disk/device/driver" 2>/dev/null)" || drvpath=""
	drv="$(basename "${drvpath:-none}")"
	[ "$drv" = "none" ] && drv=""

	# 只记"直接驱动"不够：sd 只是 SCSI 磁盘层，真正的控制器驱动（ahci/nvme/virtio_blk/
	# mptsas/megaraid_sas…）在它的上层。cloud 内核缺的恰恰是上层那个（没有 ahci.ko），
	# 只查 sd_mod 会给出错误的"通过"。这里沿 sysfs 向上把整条链都收集起来。
	path="$(readlink -f "/sys/block/$disk" 2>/dev/null)" || path=""
	while [ -n "$path" ] && [ "$path" != "/" ] && [ "$path" != "/sys" ]; do
		if [ -L "$path/driver" ]; then
			m="$(basename "$(readlink -f "$path/driver" 2>/dev/null)")"
			case " $drv_list " in
			*" $m "*) ;;
			*) [ -n "$m" ] && drv_list="$drv_list $m" ;;
			esac
		fi
		path="${path%/*}"
		[ -n "$path" ] || break
	done
	drv_list="${drv_list# }"

	{
		echo "disk=$disk"
		echo "driver=$drv"
		echo "drivers=$drv_list"
		echo "fstype=$fstype"
	} >"${root_dir}/root.driver.src" 2>/dev/null || true
	return 0
}

# 从实际生成的菜单里取出"默认会引导"的内核版本号。
# 只读 grub.cfg，不猜 /lib/modules 里的第一个 —— 检查的内核必须是真正启动的那个。
grub_default_kver() {
	local cfg="/boot/grub/grub.cfg"
	[ -s "$cfg" ] || return 1
	local first_entry="" linux_line="" kref=""
	first_entry="$(awk '/^[[:space:]]*(menuentry|submenu)[[:space:]]/ {n++; if(n>1) exit} n==1 {print}' "$cfg")"
	linux_line="$(awk '$1 == "linux" || $1 == "linuxefi" {print; exit}' <<<"$first_entry")"
	kref="$(awk '{print $2}' <<<"$linux_line")"
	case "$kref" in
	*/vmlinuz-*) echo "${kref##*/vmlinuz-}" ;;
	*) return 1 ;;
	esac
}

# $1=内核版本目录名 $2=模块名。模块可以是 .ko/.ko.xz/.ko.zst，也可以编译进内核。
kernel_has_module() {
	# 空版本会让 kb 退化成 /lib/modules/，find 会递归扫到任意内核的模块 → 假通过
	[ -n "$1" ] || return 1
	local kb="/lib/modules/$1" m="$2"
	[ -d "$kb" ] || return 1
	# sysfs 里的驱动名用连字符（virtio-pci、xen-blkfront），内核模块文件名用下划线
	# （virtio_pci.ko）。不转换就会把"编成模块的驱动"误判成缺失。
	local m_us="${m//-/_}" cand=""
	for cand in "$m" "$m_us"; do
		[ -n "$cand" ] || continue
		# 注意不能加 -x：modules.builtin 的行是 "kernel/fs/ext4/ext4.ko"，
		# 整行锚定会永远匹配不到，内置模块就被误判成缺失（实测 Debian 14 cloud 内核的 ext4）
		if [ -f "$kb/modules.builtin" ] &&
			grep -qE "(^|/)${cand}\.ko(\.(xz|zst|gz))?$" "$kb/modules.builtin" 2>/dev/null; then
			return 0
		fi
		pipe_grep_q "." find "$kb" -name "${cand}.ko*" -print -quit 2>/dev/null && return 0
	done
	return 1
}

# 把驱动链里的名字换成模块文件名（连字符→下划线），供 initramfs 检查用
module_file_name() {
	local m="$1"
	# 别名：sd 是 SCSI 磁盘类设备，没有名为 sd 的模块
	case "$m" in sd) m="sd_mod" ;; esac
	echo "${m//-/_}"
}

# 让"能用的内核"真正成为默认引导项：把缺驱动的内核包卸掉，update-grub 后
# GRUB_DEFAULT=0 自然落到剩下的那个。比改 GRUB_DEFAULT 字符串可靠——
# 菜单标题随发行版/语言变化，猜标题很容易猜错，卸掉坏内核没有歧义。
drop_kernels_lacking_modules() {
	local kb kver bad="" good=0
	for kb in /lib/modules/*/; do
		[ -d "$kb" ] || continue
		kver="$(basename "$kb")"
		local d="" lack=0
		for d in "$@"; do
			kernel_has_module "$kver" "$d" || {
				lack=1
				break
			}
		done
		if [ "$lack" -eq 1 ]; then bad="$bad $kver"; else good=$((good + 1)); fi
	done
	[ -n "$bad" ] || return 0
	# 一个能用的内核都没有时绝不能卸：卸完就没有内核可引导了
	if [ "$good" -eq 0 ]; then
		echo "警告：所有已安装内核都缺根磁盘驱动（$bad），不做任何移除"
		return 1
	fi
	command -v apt-get >/dev/null 2>&1 || {
		echo "警告：以下内核缺少根磁盘驱动，但系统不是 apt 系，无法自动移除：$bad"
		return 1
	}
	local -a pkgs=()
	local name=""
	for kver in $bad; do
		while IFS= read -r name; do
			[ -n "$name" ] && pkgs+=("$name")
		done < <(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep -F -- "$kver" || true)
	done
	[ "${#pkgs[@]}" -gt 0 ] || return 1
	echo "移除缺少根磁盘驱动的内核包：${pkgs[*]}"
	DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "${pkgs[@]}" >/dev/null 2>&1 || {
		echo "警告：移除内核包失败，需要手工处理"
		return 1
	}
	command -v update-grub >/dev/null 2>&1 && update-grub >/dev/null 2>&1
	return 0
}

verify_root_driver_installed() {
	# 重启前断言：**默认引导的那个内核**里有根磁盘整条驱动链的模块。
	# 只看 sd_mod 会误判：sd_mod 是 SCSI 磁盘层，控制器驱动（ahci/nvme/virtio_blk…）
	# 在它上层，cloud 内核缺的正是上层那个。也不该"随便找个内核有一个就算过"——
	# GRUB 默认项用的是另一个内核时，装了也白装。
	local f="${root_dir}/root.driver.src"
	[ -s "$f" ] || {
		echo "警告：没有根磁盘驱动记录（root.driver.src），跳过驱动自检"
		return 0
	}

	local disk="" drv="" drivers="" fstype="" k="" kb=""
	while IFS='=' read -r k v; do
		case "$k" in
		disk) disk="$v" ;;
		driver) drv="$v" ;;
		drivers) drivers="$v" ;;
		fstype) fstype="$v" ;;
		esac
	done <"$f"

	local -a mods=()
	local d=""
	for d in $drivers; do
		[ -n "$d" ] && mods+=("$(module_file_name "$d")")
	done
	# sysfs 链读不到（容器/受限环境）时至少查直接驱动
	[ "${#mods[@]}" -gt 0 ] || [ -z "$drv" ] || mods+=("$(module_file_name "$drv")")
	# 根文件系统自己的模块同样必须在：ext4 编成模块的镜像很常见
	case "$fstype" in
	ext4 | xfs | btrfs | f2fs | zfs) mods+=("$fstype") ;;
	esac

	# 去重（保持顺序）
	local -a uniq=()
	local seen=" "
	for d in "${mods[@]}"; do
		[ -n "$d" ] || continue
		case "$seen" in *" $d "*) continue ;; esac
		seen="$seen$d "
		uniq+=("$d")
	done
	mods=("${uniq[@]}")
	[ "${#mods[@]}" -gt 0 ] || {
		echo "警告：无法识别根磁盘（$disk）的驱动模块，跳过驱动自检"
		return 0
	}

	local kver="" miss=""
	kver="$(grub_default_kver 2>/dev/null)" || kver=""
	# 菜单解析不出来（EFI 特殊布局、手工改过 cfg）时退回检查全部内核：
	# 宁可多检查一遍，也不要因为解析失败就跳过。
	local -a targets=()
	if [ -n "$kver" ] && [ -d "/lib/modules/$kver" ]; then
		targets=("$kver")
	else
		echo "警告：无法从 GRUB 菜单确定默认内核，改为逐个检查已安装的内核"
		for kb in /lib/modules/*/; do
			[ -d "$kb" ] || continue
			targets+=("$(basename "$kb")")
		done
	fi

	# 任一目标内核缺失任一模块即视为"可能起不来"
	local missing_in_default=0
	for kver in "${targets[@]}"; do
		miss=""
		for d in "${mods[@]}"; do
			kernel_has_module "$kver" "$d" || miss="$miss $d"
		done
		[ -z "$miss" ] && continue
		echo "警告：内核 $kver 缺少模块：${miss# }（根磁盘 $disk，驱动链：${drivers:-$drv}）"
		[ "$kver" = "$(grub_default_kver 2>/dev/null)" ] && missing_in_default=1
	done

	if [ "$missing_in_default" -eq 1 ] || [ "${#targets[@]}" -eq 0 ]; then
		# 缺驱动 = 重启必黑。直接 err 会把机器留在"已抹空、无引导"的状态，
		# 补装通用内核是唯一能自救的动作，装完再复检一次。
		local -a rescue_pkgs=()
		case "$system:$arch" in
		debian:x86_64) rescue_pkgs=(linux-image-amd64) ;;
		debian:aarch64) rescue_pkgs=(linux-image-arm64) ;;
		ubuntu:x86_64 | ubuntu:aarch64) rescue_pkgs=(linux-image-generic) ;;
		esac
		if [ "${#rescue_pkgs[@]}" -gt 0 ] && command -v apt-get >/dev/null 2>&1; then
			echo "警告：默认内核缺少根磁盘驱动，尝试补装通用内核：${rescue_pkgs[*]}"
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
				-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
				"${rescue_pkgs[@]}" || true
			if command -v update-grub >/dev/null 2>&1; then
				update-grub >/dev/null 2>&1 || true
			fi
			kver="$(grub_default_kver 2>/dev/null)" || kver=""
			# 空 kver 时 [ -d /lib/modules/ ] 为真 → 必须显式先判空，否则假通过
			local ok=0
			if [ -n "$kver" ] && [ -d "/lib/modules/$kver" ]; then
				ok=1
				for d in "${mods[@]}"; do
					kernel_has_module "$kver" "$d" || ok=0
				done
			fi
			if [ "$ok" -eq 1 ]; then
				echo "存储驱动自检通过（补装后）：默认内核 $kver 含 ${mods[*]}"
				missing_in_default=0
			else
				# 补装成功但默认引导项还是原来那个坏内核（GRUB_DEFAULT=0 指向
				# 镜像自带的首个内核）。把缺驱动的内核包卸掉，剩下的那个自动成为默认。
				drop_kernels_lacking_modules "${mods[@]}" || true
				kver="$(grub_default_kver 2>/dev/null)" || kver=""
				ok=0
				if [ -n "$kver" ] && [ -d "/lib/modules/$kver" ]; then
					ok=1
					for d in "${mods[@]}"; do
						kernel_has_module "$kver" "$d" || ok=0
					done
				fi
				if [ "$ok" -eq 1 ]; then
					echo "存储驱动自检通过（移除坏内核后）：默认内核 $kver 含 ${mods[*]}"
					missing_in_default=0
				else
					echo "警告：移除坏内核后默认内核仍未解析到含驱动的内核（当前：${kver:-无}）"
				fi
			fi
		fi
	fi

	if [ "$missing_in_default" -eq 1 ] || [ "${#targets[@]}" -eq 0 ]; then
		err "自检失败：默认引导的内核里缺少根磁盘 $disk 所需的驱动模块（${mods[*]}，驱动链：${drivers:-$drv}）。重启后内核找不到根文件系统，会掉进 initramfs 救援 shell。请用 --kernel generic 重新安装"
	fi
	echo "存储驱动自检通过：根磁盘 $disk（驱动链 ${drivers:-$drv}）所需模块 ${mods[*]} 均在新内核中"

	# 模块在 /lib/modules 里 ≠ 在 initramfs 里。initramfs 才是启动时真正加载驱动的地方：
	# Debian 默认 MODULES=most 会带上存储驱动，但被改成 MODULES=dep（或最小化镜像）
	# 时只带"探测到的"模块，换盘/换控制器后 initramfs 里就没有驱动了。
	if command -v lsinitramfs >/dev/null 2>&1; then
		kver="$(grub_default_kver 2>/dev/null)" || kver=""
		local initrd=""
		for kb in "/boot/initrd.img-${kver:-x}" "/boot/initramfs-${kver:-x}.img"; do
			[ -f "$kb" ] && { initrd="$kb"; break; }
		done
		if [ -z "$kver" ]; then
			echo "警告：无法确定默认内核版本，跳过 initramfs 驱动自检"
		elif [ -z "$initrd" ]; then
			echo "警告：未找到默认内核 $kver 的 initramfs，跳过该检查"
		else
			local imissing="" rebuilt=0
			for d in "${mods[@]}"; do
				pipe_grep_q "/${d}\.ko" lsinitramfs "$initrd" && continue
				if [ "$rebuilt" -eq 0 ]; then
					echo "initramfs（$initrd）缺少 ${d}，按 MODULES=most 重建一次"
					MODULES=most update-initramfs -u -k "$kver" >/dev/null 2>&1 ||
						update-initramfs -u -k "$kver" >/dev/null 2>&1 || true
					rebuilt=1
				fi
				pipe_grep_q "/${d}\.ko" lsinitramfs "$initrd" || imissing="$imissing $d"
			done
			if [ -n "$imissing" ]; then
				err "自检失败：initramfs（$initrd）不含驱动模块${imissing}，重启后内核枚举不到磁盘。请在重启前手工执行 MODULES=most update-initramfs -u -k all"
			fi
			echo "initramfs 自检通过：$initrd 内已包含 ${mods[*]}"
		fi
	fi
	return 0
}

# 抹盘前把旧系统里有价值的配置打包，带到新系统 /root/reinstall-backup/。
# 这些东西在抹盘后没有任何办法找回，而它们恰恰是重装之后最常被需要的东西。
collect_reinstall_backup() {
	local stage="${root_dir}/reinstall-backup-stage"
	rm -rf "$stage"
	mkdir -p "$stage/payload" || {
		echo "警告：无法创建备份暂存目录，跳过旧系统配置备份"
		return 0
	}

	local -a items=(
		/etc/fstab /etc/hosts /etc/hostname /etc/resolv.conf
		/etc/network/interfaces /etc/network/interfaces.d
		/etc/netplan /etc/sysconfig/network-scripts /etc/systemd/network
		/etc/systemd/system /etc/ssh/sshd_config /etc/ssh/sshd_config.d
		/etc/apt/sources.list /etc/apt/sources.list.d
		/etc/default/grub /etc/default/grub.d /boot/grub/grub.cfg /boot/grub/grubenv
		/etc/initramfs-tools /etc/crypttab /etc/mdadm /etc/lvm /etc/crontab /etc/cron.d
		/var/spool/cron /etc/sysctl.conf /etc/sysctl.d
		/etc/security/limits.conf /etc/rc.local /root/.ssh
	)
	local src base
	for src in "${items[@]}"; do
		[ -e "$src" ] || continue
		base="${src#/}"
		mkdir -p "$stage/payload/$(dirname "$base")"
		cp -a "$src" "$stage/payload/$(dirname "$base")/" 2>/dev/null || true
	done

	# /root 下的散装脚本、笔记只取一层普通文件，避免把整个家目录拖进来
	mkdir -p "$stage/payload/root"
	local f
	while IFS= read -r f; do
		cp -a "$f" "$stage/payload/root/" 2>/dev/null || true
	done < <(find /root -maxdepth 1 -type f -size -5M 2>/dev/null)

	# 已装软件清单：重装后按需装回，比事后凭记忆靠谱
	if command -v dpkg >/dev/null 2>&1; then
		dpkg --get-selections >"$stage/payload/pkglist.txt" 2>/dev/null || true
	fi

	find "$stage/payload" -type f -size +5M -delete 2>/dev/null || true

	if tar -czf "$stage/backup.tar.gz" -C "$stage/payload" . 2>/dev/null; then
		echo "旧系统配置已打包（$(du -h "$stage/backup.tar.gz" 2>/dev/null | awk '{print $1}')）"
	else
		echo "警告：旧系统配置打包失败，本次不产生备份"
		rm -f "$stage/backup.tar.gz"
	fi

	# 上一轮重装留下的备份同样在待抹除的根分区里，一起搬进暂存区才能活下来
	if [ -d /root/reinstall-backup ] && [ -n "$(ls -A /root/reinstall-backup 2>/dev/null)" ]; then
		mkdir -p "$stage/carry"
		cp -a /root/reinstall-backup/. "$stage/carry/" || err "历史备份暂存失败，拒绝抹盘以免丢失已有备份"
		echo "发现历史重装备份，将随新系统保留"
	fi
	return 0
}

# 把备份落进新系统。历史备份最多保留两份，超过就不再新增/覆盖。
restore_reinstall_backup() {
	local stage="${root_dir}/reinstall-backup-stage"
	[ -d "$stage" ] || return 0

	mkdir -p /root/reinstall-backup 2>/dev/null || {
		echo "警告：无法创建 /root/reinstall-backup，跳过备份恢复"
		return 0
	}
	chmod 700 /root/reinstall-backup 2>/dev/null || true

	if [ -d "$stage/carry" ]; then
		cp -an "$stage/carry/." /root/reinstall-backup/ || err "历史备份恢复失败，暂存数据仍在 $stage，请勿清理"
	fi

	local count=0
	count=$(find /root/reinstall-backup -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)
	if [ "$count" -ge 2 ]; then
		echo "已存在 $count 份重装备份（上限 2 份），本次不再新增，也不覆盖旧备份"
		rm -rf "$stage"
		return 0
	fi

	local gen
	gen="/root/reinstall-backup/$(date -u '+%Y%m%dT%H%M%SZ')"
	mkdir "$gen" || err "备份目录已存在或不可创建，拒绝覆盖：$gen"
	if [ -f "$stage/backup.tar.gz" ]; then
		"$busybox_path" tar -xzf "$stage/backup.tar.gz" -C "$gen" 2>/dev/null ||
			echo "警告：旧系统配置解包失败，备份可能不完整"
	fi
	cat >"$gen/README.txt" <<EOF
重装前旧系统的配置快照（由 ReinstallDebianUbuntu.sh 自动生成）

etc/      旧系统的 /etc 下与网络、SSH、APT、GRUB、计划任务相关的配置
root/     旧系统 /root 下的普通文件（脚本、笔记等）
pkglist.txt  旧系统已安装软件清单（仅当旧系统有 dpkg 时才有此文件）

注意：这些是旧系统的配置，不能直接整目录盖回新系统
（UUID、网卡名、软件版本都可能不同），请按需挑用。
备份最多两份；达到两份后不再新增，不覆盖或删除已有两份。
EOF
	chmod -R go-rwx "$gen" 2>/dev/null || true
	echo "旧系统配置已备份到 $gen"
	rm -rf "$stage"
	return 0
}

# 仅在最终确认、元数据备份、WIPE_STARTED 写入之后调用。
clean_retained_boot() {
	local current=""
	current="$(findmnt -rno TARGET,SOURCE,FSTYPE)" || err "无法复核引导分区挂载"
	current="$(awk '$1 == "/boot" || index($1, "/boot/") == 1 || $1 == "/efi"' <<<"$current")"
	[ -f "${work_dir}/boot.mounts.preflight" ] || err "缺少引导挂载预检记录，拒绝删除"
	[ "$current" = "$(<"${work_dir}/boot.mounts.preflight")" ] ||
		err "确认期间引导分区挂载已改变，拒绝删除，请重新预检"
	[ "${boot_separate:-0}" -eq 1 ] || return 0
	[ "${wipe_phase:-0}" -eq 1 ] && [ "${dry_run:-0}" -eq 0 ] || err "尚未授权删除独立 /boot"

	echo "清理独立 /boot 的旧内核及 GRUB 配置（保留 EFI 目录与 ESP）"
	if command -v chattr >/dev/null 2>&1; then
		find /boot -xdev -depth -mindepth 1 ! -ipath '/boot/efi' ! -ipath '/boot/efi/*' \
			-exec chattr -i {} + 2>/dev/null || true
	fi
	find /boot -xdev -depth -mindepth 1 ! -ipath '/boot/efi' ! -ipath '/boot/efi/*' -delete ||
		err "无法清空独立 /boot 的旧内核，已中止，请勿重启"
}

delete_old_system() {
	[ -f "$busybox_path" ] || err "BusyBox 文件缺失：$busybox_path"
	"$busybox_path" --help >/dev/null 2>&1 || err "BusyBox 不可执行：$busybox_path"

	# 只允许在正常的根上执行，防止变量异常时误删
	[ -n "$root_dir" ] && [ "$root_dir" != "/" ] || err "root_dir 取值异常（'$root_dir'），拒绝删除"
	[ -d "$root_dir" ] && [ ! -L "$root_dir" ] || err "$root_dir 不是真实目录（可能是符号链接），拒绝删除"

	# 旧 fstab 只留作参考：新系统必须自己生成，直接套用旧机的 UUID/挂载选项
	# 会让新系统起不来（旧机的 /home、/var 分区可能不存在或类型不同）
	cp /etc/fstab "${root_dir}/fstab.old.reinstall" 2>/dev/null || echo "警告：无法备份 fstab"

	# 记录根设备标识，供重装后生成最小 fstab（fstab 缺失不影响 root 挂载，但可读性更好）
	# 必须在抹盘前取：抹完 blkid/util-linux 都没了，新镜像里也还没有
	if command -v findmnt >/dev/null 2>&1; then
		findmnt -no SOURCE,FSTYPE / >"${root_dir}/root.dev.src" 2>/dev/null || true
		findmnt -no UUID / >"${root_dir}/root.uuid.src" 2>/dev/null || true
		# btrfs 的真实子卷名（subvol=/@ 不是通用假设）
		findmnt -no OPTIONS / 2>/dev/null |
			sed -n 's/.*subvol=\([^,]*\).*/\1/p' >"${root_dir}/root.subvol.src" || true
		# ESP 实际挂载点：/boot/efi 或 /efi，install_grub 写在抹盘后，必须提前记下。
		# preflight 可能已经把 /boot（本身即 ESP）写进 esp.src，那种情况不要覆盖。
		if [ ! -s "${root_dir}/esp.src" ]; then
			findmnt -rno TARGET,FSTYPE 2>/dev/null |
				awk '$2 == "vfat" && ($1 == "/boot/efi" || $1 == "/efi") { print $1; exit }' \
					>"${root_dir}/esp.src" || true
		fi
	fi

	# 记录根磁盘依赖的存储驱动名。重启前据此核对新内核是否带这些驱动：
	# cloud/virtual 内核裁掉了 ahci/nvme，装到 SATA/NVMe 机器上会找不到根设备
	record_root_drivers

	# 记录旧机的内核命令行。/proc/cmdline 在抹盘后仍指向老内核，但 reboot_prompt
	# 之前的一切都可能读到它，先落盘更稳。新系统要继承 console=/iommu 这类参数：
	# 云镜像的 /etc/default/grub 是空的，不继承就等于抹掉了 VPS 唯一能看开机的串口控制台。
	tr ' ' '
' </proc/cmdline >"${root_dir}/old.cmdline.src" 2>/dev/null || true

	# 搜集要带进新系统的旧配置。必须在抹盘前做，抹完这些文件就没了。
	collect_reinstall_backup

	# 抹盘标记：脚本自身的删除会把 /bin/sh、bash、curl 一起带走，中途失败后
	# 二次运行等于在「半新半旧」的系统上重新选盘。标记文件留在 $root_dir（被排除），
	# 下次启动时据此拒绝静默续跑。
	{
		echo "started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "root_dir=$root_dir"
		echo "target=$system $selected_version $image_arch"
	} >"${root_dir}/WIPE_STARTED" 2>/dev/null || echo "警告：无法写入抹盘标记（重启后无法识别部分删除状态）"

	clean_retained_boot

	echo "即将删除当前根文件系统中的全部文件（保留 $root_dir）。"
	if command -v findmnt >/dev/null 2>&1; then
		echo "以下挂载点不在根文件系统上，将保持不变："
		findmnt -rno TARGET | grep -v '^/$' | sed 's/^/  /' || true
	fi

	# 排除表达式只拼一次，-delete 与复查共用，避免两处规则漂移
	local -a expr=()
	mapfile -d '' -t expr < <(wipe_exclude_expr)
	[ "${#expr[@]}" -gt 0 ] || err "内部错误：删除排除表达式为空，拒绝执行"

	# 记录换区大小，重装后按原尺寸重建 swapfile（云镜像通常完全没有 swap）
	if command -v swapon >/dev/null 2>&1 && command -v findmnt >/dev/null 2>&1; then
		swapon --show=SIZE --noheadings --bytes 2>/dev/null |
			awk '{ s += $1 } END { if (s > 0) printf "%d\n", s }' >"${root_dir}/swap.size.src" || true
	fi

	# 活跃 swapfile 的 inode 带 S_SWAPFILE，内核拒绝 unlink（ETXTBSY），-delete 删不掉，
	# 随后的硬复查会把它当成残留并中止 —— 而此时盘已经抹空。先全部关掉。
	if command -v swapoff >/dev/null 2>&1; then
		swapoff -a 2>/dev/null || true
	fi

	# 目录也可能被 chattr +i（只处理 -type f 会让整个旧 /root/.ssh、/etc/ld.so.preload
	# 子树在新系统里存活），所以目录和文件都要清不可变位。
	# 注意这里是 AND 语义（\( expr \) -exec），不是 -o：写成 -o 会变成
	# "排除表达式为假才执行"，正好作用在要保留的路径上（旧版本的真 bug）
	# 附件属性 +a（append-only）同样会阻止 unlink，只清 -i 不够
	if command -v chattr >/dev/null 2>&1; then
		find / -xdev \( "${expr[@]}" \) -exec chattr -i -a {} + 2>/dev/null || true
	fi

	# 先缓存挂载点：删除一结束 /usr/bin/findmnt 就没了，复查阶段再调会静默返回空，
	# 于是 /boot/efi 这类挂载点被当成「残留旧文件」误报硬失败（真机 AWS 上踩到）。
	WIPE_MOUNTS=()
	local _m=""
	while IFS= read -r _m; do
		[ -n "$_m" ] || continue
		[ "$_m" = "/" ] && continue
		WIPE_MOUNTS+=("$_m")
	done < <(findmnt -rno TARGET 2>/dev/null || true)

	# -xdev：不跨越挂载点，避免连带抹掉独立 /boot/efi、数据盘或 NFS
	# 先停写盘服务再删，避免 journald 竞态重建 /var/log/journal
	stop_disk_writers
	local attempt
	for attempt in 1 2 3; do
		find / -xdev \( "${expr[@]}" \) -delete 2>/dev/null
		sync 2>/dev/null || true
		[ -z "$(wipe_leftovers)" ] && break
		[ "$attempt" -lt 3 ] && echo "删除后仍有残留，第 $attempt 轮清理（可能是写盘进程竞态），重试..."
	done

	# 复查：expr 为真 = 未被排除的路径。祖先目录（如 /tmp，因为 $work_dir 在其下）
	# 会残留且删不掉，属于正常现象，过滤掉。
	#
	# 残留按位置分流，避免「静默把旧文件带进新系统」：
	#  - 安全敏感位置（/etc /usr /root /home /bin /sbin /lib* /boot /opt /srv，以及
	#    cron 与 systemd/dpkg 状态目录）残留 = 攻击者的持久化（ld.so.preload、cron、
	#    SUID、systemd unit、authorized_keys）会跟着活下来 → 默认硬失败，必须显式
	#    ALLOW_DIRTY_WIPE=1 才继续；
	#  - 其它位置（/var/log 之类）只告警继续：抹盘已经开始，err 退出只会留下一台
	#    删空一半又没有引导的机器（真实 VPS 上就是这么卡死的）。
	local -a leftovers=()
	mapfile -t leftovers < <(wipe_leftovers)
	local p
	local -a sensitive=()
	if [ "${#leftovers[@]}" -gt 0 ]; then
		echo "警告：删除后仍有 ${#leftovers[@]} 处残留，逐个检查："
		for p in "${leftovers[@]}"; do
			if [ -d "$p" ] && [ ! -L "$p" ] &&
				[ -z "$("$busybox_path" find "$p" -mindepth 1 -print -quit 2>/dev/null)" ]; then
				echo "  $p（空目录，无害）"
			elif wipe_leftover_is_mount_only_dir "$p"; then
				echo "  $p（只剩下保持不变的挂载点，无害）"
			elif wipe_leftover_is_sensitive "$p"; then
				echo "  $p（安全敏感位置！$("$busybox_path" ls -ld "$p" 2>&1)）"
				sensitive+=("$p")
			else
				echo "  $p（非安全敏感位置，$("$busybox_path" ls -ld "$p" 2>&1)）"
			fi
		done
		if [ "${#sensitive[@]}" -gt 0 ]; then
			[ "${ALLOW_DIRTY_WIPE:-0}" -eq 1 ] || err "删除旧系统未完成，这些安全敏感位置仍有旧文件：${sensitive[*]}。旧 /etc /usr /root 里的 ld.so.preload、cron、SUID、systemd unit、authorized_keys 会被新系统继承，等于把持久化带过去。默认中止（盘已抹空，进救援系统用 ALLOW_DIRTY_WIPE=1 重跑 --resume-partial 可强制继续）。"
			echo "警告：ALLOW_DIRTY_WIPE=1，忽略上述敏感残留继续；重装完成后务必人工清理这些路径。"
		fi
	fi

	echo "旧系统文件已清空"
}

# 把后续所有输出同时写到新系统的 /var/log/reinstall.log：
# 抹盘之后的所有报错都只会出现在屏幕上，VPS 面板关掉窗口就再也看不到了。
# 只能在新 rootfs 解压之后调用（此前 /usr/bin/tee 已被删除）。
enable_logging() {
	[ -d /var/log ] || return 0
	command -v tee >/dev/null 2>&1 || return 0
	[ ! -L /var/log/reinstall.log ] || err "日志文件不能是符号链接"
	(umask 077; : >>/var/log/reinstall.log) || return 0
	chmod 600 /var/log/reinstall.log || err "无法限制日志文件权限"
	# 保存原输出，随机口令只发往控制台，不进入持久日志。
	exec {reinstall_console_fd}>&1
	exec > >(tee -a /var/log/reinstall.log) 2>&1
	echo "=== 重装日志开始：$(date -u '+%Y-%m-%dT%H:%M:%SZ') ==="
	return 0
}

extract_image() {
	# 校验与解压之间隔着一次人工确认（可能几分钟），期间文件可被替换。
	# 解压前再算一次，把 TOCTOU 窗口压到最小。
	if [ -n "$verified_image_sha256" ]; then
		# 此时系统的 sha256sum/awk 都已被删除，只能用 busybox 静态二进制 + 纯内建展开
		local rehash=""
		rehash="$("$busybox_path" sha256sum "${root_dir}/os.tar.xz" 2>/dev/null)"
		rehash="${rehash%% *}"
		[ "$rehash" = "$verified_image_sha256" ] ||
			err "解压前复核发现镜像文件已改变（期望 $verified_image_sha256，实际 $rehash），已中止"
	fi

	echo "开始解压系统镜像..."
	cd "$root_dir" || err "无法进入 $root_dir"
	# 已开启 pipefail：xz 截断或 tar 失败都会反映到整条管道的退出码
	"$busybox_path" xzcat "$root_dir/os.tar.xz" | "$busybox_path" tar -x -C / || err "解压系统镜像失败，当前系统已不可引导，请从救援系统重试"

	# 解压后必须复核关键路径：归档先通过 preflight 才删盘，但解压本身仍可能
	# 因磁盘满/权限导致部分失败，此时若继续 apt/grub 会得到无法引导的系统
	[ -x /bin/sh ] || err "解压后缺少可执行的 /bin/sh，镜像不完整"
	[ -s /etc/passwd ] || err "解压后 /etc/passwd 为空或缺失，镜像不完整"
	[ -x /usr/bin/dpkg ] || err "解压后缺少 /usr/bin/dpkg，镜像不是 Debian/Ubuntu 系统"

	# 抹盘前预下载的 .deb 搬进新系统的 apt 缓存目录：网络正常时 apt 直接复用本地包，
	# 网络断了还能 dpkg -i 装上内核。必须在 apt 之前做。
	if [ -n "${offline_stage_dir:-}" ] && [ -d "$offline_stage_dir" ] && ls "$offline_stage_dir"/*.deb >/dev/null 2>&1; then
		mkdir -p /var/cache/apt/archives
		cp -f "$offline_stage_dir"/*.deb /var/cache/apt/archives/ 2>/dev/null || true
		echo "已把 $(find /var/cache/apt/archives -maxdepth 1 -name '*.deb' 2>/dev/null | wc -l) 个预下载包放入新系统 apt 缓存"
	fi

	# 不再把旧机的 /etc/fstab 整份搬进新系统：旧机的 UUID、分区布局、挂载选项
	# 与刚解压的 rootfs 无关，套用会让新系统起不来。只保留参考副本，并按当前根设备
	# 生成最小 fstab（fstab 缺失不影响 root 挂载，但 systemd 会为此报警）
	write_minimal_fstab

	enable_logging

	[ -f "${root_dir}/resolv.conf.bak" ] && cp "${root_dir}/resolv.conf.bak" /etc/resolv.conf.old

	# 云镜像自带 cloud-init。真 VPS 上有 metadata 源，首次启动它会重新生成网络
	# 配置、执行 disable_root（锁死 root SSH）、覆盖 authorized_keys —— 直接就失联。
	# 而本文档场景根本不需要 cloud-init，直接停掉，最省事也最安全。
	disable_cloud_init

	restore_reinstall_backup
	return 0
}

# cloud-init 在首次启动时有最高优先级：它会把我们刚写的网络/SSH 配置改回去。
# 用 cloud-init.disabled 标记文件停用（官方支持的开关），并清掉残留的 datasource。
disable_cloud_init() {
	[ -d /etc/cloud ] || return 0
	touch /etc/cloud/cloud-init.disabled 2>/dev/null || true
	mkdir -p /etc/cloud/cloud.cfg.d 2>/dev/null || true
	cat >/etc/cloud/cloud.cfg.d/99-reinstall-lockdown.cfg <<'EOF'
# 由 ReinstallDebianUbuntu.sh 写入：禁止 cloud-init 改写本机配置
disable_root: false
ssh_pwauth: true
network:
  config: disabled
EOF
	rm -rf /var/lib/cloud/instances /var/lib/cloud/instance 2>/dev/null || true
	echo "已停用 cloud-init（/etc/cloud/cloud-init.disabled），避免首启覆盖网络与 SSH 配置"
	return 0
}

write_minimal_fstab() {
	local src_file="${root_dir}/root.dev.src"
	local dev="" fstype="" uuid="" opts="defaults" line=""

	# 只用 bash 内建读取：这段代码跑在抹盘之后，/usr/bin/awk、head、tr 是否还能用
	# 取决于新镜像解压完整度（解压异常时它们可能还没就位），不能用外部命令做前置判断。
	if [ -s "$src_file" ]; then
		read -r dev fstype _ <"$src_file" || true
	fi

	# 用 UUID 而不是 /dev/sdX：设备名在换盘/换接口后会变。
	# 优先用抹盘前就记下的值（此时新镜像里还没有 blkid）
	if [ -s "${root_dir}/root.uuid.src" ]; then
		IFS= read -r uuid <"${root_dir}/root.uuid.src" || true
	fi
	if [ -z "$uuid" ] && [ -n "$dev" ] && [ -b "$dev" ] && command -v blkid >/dev/null 2>&1; then
		uuid="$(blkid -s UUID -o value "$dev" 2>/dev/null)"
	fi

	# btrfs 不要猜子卷名：根可能是顶层卷（没有 @），写死 subvol=/@ 会让开机
	# remount 根失败。抹盘前记下的 OPTIONS 里有真实 subvol= 才用它。
	if [ "$fstype" = "btrfs" ]; then
		local subvol=""
		if [ -s "${root_dir}/root.subvol.src" ]; then
			IFS= read -r subvol <"${root_dir}/root.subvol.src" || true
		fi
		[ -n "$subvol" ] && opts="defaults,subvol=$subvol"
	fi

	# xfs 不支持 fsck 的 5 阶段，pass 必须写 0；写成 1 会让开机卡在 fsck 阶段
	local pass="1"
	[ "$fstype" = "xfs" ] && pass="0"
	[ "$fstype" = "btrfs" ] && pass="0"

	if [ -n "$uuid" ]; then
		line="UUID=$uuid / $fstype $opts 0 $pass"
	else
		# 拿不到 UUID 就不写 root 行：内核对 root= 参数已能挂载，写错反而更糟
		echo "警告：无法确定根文件系统 UUID，写入空 fstab（不影响启动）"
	fi

	# 旧机 fstab 随 $root_dir 一起会被 finalize_install 删掉，先搬到新系统留档
	if [ -f "${root_dir}/fstab.old.reinstall" ]; then
		cp "${root_dir}/fstab.old.reinstall" /etc/fstab.old.reinstall 2>/dev/null ||
			echo "警告：无法留档旧 fstab" >&2
	fi

	# /boot 独立保留时（EFI + 独立 /boot，或 /boot 本身是 ESP），必须写进 fstab：
	# 不写则开机不挂载 /boot，内核升级时装到根分区的 /boot 目录，
	# 而 GRUB 仍在独立分区的 /boot/grub 里找内核 —— 下次重启直接起不来。
	local boot_line=""
	if [ -s "${root_dir}/boot.dev.src" ]; then
		local boot_src="" boot_fs="" boot_uuid=""
		read -r boot_src boot_fs <"${root_dir}/boot.dev.src" || true
		[ -s "${root_dir}/boot.uuid.src" ] && IFS= read -r boot_uuid <"${root_dir}/boot.uuid.src" || true
		local boot_pass="1"
		[ "$boot_fs" = "xfs" ] && boot_pass="0"
		if [ -n "$boot_uuid" ]; then
			boot_line="UUID=$boot_uuid /boot ${boot_fs:-ext4} defaults 0 $boot_pass"
		elif [ -n "$boot_src" ]; then
			boot_line="$boot_src /boot ${boot_fs:-ext4} defaults 0 $boot_pass"
		fi
		[ -n "$boot_line" ] && echo "独立的 /boot 已写入 fstab：$boot_line"
	fi

	# EFI 系统必须把 ESP 写进 fstab：不写的话 /boot/efi 开机不会挂载，
	# 之后每次内核升级 update-grub 都会因为找不到 ESP 而失败，
	# 且 `grub-install` 会认为没有 EFI 目录 —— 积累下来就是下次升级引导炸掉。
	local esp_line=""
	if [ "${IS_EFI:-0}" -eq 1 ]; then
		local esp_dir=""
		if [ -s "${root_dir}/esp.src" ]; then
			IFS= read -r esp_dir <"${root_dir}/esp.src" || true
		fi
		[ -n "$esp_dir" ] || esp_dir="/boot/efi"
		local esp_src="" esp_uuid="" esp_fs=""
		if findmnt -rno SOURCE,FSTYPE "$esp_dir" >/dev/null 2>&1; then
			read -r esp_src esp_fs < <(findmnt -rno SOURCE,FSTYPE "$esp_dir" 2>/dev/null | head -1) || true
			esp_uuid="$(findmnt -rno UUID "$esp_dir" 2>/dev/null | head -1)"
			if [ -n "$esp_uuid" ]; then
				esp_line="UUID=$esp_uuid $esp_dir ${esp_fs:-vfat} defaults 0 1"
			elif [ -n "$esp_src" ]; then
				esp_line="$esp_src $esp_dir ${esp_fs:-vfat} defaults 0 1"
			fi
		fi
		[ -n "$esp_line" ] && echo "ESP 已写入 fstab：$esp_dir" ||
			echo "警告：未能确定 ESP 的 UUID，fstab 中缺少 ${esp_dir} 条目（内核升级时可能报错）"
	fi

	# 末尾必须显式成功：复合命令的退出码取最后一条，line 为空时
	# `[ -n "$line" ] && echo` 返回 1，会让 `|| err` 把一个写入成功的 fstab 判成失败
	{
		echo "# 由 reinstall 脚本生成：仅包含当前根文件系统。"
		echo "# 旧机 fstab 备份见 /etc/fstab.old.reinstall，需要额外挂载请手工迁移。"
		if [ -n "$line" ]; then
			echo "$line"
		fi
		if [ -n "$boot_line" ]; then
			echo "$boot_line"
		fi
		if [ -n "$esp_line" ]; then
			echo "$esp_line"
		fi
		true
	} >/etc/fstab || err "无法写入 /etc/fstab"
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
			echo "https://deb.debian.org/debian"
		else
			echo "https://archive.ubuntu.com/ubuntu"
		fi
	fi
}

write_apt_sources() {
	local mirror_url="$1"
	local codename="$2"

	: >/etc/apt/sources.list

	if [ "$system" = "debian" ]; then
		local components="main contrib non-free"
		[[ "$codename" == "bookworm" || "$codename" == "trixie" || "$codename" == "forky" ]] && components="main contrib non-free non-free-firmware"

		cat >>/etc/apt/sources.list <<EOF
deb $mirror_url $codename $components
deb $mirror_url $codename-updates $components
deb $mirror_url $codename-backports $components
deb https://security.debian.org/debian-security $codename-security $components
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

enable_unit_offline() {
	local unit="$1"
	# --root=/ 直接操作新系统的 unit 文件，不去 dbus 上找还活着的老 systemd
	if systemctl --root=/ enable "$unit" >/dev/null 2>&1; then
		echo "已启用 $unit"
		return 0
	fi
	# 回落分支会去问还活着的老 systemd，对新系统无效，只是尽人事
	if systemctl enable "$unit" >/dev/null 2>&1; then
		echo "警告：已通过运行中的 systemd 启用 $unit（--root 方式失败，重启后需确认）"
		return 0
	fi
	echo "警告：无法启用 $unit，请重启后手动检查"
	return 1
}

sshd_bin_path() {
	# 已 wiped 的系统上 PATH 未必含 /usr/sbin，`command -v sshd` 会判未安装。
	# 自检链路必须用绝对路径探测，否则整个校验会被静默跳过。
	local b
	for b in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do
		if [ -x "$b" ]; then
			printf '%s' "$b"
			return 0
		fi
	done
	return 1
}

sshd_directive_supported() {
	# $1 = sshd 绝对路径，$2 = 完整指令行（如 "UseDNS no"）。
	# 用只含 Port + 该指令的临时配置做解析，能通过才算本机 OpenSSH 支持。
	# 目的：GSSAPIAuthentication / UseDNS 这类选项在版本间被增删，
	# 写进 drop-in 后会让 sshd 整体起不来，等于重启后把机器锁在门外。
	local tf="" rc=0
	tf="$(mktemp)" || return 1
	printf 'Port 22\n%s\n' "$2" >"$tf"
	"$1" -T -f "$tf" >/dev/null 2>&1
	rc=$?
	rm -f "$tf"
	[ "$rc" -eq 0 ]
}

write_sshd_dropin() {
	local dropin_dir="/etc/ssh/sshd_config.d"
	local dropin="${dropin_dir}/00-reinstall.conf"
	local tmp=""

	mkdir -p "$dropin_dir"

	# sshd 是「第一次出现的值生效」，所以 Include 不仅要存在，还必须在任何
	# Port/PasswordAuthentication 之类之前出现，否则主文件里的旧值会赢。
	# 用 awk 判断：第一个非注释、非空白行就应该是这条 Include。
	if ! awk '
		/^[[:space:]]*(#|$)/ { next }
		{ if ($0 ~ /^[[:space:]]*Include[[:space:]]+\/etc\/ssh\/sshd_config\.d\/\*\.conf/) found = 1; exit }
		END { exit(found ? 0 : 1) }
	' /etc/ssh/sshd_config; then
		tmp="$(mktemp)"
		printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >"$tmp"
		cat /etc/ssh/sshd_config >>"$tmp"
		cat "$tmp" >/etc/ssh/sshd_config
		rm -f "$tmp"
	fi

	# sshd 对同一关键字取"第一次出现的值"，00- 前缀保证胜过云镜像自带的 50-/60- 配置。
	# 只写三条各版本都存在的核心指令；其余可选加固逐条探测后再追加。
	{
		echo "# 由重装脚本生成，优先级高于镜像自带的 sshd_config.d/*.conf"
		if [ -n "$ssh_port" ]; then
			echo "Port $ssh_port"
		fi
		echo "PermitRootLogin $sshd_policy_permit_root"
		echo "PasswordAuthentication $sshd_policy_password_auth"
	} >"$dropin"

	local sshd_bin="" opt=""
	if sshd_bin="$(sshd_bin_path)"; then
		for opt in "MaxAuthTries 3" "GSSAPIAuthentication no" "ClientAliveInterval 60" "UseDNS no"; do
			if sshd_directive_supported "$sshd_bin" "$opt"; then
				echo "$opt" >>"$dropin"
			else
				echo "提示：本机 sshd 不支持 ${opt%% *}，未写入 00-reinstall.conf"
			fi
		done
	else
		echo "警告：未找到 sshd 可执行文件，跳过硬化的可选指令（只写 Port/PermitRootLogin/PasswordAuthentication）"
	fi
	chmod 0644 "$dropin"

	# 兜底：逐条探测仍有漏网（或 sshd -T 因其它原因失败）时，直接用整份配置验证，
	# 只删除它明确拒绝的选项。用绝对路径调用，避免 PATH 差异导致整段被跳过。
	mkdir -p /run/sshd 2>/dev/null || true
	if [ -n "$sshd_bin" ]; then
		local tries=0 out="" bad=""
		while [ "$tries" -lt 8 ]; do
			tries=$((tries + 1))
			"$sshd_bin" -T -f /etc/ssh/sshd_config >/dev/null 2>&1 && break
			out="$("$sshd_bin" -T -f /etc/ssh/sshd_config 2>&1 || true)"
			bad="$(printf '%s\n' "$out" | sed -n 's/.*Unsupported option \([A-Za-z0-9]*\).*/\1/p' | head -n 1)"
			if [ -z "$bad" ]; then
				# 报错里没有选项名（缺 hostkey、缺权限分离目录、语法错…）时无法定向删除。
				# 第一轮先退到"只保留核心三条"，把不兼容选项一次性清掉再验。
				if [ "$tries" -eq 1 ]; then
					sed -i -e '/^MaxAuthTries[[:space:]]/d' -e '/^GSSAPIAuthentication[[:space:]]/d' \
						-e '/^ClientAliveInterval[[:space:]]/d' -e '/^UseDNS[[:space:]]/d' "$dropin"
					continue
				fi
				echo "警告：sshd 配置自检仍未通过：$(printf '%s\n' "$out" | head -n 1)"
				break
			fi
			echo "提示：本机 sshd 不支持 $bad，已从 00-reinstall.conf 移除"
			sed -i "/^${bad}[[:space:]]/d" "$dropin"
		done
	fi
}

configure_ssh() {
	echo "配置 SSH 服务..."

	if [ ! -f "/etc/ssh/sshd_config" ]; then
		echo "警告：/etc/ssh/sshd_config 未找到，SSH 可能无法启动"
		return 0
	fi

	# 主文件同步修改一次，兼容没有 Include 目录的旧镜像
	grep -q "^Port " /etc/ssh/sshd_config || echo "Port 22" >>/etc/ssh/sshd_config

	if [ -n "$ssh_port" ]; then
		sed -i "s/^Port .*/Port $ssh_port/" /etc/ssh/sshd_config
	else
		sed -i "s/^Port .*/Port 22/" /etc/ssh/sshd_config
	fi

	write_sshd_dropin

	# Ubuntu 22.10+ 默认用 ssh.socket 触发，sshd_config 里的 Port 会被忽略
	if { [ -f /lib/systemd/system/ssh.socket ] || [ -f /usr/lib/systemd/system/ssh.socket ]; } && [ -n "$ssh_port" ] && [ "$ssh_port" != "22" ]; then
		echo "检测到 ssh.socket 套接字激活，关闭以确保 --ssh-port 生效"
		# disable 只是去掉 wants 链接，ssh.service 的 Also=ssh.socket 还会把它带回来；
		# 这里直接 mask，避免重启后实际监听 22 端口
		systemctl --root=/ disable ssh.socket >/dev/null 2>&1 || true
		systemctl --root=/ mask ssh.socket >/dev/null 2>&1 || true
		rm -f /etc/systemd/system/sockets.target.wants/ssh.socket
	fi

	enable_unit_offline ssh.service || err "无法启用 ssh.service，重启后将无法通过 SSH 登录"
}

generate_password() {
	local pw=""
	# 注意：字符集里不能出现 "-"，否则 "x-y" 会被 tr 当成区间（"_-@" 是反向区间，直接报错）
	pw="$(LC_ALL=C tr -dc 'A-Za-z0-9._@#%+=' </dev/urandom 2>/dev/null | head -c 20)" || true
	if [ -z "$pw" ]; then
		pw="$(openssl rand -hex 12 2>/dev/null)" || true
	fi
	[ -n "$pw" ] || err "无法生成随机密码"
	printf '%s' "$pw"
}

resolve_password_source() {
	if [ -n "$password_file" ]; then
		# root 用 head 读任意路径：不让符号链接把读取目标换成别处，
		# 也不接受属主/权限宽松的文件（同机用户可预先写入新 root 口令）
		[ -f "$password_file" ] && [ ! -L "$password_file" ] || err "密码文件必须是不经符号链接的普通文件：$password_file"
		[ -r "$password_file" ] || err "无法读取密码文件：$password_file"
		local pf_owner pf_mode
		pf_owner="$(stat -c %u "$password_file" 2>/dev/null)"
		pf_mode="$(stat -c %a "$password_file" 2>/dev/null)"
		if [ "$pf_owner" != "0" ] || { [ -n "$pf_mode" ] && [ "${pf_mode: -1}" != "0" ] && [ "${pf_mode: -2}" != "00" ]; }; then
			echo "警告：密码文件属主非 root 或权限对其他人可读（owner=$pf_owner mode=$pf_mode），同机用户可能已看到新 root 口令" >&2
		fi
		password="$(head -n 1 "$password_file" | tr -d '\r\n')"
	elif [ "$password_stdin" -eq 1 ]; then
		read -rs password || err "无法从标准输入读取密码"
		echo
	fi

	[ -n "$password" ] && final_password="$password"
}

configure_root_password() {
	local generated=0

	echo "设置 root 用户密码..."

	# 不再回落到任何公开的默认口令
	if [ -z "$final_password" ]; then
		# 命令替换里的 err 只会退出子 shell，必须在这里再判一次：
		# 否则空口令会一路走到 passwd，重启后 root 无口令可登（或 PAM 拒登）
		final_password="$(generate_password)" || err "生成随机 root 密码失败"
		[ -n "$final_password" ] || err "生成的 root 密码为空，拒绝继续"
		generated=1
	fi

	# printf 而非 echo -e：echo 会解释反斜杠并改写口令本身
	if printf '%s\n%s\n' "$final_password" "$final_password" | passwd root >/dev/null 2>&1; then
		echo "root 密码已设置"
	else
		# 口令没设上是「重启后进不去」的等级，不能只告警
		err "passwd 执行失败，root 密码未设置。已中止（当前系统已解压，请勿重启，先手工修复）"
	fi

	if [ "$generated" -eq 1 ]; then
		echo "=================================================="
		echo "已生成随机 root 密码：$final_password" >&"${reinstall_console_fd:-1}"
		echo "此口令只显示这一次，请立即记录"
		echo "=================================================="
	elif [ "$final_password" = "blog.ylx.me" ]; then
		echo "警告：root 密码使用了公开的旧默认值 'blog.ylx.me'，请立即更改！"
	fi
}

configure_authorized_keys() {
	[ -z "$authorized_keys_url" ] && return 0

	local key_tmp="${work_dir}/authorized_keys"

	echo "从 $authorized_keys_url 下载 SSH 公钥..."
	mkdir -p /root/.ssh
	chmod 700 /root/.ssh

	if ! curl "${CURL_TLS_OPTS[@]}" -sSLf --connect-timeout 10 --max-time 20 --max-filesize 65536 \
		"$authorized_keys_url" -o "$key_tmp"; then
		echo "警告：无法下载 SSH 公钥：$authorized_keys_url（保留密码登录）"
		return 0
	fi

	# 只保留能通过 ssh-keygen 解析的行。"类型前缀 + AAAA" 的 grep 挡不住
	# 'ssh-ed25519 AAAA' 这种残废公钥：它会通过正则，然后在关掉密码登录后
	# 让 sshd 一个密钥都认不出 —— 重启即锁死，只能控制台救援。
	local valid_tmp="${work_dir}/authorized_keys.valid"
	: >"$valid_tmp"
	local line="" kept=0
	while IFS= read -r line || [ -n "$line" ]; do
		# 去掉 CR（Windows 换行会让密钥永远匹配不上）
		line="${line%$'\r'}"
		case "$line" in
		'' | '#'*) continue ;;
		esac
		printf '%s\n' "$line" >"${work_dir}/k.one"
		if command -v ssh-keygen >/dev/null 2>&1; then
			ssh-keygen -l -f "${work_dir}/k.one" >/dev/null 2>&1 || continue
		else
			printf '%s\n' "$line" | grep -qE '^(ssh-(rsa|ed25519)|ecdsa-sha2-nistp[0-9]+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)[[:space:]]+AAAA' || continue
		fi
		printf '%s\n' "$line" >>"$valid_tmp"
		kept=$((kept + 1))
	done <"$key_tmp"
	rm -f "${work_dir}/k.one"

	if [ "$kept" -eq 0 ]; then
		echo "警告：下载内容中没有可用的 SSH 公钥，已忽略并保留密码登录"
		return 0
	fi

	install -m 0600 -o root -g root "$valid_tmp" /root/.ssh/authorized_keys || {
		echo "警告：无法安装 authorized_keys，保留密码登录"
		return 0
	}

	# 装完再验一次：install 成功不等于文件内容能被 sshd 用
	if command -v ssh-keygen >/dev/null 2>&1; then
		ssh-keygen -l -f /root/.ssh/authorized_keys >/dev/null 2>&1 || {
			echo "警告：authorized_keys 安装后仍无法解析，保留密码登录"
			rm -f /root/.ssh/authorized_keys
			return 0
		}
	fi

	echo "SSH 公钥配置完成（$kept 个密钥）"

	# 只有公钥确实可用时，才收紧为仅公钥登录
	sshd_policy_password_auth="no"
	sshd_policy_permit_root="prohibit-password"
	write_sshd_dropin
	sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config || true
	echo "已关闭 SSH 密码登录，root 仅允许公钥登录"
}

write_network_interfaces() {
	if [ -d /etc/netplan ] && ls /etc/netplan/*.yaml >/dev/null 2>&1; then
		# 备份而不是直接删：netplan 是镜像自带的唯一可用网络配置，
		# 一旦 ifupdown 没起来，这是最后一份能手工恢复的参照
		mkdir -p /etc/netplan.reinstall-backup
		cp -a /etc/netplan/*.yaml /etc/netplan.reinstall-backup/ 2>/dev/null || true
		rm -f /etc/netplan/*.yaml
		echo "已备份并移除 Netplan 配置以确保 ifupdown 生效（备份：/etc/netplan.reinstall-backup/）"
	fi

	# 网卡命名：新系统带 net.ifnames=0，单网卡一定是 eth0；多网卡时枚举顺序
	# 不保证，所以用 systemd .link 按 MAC 把「现在承载默认路由的那块」钉成 eth0。
	# 不写死 PCI 路径，换插槽、换虚机重建都能继续命中。
	mkdir -p /etc/systemd/network
	if [ -n "$primary_nic_mac" ] && [ "${nic_count:-0}" -gt 1 ]; then
		cat >/etc/systemd/network/10-reinstall-eth0.link <<EOF
[Match]
MACAddress=$primary_nic_mac

[Link]
Name=$network_adapter
EOF
		echo "已按 MAC $primary_nic_mac 把主网卡固定为 $network_adapter（共 $nic_count 块网卡）"
	elif [ "${nic_count:-0}" -le 1 ]; then
		echo "只有一块网卡，net.ifnames=0 下必然是 $network_adapter，无需 MAC 绑定"
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

		# IPv6：原系统是静态（地址没有 dynamic 标记）就照抄全部地址/网关/路由；
		# 是 RA/SLAAC 自动拿到的就写 auto，让它自己再要一份 —— 写死会在提供商
		# 换前缀后失效，反而制造「IPv4 通、IPv6 不通」的难查故障。
		if [ "${#ipv6_addrs[@]}" -gt 0 ] && [ "$ipv6_dynamic" -eq 0 ]; then
			local first6="${ipv6_addrs[0]}" extra6="" route6=""
			{
				echo "iface $network_adapter inet6 static"
				echo "    address ${first6%%/*}"
				echo "    netmask ${first6##*/}"
				if [ -n "$ipv6_gw" ]; then echo "    gateway $ipv6_gw"; fi
				for extra6 in "${ipv6_addrs[@]:1}"; do
					echo "    up ip -6 addr add $extra6 dev $network_adapter"
				done
				for route6 in "${ipv6_routes[@]}"; do
					echo "    up ip -6 route add $route6 dev $network_adapter"
				done
			} >>/etc/network/interfaces
			echo "已写入静态 IPv6：${ipv6_addrs[*]}（网关 ${ipv6_gw:-无}，额外路由 ${#ipv6_routes[@]} 条）"
		elif [ "${#ipv6_addrs[@]}" -gt 0 ] && [ "$ipv6_dynamic" -eq 1 ]; then
			# 静态 IPv4 + 自动获得的 IPv6（RA/SLAAC）：照旧要一份，别把 IPv6 丢掉
			echo "iface $network_adapter inet6 auto" >>/etc/network/interfaces
			echo "IPv6 仍沿用自动获取（RA/SLAAC）：${ipv6_addrs[*]}"
		elif [ "$use_native_ipv6" -eq 1 ]; then
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
EOF

		# 只有原系统确有全局 IPv6 时才写 IPv6 段，且用 auto（SLAAC）而不是 dhcp：
		#  1) 没有 IPv6 服务器时 dhclient -6 会一直发 Solicit，ifup -a 被
		#     networking.service 的 TimeoutStartSec 超时 kill，服务变 failed；
		#  2) SLAAC 不等待响应，即使局域没有 RA 也不会卡住启动。
		# 实测（VMware NAT）：只写 inet dhcp 时 networking.service=active。
		if [ "$has_ipv6" -eq 1 ]; then
			cat >>/etc/network/interfaces <<EOF
iface $network_adapter inet6 auto
EOF
		fi
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

	# DHCP 身份延续：提供商那份「按 client-id / DUID 绑定」的租约还能命中同一地址。
	# 不写这段时，新系统用 MAC 派生的默认 client-id —— 多数情况等价，
	# 但用过自定义 client-id / dhcpcd DUID 的机器换客户端后会拿到另一个 IP。
	if [ -n "$dhcp_client_id" ]; then
		mkdir -p /etc/dhcp
		{
			echo "# 由 ReinstallDebianUbuntu.sh 写入：沿用重装前系统的 DHCP client-id"
			echo "send dhcp-client-identifier $dhcp_client_id;"
		} >/etc/dhcp/dhclient.conf
		echo "已写入 DHCP client-id：$dhcp_client_id"
	fi
	if [ -n "$dhcp6_client_id" ]; then
		mkdir -p /etc/dhcp
		{
			echo "# 由 ReinstallDebianUbuntu.sh 写入：沿用重装前系统的 DHCPv6 DUID"
			echo "send dhcp6.client-id $dhcp6_client_id;"
		} >/etc/dhcp/dhclient6.conf
		echo "已写入 DHCPv6 DUID：$dhcp6_client_id"
	fi
}

# 内核选型。实测：Debian 的 linux-image-cloud-amd64 里根本没有 ahci.ko / nvme.ko，
# 只有 virtio_blk —— 那是给云厂商纯 virtio 环境裁的。装到 SATA/AHCI 或 NVMe
# 机器（含 VMware/VirtualBox/绝大多数独立服务器）上，initramfs 找不到根设备，
# 开机会掉进救援 shell：ALERT! UUID=... does not exist. Dropping to a shell!
# 所以默认按抹盘前探测到的根磁盘驱动自动选，操作者不用关心。
#
# 结果写进全局 kernel_pkg，main() 里会提前调用一次
# 用于 dry-run 摘要，install_base_packages 再调用一次拿实际包名。
resolve_kernel_packages() {
	local flavor="$kernel_flavor"
	local root_driver=""
	if [ -s "${root_dir}/root.driver.src" ]; then
		while IFS='=' read -r k v; do
			[ "$k" = "driver" ] && root_driver="$v"
		done <"${root_dir}/root.driver.src"
	fi
	# 抹盘前（dry-run 摘要）root.driver.src 还没生成，用实时探测的结果
	[ -n "$root_driver" ] || root_driver="${detected_root_driver:-}"

	if [ "$flavor" = "auto" ]; then
		case "$root_driver" in
		virtio_blk | virtio_scsi) flavor="cloud" ;;
		*) flavor="generic" ;;
		esac
	fi
	case "$flavor:$system:$arch" in
	cloud:debian:x86_64) kernel_pkg="linux-image-cloud-amd64" ;;
	cloud:debian:aarch64) kernel_pkg="linux-image-cloud-arm64" ;;
	cloud:ubuntu:x86_64 | cloud:ubuntu:aarch64) kernel_pkg="linux-image-virtual" ;;
	generic:debian:x86_64) kernel_pkg="linux-image-amd64" ;;
	generic:debian:aarch64) kernel_pkg="linux-image-arm64" ;;
	generic:ubuntu:x86_64 | generic:ubuntu:aarch64) kernel_pkg="linux-image-generic" ;;
	*) err "未知系统/架构组合：$system/$arch" ;;
	esac

	# 只打印一次结论，避免 dry-run 摘要与安装阶段重复刷屏
	if [ "${kernel_pkg_logged:-0}" -ne 1 ]; then
		case "$flavor" in
		cloud) echo "内核选择：根磁盘走 ${root_driver:-virtio}，使用精简内核（cloud/virtual）：$kernel_pkg" ;;
		*) [ -n "$root_driver" ] && echo "内核选择：根磁盘走 $root_driver，精简内核不含该驱动，使用通用内核：$kernel_pkg" ||
			echo "内核选择：未能识别根磁盘驱动，保守使用通用内核：$kernel_pkg" ;;
		esac
		kernel_pkg_logged=1
	fi
	return 0
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
	# Debian 14 起 isc-dhcp-client 已从仓库移除。ifupdown 的 dhcp 方法会按
	# dhclient -> udhcpc -> dhcpcd 的顺序去找，装上任意一个都能拿到地址。
	local DHCP_CLIENT="" cand
	for cand in isc-dhcp-client dhcpcd-base udhcpc; do
		if apt-get -s install "$cand" >/dev/null 2>&1; then
			DHCP_CLIENT="$cand"
			break
		fi
	done
	if [ -z "$DHCP_CLIENT" ]; then
		echo "警告：找不到可用的 DHCP 客户端包，DHCP 网络可能无法自动配置"
	fi

	local BASE_PACKAGES="systemd openssh-server passwd wget nano htop net-tools ${DHCP_CLIENT} ifupdown ifmetric ethtool fdisk coreutils curl sudo util-linux gnupg apt-utils tzdata xfsprogs"

	resolve_kernel_packages || err "无法确定内核软件包"
	BASE_PACKAGES="$BASE_PACKAGES $kernel_pkg"

	# 根在 LVM/软 RAID 上时，新系统必须装对应的用户态工具，否则 initramfs
	# 激活不了卷组/阵列 —— 现象同样是开机掉进救援 shell（"ALERT! UUID=... does not exist"）。
	# 这类机器的 / 通常是 /dev/mapper/vg-root 或 /dev/md0，抹盘前记在 root.dev.src 里。
	local root_src_raw="" root_src=""
	if [ -s "${root_dir}/root.dev.src" ]; then
		read -r root_src_raw _ <"${root_dir}/root.dev.src" 2>/dev/null || true
	fi
	root_src="$(readlink -f "${root_src_raw:-}" 2>/dev/null || printf '%s' "${root_src_raw:-}")"
	case "$root_src" in
	/dev/mapper/*)
		BASE_PACKAGES="$BASE_PACKAGES lvm2"
		echo "根文件系统在 LVM（$root_src）上，新系统将安装 lvm2"
		;;
	/dev/md*)
		BASE_PACKAGES="$BASE_PACKAGES mdadm"
		echo "根文件系统在软 RAID（$root_src）上，新系统将安装 mdadm"
		;;
	/dev/dm-*)
		BASE_PACKAGES="$BASE_PACKAGES lvm2"
		echo "根文件系统在 device-mapper（$root_src）上，新系统将安装 lvm2"
		;;
	esac

	if ! apt-get install $APT_OPTS $BASE_PACKAGES; then
		# 索引没取到时 apt 连包名都解析不了。预下载的 .deb 已经把内核+initramfs
		# 装上的话，允许以最小状态继续；sshd 缺失会在 finalize_install 的断言里
		# 被拦住，不会带着"必然失联"的系统重启。
		offline_package_rescue || err "安装软件包失败（内核：$BASE_PACKAGES）"
		echo "警告：软件包未全部安装，系统以最小可用状态继续。重启后请立即执行：apt-get update && apt-get -f install"
	fi
}

# 从旧机 cmdline 继承"看不到就救不回来"的内核参数。
# 云镜像/云主机镜像的 /etc/default/grub 往往是空的，而旧机是在 console=ttyS0,115200
# 下跑的。不继承的话，新系统装完重启就只有 VGA 输出，VPS 面板上既看不到也不可恢复
# ——那是最典型的"装完就失联"场景。只继承白名单，绝不整体搬运（root=/ro/quiet
# 这些必须由新系统自己决定）。
grub_inherit_old_cmdline() {
	local src="${root_dir}/old.cmdline.src" tok kept=""
	[ -s "$src" ] || return 0
	while IFS= read -r tok; do
		[ -n "$tok" ] || continue
		case "$tok" in
		console=* | earlyprintk* | earlycon=* | keep_bootcon | intel_iommu=* | amd_iommu=* | iommu=* | nomodeset | pti=* | mitigations=* | vsyscall=*)
			kept="${kept:+$kept }$tok"
			;;
		esac
	done <"$src"
	if [ -n "$kept" ]; then
		grub_append_cmdline "GRUB_CMDLINE_LINUX" "$kept"
		echo "已从旧机继承内核参数：$kept"
	else
		echo "旧机内核命令行里没有需要继承的参数（console=/iommu 等）"
	fi
	return 0
}

# 往 /etc/default/grub 的某个变量里追加参数，保留原有内容并去重。
# 直接 sed 整体替换会丢掉 console=ttyS0（串口控制台）、iommu 之类设置，
# 抹盘后没有任何面板手段能把它们加回来。
grub_read_literal() {
	local key="$1" file="${2:-/etc/default/grub}" raw=""
	local double='^"([^"\\]*)"[[:space:]]*(#.*)?$' single="^'([^']*)'[[:space:]]*(#.*)?$"
	raw="$(awk -v k="$key" '$0 ~ "^[[:space:]]*" k "=" {v=$0; sub("^[[:space:]]*" k "=", "", v)} END {print v}' "$file")" || return 1
	if [[ "$raw" =~ $single ]]; then
		printf '%s' "${BASH_REMATCH[1]}"
	elif [[ "$raw" =~ $double ]]; then
		local value="${BASH_REMATCH[1]}"
		case "$value" in *'$'* | *'`'*) return 1 ;; esac
		printf '%s' "$value"
	elif [[ "$raw" =~ ^[a-zA-Z0-9_./:=,+-]*$ ]]; then
		printf '%s' "$raw"
	else
		return 1 # 不 eval 动态 shell 配置，也不静默丢掉它
	fi
}

# 生成 POSIX shell 的单引号赋值；内核参数中的 $、引号等不得变成 shell 代码。
grub_literal_assignment() {
	local key="$1" value="$2"
	local quote="'" escaped="'\\''"
	value="${value//"$quote"/"$escaped"}"
	printf "%s='%s'\n" "$key" "$value"
}

grub_append_cmdline() {
	local key="$1" extra="$2" cur="" merged="" tok
	cur="$(grub_read_literal "$key")" || err "$key 含非字面量配置，拒绝猜测或执行它"
	local -a tokens=()
	read -r -a tokens <<<"$extra"
	for tok in "${tokens[@]}"; do
		case " $cur " in
		*" $tok "*) ;;
		*) cur="${cur:+$cur }$tok" ;;
		esac
	done
	merged="$cur"
	local tmp=""
	tmp="$(mktemp /etc/default/.grub.reinstall.XXXXXX)" || err "无法创建 GRUB 配置临时文件"
	awk -v k="$key" '$0 !~ "^[[:space:]]*" k "="' /etc/default/grub >"$tmp" &&
		grub_literal_assignment "$key" "$merged" >>"$tmp" &&
		chmod 644 "$tmp" && mv -f "$tmp" /etc/default/grub || err "写入 GRUB 参数失败"
	echo "内核参数 $key=$merged"
}

# grub-mkconfig 会在 /etc/default/grub 之后读取 *.cfg。保留发行版文件，
# 只把本脚本负责的设置写入本次排序最后的 drop-in，避免后加载配置撤销它们。
write_grub_policy() {
	local dir=/etc/default/grub.d file="" policy="" key="" value=""
	mkdir -p "$dir" || err "无法创建 GRUB 配置目录"
	policy="$dir/zz-reinstall.cfg"
	for file in "$dir"/*.cfg; do
		[ -f "$file" ] || continue
		if [[ "$file" > "$policy" ]]; then
			policy="${file%.cfg}.zz-reinstall.cfg"
		fi
	done
	[ ! -L "$policy" ] || err "GRUB 策略文件不允许是符号链接"
	local tmp=""
	tmp="$(mktemp "$dir/.reinstall.XXXXXX")" || err "无法创建 GRUB 策略临时文件"
	{
		printf '# Managed by ReinstallDebianUbuntu.sh; keep this after vendor drop-ins.\n'
		printf 'GRUB_DEFAULT=0\nGRUB_SAVEDEFAULT=false\nGRUB_TIMEOUT=5\nGRUB_TIMEOUT_STYLE=menu\nGRUB_RECORDFAIL_TIMEOUT=5\nGRUB_DISABLE_OS_PROBER=true\n'
		for key in GRUB_CMDLINE_LINUX GRUB_CMDLINE_LINUX_DEFAULT GRUB_TERMINAL GRUB_SERIAL_COMMAND; do
			value="$(grub_read_literal "$key")" || err "无法读取 $key 的字面值"
			if [ -n "$value" ] || [[ "$key" == GRUB_CMDLINE_* ]]; then
				grub_literal_assignment "$key" "$value" || err "写入 $key 失败"
				if [ "$key" = GRUB_TERMINAL ]; then
					grub_literal_assignment GRUB_TERMINAL_INPUT "$value"
					grub_literal_assignment GRUB_TERMINAL_OUTPUT "$value"
				fi
			fi
		done
	} >"$tmp" || err "写入 GRUB 最终策略失败"
	chmod 644 "$tmp" && mv -f "$tmp" "$policy" || err "保存 GRUB 最终策略失败"

	# grubenv 中 next_entry 优先于 GRUB_DEFAULT；saved_entry/recordfail 也不能继承。
	if [ -e /boot/grub/grubenv ]; then
		grub-editenv /boot/grub/grubenv unset next_entry saved_entry prev_saved_entry recordfail ||
			err "无法清除旧 GRUB 启动状态"
	fi
	echo "GRUB 最终策略：$policy（默认第一个正常引导项，菜单等待 5 秒）"
}

install_grub() {
	echo "安装 GRUB 引导加载程序..."

	# 预置设备，避免 grub-pc 的 debconf 交互在当前环境里挂死
	echo "grub-pc grub-pc/install_devices multiselect $grub_device" | debconf-set-selections 2>/dev/null || true

	# grub2 只是元包，amd64/ppc64el 之外不存在该包名（arm64 必须用显式包）
	if [ "$arch" = "x86_64" ]; then
		apt-get install -y grub2 -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装 GRUB 失败"
	else
		apt-get install -y grub-common grub2-common -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" || err "安装 GRUB 失败（当前架构没有 grub2 元包）"
	fi

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
		# ESP 可能挂在 /efi 而不是 /boot/efi（preflight 两者都放行）。挂错位置
		# 会把 EFI 文件写进根文件系统，重启后没有引导项。挂载点用抹盘前记下的值。
		local efi_dir="/boot/efi"
		if [ -s "${root_dir}/esp.src" ]; then
			IFS= read -r efi_dir <"${root_dir}/esp.src" || true
		fi
		[ -n "$efi_dir" ] || efi_dir="/boot/efi"
		echo "使用 ESP 目录：$efi_dir"
		mkdir -p "$efi_dir"
		# 有些 VPS/虚拟机的 efivarfs 只读（没有真正的 NVRAM），写引导变量会失败，
		# 但引导文件本身照样能装 —— 只是要靠固件默认路径 EFI/BOOT/BOOTX64.EFI 引导。
		# 这种情况用 --no-nvram 重试，并把提示打出来，避免整台机器卡在这一步。
		if ! grub-install --target="$grub_target" --efi-directory="$efi_dir" --bootloader-id="$system" --recheck "$grub_device"; then
			echo "警告：EFI 安装写入 NVRAM 失败（常见于 efivarfs 只读的 VPS），改用 --no-nvram 重试"
			grub-install --target="$grub_target" --efi-directory="$efi_dir" --bootloader-id="$system" --recheck --no-nvram "$grub_device" ||
				err "GRUB EFI 安装失败"
			echo "提示：已使用固件默认引导路径，请确认面板/BIOS 里从 $efi_dir 所在磁盘引导"
		fi

		local efi_file_path="$efi_dir/EFI/$system/grubx64.efi"
		[ "$arch" = "aarch64" ] && efi_file_path="$efi_dir/EFI/$system/grubaa64.efi"

		if [ -f "$efi_file_path" ]; then
			mkdir -p "$efi_dir/EFI/BOOT"
			if [ "$arch" = "x86_64" ]; then
				cp "$efi_file_path" "$efi_dir/EFI/BOOT/BOOTX64.EFI"
			else
				cp "$efi_file_path" "$efi_dir/EFI/BOOT/BOOTAA64.EFI"
			fi
			echo "EFI 引导文件备份成功"
		else
			err "验证失败：未找到 EFI 核心文件 $efi_file_path"
		fi
		;;

	standard)
		echo "执行标准 BIOS 模式安装..."
		[ "$arch" = "x86_64" ] || err "BIOS/legacy 引导仅支持 x86_64"
		grub-install --target=i386-pc --boot-directory=/boot --recheck "$grub_device" || {
			# 自救路径写的是和 force_embed 完全相同的扇区，确认等级必须一致：
			# 否则「第一次失败」就能让操作者绕过 force_embed 的确认闸
			echo "警告：标准安装遇到分区校验阻碍（通常是 Legacy+GPT 且无 BIOS Boot 分区）"
			ask_confirm "需要以 --force 强制嵌入引导代码（会写入 GPT 保护扇区附近并可能破坏分区表），确认继续？" ||
				err "用户取消强制自救。系统已抹除且无引导，请从救援介质重装"
			grub-install --target=i386-pc --boot-directory=/boot --recheck --force "$grub_device" || err "GRUB BIOS 强制自救失败"
		}
		;;

	force_embed)
		echo "执行强制嵌入模式 (适配 Legacy+GPT 无 BIOS Boot 分区)..."
		[ "$arch" = "x86_64" ] || err "BIOS/legacy 引导仅支持 x86_64"
		# 这里的风险确认在 auto_detect_grub_mode 里、抹盘之前就已经做过了。
		# 抹盘后再问一次毫无意义：此时拒绝只会把机器留在"已抹空、无引导"的状态。
		echo "[提示] 强制嵌入已在抹盘前确认，继续执行。"
		grub-install --target=i386-pc --boot-directory=/boot --recheck --force "$grub_device" || err "GRUB 强制嵌入安装失败"
		;;
	esac

	if command -v update-grub >/dev/null 2>&1; then
		update-grub || err "更新 GRUB 配置失败"
	else
		grub-mkconfig -o /boot/grub/grub.cfg || err "更新 GRUB 配置失败"
	fi
}

# 首次启动相关的收尾配置：machine-id、时间同步、swap、networkd、配置落盘。
rebuild_initramfs() {
	# $1 = 触发原因（写进日志/提示）
	# 目的：把"看起来失败"变成"看得见原因"，并尽量降级到能开机。
	#   - initramfs-tools 的 hooks 缺失时，-u 只会生成空壳 → 先补装
	#   - -k all 会遍历 /lib/modules 下所有目录，任何一个残留目录没有对应内核
	#     就会整批失败 → 退化成逐个内核重建
	# 返回 0 = 至少有一个 initramfs 生成成功。
	local reason="$1"
	local log="/var/log/reinstall-initramfs.log"
	local rc=0 kb any_ok=0

	command -v update-initramfs >/dev/null 2>&1 || return 0

	if [ ! -d /usr/share/initramfs-tools/hooks ]; then
		echo "警告：initramfs-tools 的 hooks 缺失（无 /usr/share/initramfs-tools/hooks），尝试补装"
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq initramfs-tools >>"$log" 2>&1 || true
	fi

	: >"$log" 2>/dev/null || log=/dev/null
	update-initramfs -u -k all >>"$log" 2>&1 && any_ok=1

	if [ "$any_ok" -ne 1 ]; then
		echo "提示：update-initramfs -u -k all 失败（详见 $log），改为逐个内核重试"
		for kb in /lib/modules/*; do
			[ -d "$kb" ] || continue
			if update-initramfs -u -k "${kb##*/}" >>"$log" 2>&1; then
				any_ok=1
			fi
		done
	fi

	if [ "$any_ok" -eq 1 ]; then
		return 0
	fi

	rc=1
	echo "警告：重建 initramfs 失败（$reason）。最近的错误输出："
	tail -n 15 "$log" 2>/dev/null | sed 's/^/  | /'
	echo "  已有 initramfs：$(ls -1 /boot/initrd.img-* 2>/dev/null | tr '\n' ' ')"
	echo "  它通常仍可开机；若重启后卡在 initramfs 或缺磁盘驱动，进救援系统执行："
	echo "    MODULES=most update-initramfs -u -k all"
	# 留痕：重启后排查用
	{
		echo "重建 initramfs 失败：$reason"
		date -u 2>/dev/null || true
		tail -n 30 "$log" 2>/dev/null
	} >/root/INITRAMFS-REBUILD-FAILED 2>/dev/null || true
	return "$rc"
}

harden_first_boot() {
	# 1) machine-id 是镜像自带的固定值，所有用同一镜像的机器都相同。
	#    journald、systemd-networkd、部分软件授权都靠它区分实例。
	rm -f /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true
	mkdir -p /var/lib/dbus 2>/dev/null || true
	if command -v systemd-machine-id-setup >/dev/null 2>&1; then
		systemd-machine-id-setup >/dev/null 2>&1 &&
			echo "已重新生成 machine-id：$(cat /etc/machine-id 2>/dev/null)" ||
			echo "警告：systemd-machine-id-setup 失败，machine-id 可能与其它实例相同"
	else
		head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' >/etc/machine-id 2>/dev/null || true
		echo "已用随机值生成 machine-id（systemd-machine-id-setup 不存在）"
	fi
	[ -f /etc/machine-id ] && cp /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true

	# 2) 时间同步：云镜像几乎都不装 NTP 客户端，证书校验、apt 签名、TOTP 都可能因
	#    时钟漂移失败。装 systemd-timesyncd（systemd 自带，体积最小）并启用。
	if ! dpkg -s systemd-timesyncd >/dev/null 2>&1; then
		apt-get install -y -qq systemd-timesyncd >/dev/null 2>&1 || true
	fi
	if dpkg -s systemd-timesyncd >/dev/null 2>&1; then
		enable_unit_offline systemd-timesyncd.service || true
		echo "已启用 systemd-timesyncd 时间同步"
	else
		echo "警告：systemd-timesyncd 不可用，系统时间可能漂移"
	fi

	# 3) swap：按旧系统的换区大小重建 swapfile（没有旧 swap 就不建，避免白占磁盘）
	local swap_bytes=0
	if [ -s "${root_dir}/swap.size.src" ]; then
		IFS= read -r swap_bytes <"${root_dir}/swap.size.src" || true
	fi
	case "$swap_bytes" in '' | *[!0-9]*) swap_bytes=0 ;; esac
	if [ "$swap_bytes" -ge 268435456 ]; then
		local swap_mb=$(((swap_bytes + 1048575) / 1048576))
		if [ ! -f /swapfile ]; then
			echo "按原系统大小重建 swap：${swap_mb}MB"
			# btrfs swapfile 需 NOCOW、无洞且满足设备布局限制；dd 本身不会关闭 COW。
			local mk_ok=0
			local root_fs=""
			root_fs="$(findmnt -rno FSTYPE / 2>/dev/null)"
			if [ "$root_fs" = "btrfs" ]; then
				if (umask 077; : >/swapfile) && chattr +C /swapfile 2>/dev/null; then
					dd if=/dev/zero of=/swapfile bs=1M count="$swap_mb" status=none 2>/dev/null && mk_ok=1
				fi
			else
				(umask 077; fallocate -l "${swap_mb}M" /swapfile) 2>/dev/null && mk_ok=1
				if [ "$mk_ok" -ne 1 ]; then
					(umask 077; dd if=/dev/zero of=/swapfile bs=1M count="$swap_mb" status=none) 2>/dev/null && mk_ok=1
				fi
			fi
			if [ "$mk_ok" -eq 1 ]; then
				chmod 600 /swapfile
				if mkswap /swapfile >/dev/null 2>&1 && swapon /swapfile >/dev/null 2>&1; then
					grep -q '^/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >>/etc/fstab
					echo "swap 已启用并写入 fstab"
				else
					rm -f /swapfile
					echo "警告：mkswap/swapon 失败，已删除 /swapfile"
				fi
			else
				rm -f /swapfile
				echo "警告：无法创建 /swapfile（磁盘空间不足或文件系统不支持），已清除部分文件"
			fi
		fi
	elif [ "$swap_bytes" -gt 0 ]; then
		echo "原系统 swap 仅 $((swap_bytes / 1048576))MB，过小，跳过重建"
	fi

	# 3b) initramfs 的 resume 指向旧系统的 swap UUID 时，开机阶段会去等一个不存在的
	#     设备（"Waiting for suspend/resume device"），在只有 SSH 的 VPS 上表现为
	#     开机卡住 30s~数分钟甚至直接失败。镜像里没建 swap 时明确写 RESUME=none。
	local resume_file="/etc/initramfs-tools/conf.d/resume"
	# swapfile 的内部 UUID 不是可发现的块设备 UUID；休眠还需要底层设备与
	# resume_offset。这里只恢复换页能力，不配置 VPS 休眠，始终禁用自动恢复。
	mkdir -p "$(dirname "$resume_file")" || err "无法创建 initramfs resume 配置目录"
	printf 'RESUME=none\n' >"$resume_file" || err "无法禁用旧休眠设备恢复"
	echo "initramfs resume 已设为 none（swap 仍可用，不启用休眠恢复）"
	# resume 文件是在 init_os 里的 update-initramfs 之后才写的，必须再重建一次，
	# 否则新的 RESUME 不会被收进 initramfs。
	# 注意：RESUME=none 只是"不自动恢复休眠"，重建失败并不等于系统起不来
	#（旧 initramfs 里找不到 resume 设备只会多等几秒）。这里告警继续，
	# 不能因为一次非关键的 resume 配置把整台机器卡在"请勿重启"。
	if command -v update-initramfs >/dev/null 2>&1; then
		rebuild_initramfs "resume 配置" ||
			echo "警告：resume 配置未写入 initramfs；如开机出现 Waiting for suspend/resume device，可手工执行 update-initramfs -u -k all 后重启"
	fi

	# 4) 只保留 ifupdown：networkd 与 ifupdown 同时 enabled 会在开机时抢同一块网卡，
	#    表现是「有时能上网有时不能」。mask 掉 networkd，保留 .network 文件供排查。
	#    注意不能只删 service：socket 与 wait-online 也要一起处理，只 mask service
	#    时 systemd-networkd-wait-online 会因为等不到 networkd 而在每次开机失败。
	if [ -f /lib/systemd/system/systemd-networkd.service ]; then
		for unit in systemd-networkd.service systemd-networkd.socket systemd-networkd-wait-online.service; do
			[ -f "/lib/systemd/system/$unit" ] || continue
			systemctl --root=/ mask "$unit" >/dev/null 2>&1 ||
				systemctl mask "$unit" >/dev/null 2>&1 || true
		done
		echo "已 mask systemd-networkd.service/socket/wait-online（保留 ifupdown 作为唯一网络管理器）"
	fi

	# 5) 首次启动网络自检：静态 IP 配错时至少留下明确痕迹，并尝试退回 DHCP
	cat >/usr/local/sbin/reinstall-netcheck.sh <<'EOF'
#!/bin/sh
# 由 ReinstallDebianUbuntu.sh 安装：首次启动检查网络是否真的通。
# 静态配置写错（网关/掩码/网卡名不对）时，这里会尝试退回 DHCP，并留下标记文件。
MARK=/root/NETWORK-FAILED
[ -f /root/.netcheck.done ] && exit 0
sleep 20
if ping -c 1 -W 3 "$(ip route show default 2>/dev/null | awk '{print $3; exit}')" >/dev/null 2>&1 ||
	getent hosts deb.debian.org >/dev/null 2>&1; then
	touch /root/.netcheck.done
	exit 0
fi
echo "$(date -u) network check failed" >"$MARK"
if command -v dhclient >/dev/null 2>&1; then
	dhclient -v >>"$MARK" 2>&1 && touch /root/.netcheck.done && exit 0
fi
exit 1
EOF
	chmod 0755 /usr/local/sbin/reinstall-netcheck.sh
	cat >/etc/systemd/system/reinstall-netcheck.service <<'EOF'
[Unit]
Description=One-shot network check after reinstall
After=network-online.target networking.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/reinstall-netcheck.sh
RemainAfterExit=yes
StandardOutput=journal

[Install]
WantedBy=multi-user.target
EOF
	enable_unit_offline reinstall-netcheck.service || echo "警告：无法启用 reinstall-netcheck.service"

	return 0
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
	# 时钟不准时 apt 会把所有索引判成"来自未来"，先按镜像时间校正再来一次
	sync_clock_from_mirror "$final_apt_mirror_url"
	# 抹盘后取不到索引是最危险的：此时旧系统已经没了，装不上内核就等于装出
	# 一台开不了机的机器。所以先尽力用预下载的 .deb 把内核+initramfs 弄上去，
	# 真弄不成才按致命错误停下。
	if ! apt-get update; then
		# RTC 偏移时第一次 update 会整批失败；再校一次时钟后重试一次
		sync_clock_from_mirror "$final_apt_mirror_url"
		if ! apt-get update; then
			offline_package_rescue || err "无法更新软件源"
		fi
	fi

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

	# 校验 sshd 真正生效的取值，而不是只看自己写了什么：
	# 1) "改了主文件但被 drop-in 覆盖"这类静默失效
	# 2) 关了密码登录却没有任何可用公钥 —— 重启即失去 SSH
	# sshd/ssh-keygen 在 /usr/sbin（常不在 PATH 里，例如 su -c 或 CI 的 root shell）。
	# 用 `command -v` 会在装好的系统上判"未安装"，属反向误报。
	local sshd_bin="" keygen_bin=""
	sshd_bin="$(sshd_bin_path)" || sshd_bin=""
	for _b in /usr/bin/ssh-keygen /usr/local/bin/ssh-keygen /bin/ssh-keygen; do
		[ -x "$_b" ] && { keygen_bin="$_b"; break; }
	done

	# sshd -T 需要特权分离目录存在，否则直接以 255 退出并打印
	# "Missing privilege separation directory: /run/sshd"。
	# 那样下面的所有断言都会被跳过，只剩一句"无法自检"的警告 —— 正是锁死场景。
	mkdir -p /run/sshd 2>/dev/null || true

	# 最后一道自动修复：drop-in 里只要残留一个本机不认识的选项，sshd 重启后
	# 就完全起不来（不是降级，是全部连接拒绝）。这里把报错点名的选项删掉重试。
	if [ -n "$sshd_bin" ] && [ -f /etc/ssh/sshd_config.d/00-reinstall.conf ]; then
		local _try=0 _err="" _bad=""
		while [ "$_try" -lt 4 ]; do
			_try=$((_try + 1))
			_err="$("$sshd_bin" -T 2>&1 >/dev/null)"
			_bad="$(printf '%s\n' "$_err" | sed -n 's/.*Unsupported option \([A-Za-z0-9]*\).*/\1/p' | head -n 1)"
			[ -n "$_bad" ] || break
			echo "提示：sshd 仍不支持 $_bad，已从 00-reinstall.conf 移除后复验"
			sed -i "/^${_bad}[[:space:]]/d" /etc/ssh/sshd_config.d/00-reinstall.conf
		done
	fi

	local effective="" sshd_err=""
	if [ -n "$sshd_bin" ]; then
		sshd_err="$("$sshd_bin" -T 2>&1 >/dev/null)"
	fi
	if [ -n "$sshd_bin" ] && [ -z "$sshd_err" ]; then
		effective="$("$sshd_bin" -T 2>/dev/null)"
		echo "SSH 生效配置："
		printf '%s\n' "$effective" | grep -E '^(port|permitrootlogin|passwordauthentication|maxauthtries) ' | sed 's/^/  /' || true

		if [ -n "$ssh_port" ] && ! printf '%s\n' "$effective" | grep -qx "port $ssh_port"; then
			err "sshd -T 显示端口不是 $ssh_port（可能是 ssh.socket 或其它 drop-in 覆盖），重启后将无法按预期端口登录"
		fi
		if printf '%s\n' "$effective" | grep -qx 'passwordauthentication no'; then
			# 关掉密码登录前必须确认新系统里确实有可解析的公钥
			if [ -z "$keygen_bin" ] || ! "$keygen_bin" -l -f /root/.ssh/authorized_keys >/dev/null 2>&1; then
				err "sshd 已关闭密码登录，但 /root/.ssh/authorized_keys 中没有可用公钥，重启后将无法登录。已中止"
			fi
		fi
	else
		if [ -n "$sshd_err" ]; then
			echo "警告：sshd -T 自检失败：$sshd_err（重启后请确认 SSH 可用性）"
		else
			echo "警告：无法用 sshd -T 自检 SSH 配置（重启后请确认 SSH 可用性）"
		fi
		# 自检没跑成时无法断言"端口是否被覆盖"，至少把写入结果复查一遍：
		# 密码登录被关掉却没有任何可解析公钥，是最确定的锁死条件。
		if printf '%s\n' "$sshd_policy_password_auth" | grep -qx 'no'; then
			if [ -z "$keygen_bin" ] || ! "$keygen_bin" -l -f /root/.ssh/authorized_keys >/dev/null 2>&1; then
				err "已关闭密码登录，但 /root/.ssh/authorized_keys 中没有可用公钥，重启后将无法登录。已中止"
			fi
		fi
	fi

	echo "应用系统优化配置..."
	cat >/etc/sysctl.d/99-bbr.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

	if [ -f "/etc/default/grub" ]; then
		# 内核参数只能追加，不能整体覆盖：云镜像/VPS 镜像的 GRUB_CMDLINE_LINUX
		# 常带 console=ttyS0,115200（串口控制台）、intel_iommu=on、iommu=pt 之类，
		# 覆盖掉等于把机器唯一能看到开机过程的通道拆了，而且无法从面板恢复。
		grub_inherit_old_cmdline
		# 串口控制台的机器，GRUB 菜单本身也要走串口，否则面板上连菜单都看不到，
		# 内核参数继承了 console=ttyS0 也没用（菜单阶段还是黑屏）。
		if [ -s "${root_dir}/old.cmdline.src" ] && grep -qE '^console=ttyS0' "${root_dir}/old.cmdline.src"; then
			local serial_speed="115200"
			serial_speed="$(sed -n 's/^console=ttyS0,\([0-9]\{1,\}\).*/\1/p' "${root_dir}/old.cmdline.src" | head -1)"
			[ -n "$serial_speed" ] || serial_speed=115200
			if ! grep -q '^GRUB_TERMINAL=' /etc/default/grub; then
				echo 'GRUB_TERMINAL="serial console"' >>/etc/default/grub
			fi
			if ! grep -q '^GRUB_SERIAL_COMMAND=' /etc/default/grub; then
				echo "GRUB_SERIAL_COMMAND=\"serial --speed=${serial_speed} --unit=0 --word=8 --parity=no --stop=1\"" >>/etc/default/grub
			fi
			echo "GRUB 菜单已启用串口输出（ttyS0，${serial_speed}）"
		fi
		grub_append_cmdline "GRUB_CMDLINE_LINUX" "net.ifnames=0 biosdevname=0"
		# btrfs 根必须是某个子卷时，内核命令行要带 rootflags，否则内核按顶层卷挂载，
		# fstab 里的 subvol 只在 systemd 重挂载阶段才生效，早期已经读过错误的内容
		if [ -s "${root_dir}/root.subvol.src" ]; then
			local sv=""
			IFS= read -r sv <"${root_dir}/root.subvol.src" || true
			if [ -n "$sv" ]; then
				grub_append_cmdline "GRUB_CMDLINE_LINUX" "rootflags=subvol=$sv"
			fi
		fi
		# 同理，DEFAULT 里可能有 mitigations=off / transparent_hugepage=never 等运维项
		grub_append_cmdline "GRUB_CMDLINE_LINUX_DEFAULT" "quiet"
		# 老内核留在 /boot 会让超时菜单默认选错项，这里让 update-grub 只收新内核；
		# os-prober 在抹空的机器上还会去嗅探别的磁盘，直接关掉。
		grep -q '^GRUB_DISABLE_OS_PROBER=' /etc/default/grub && sed -i 's/^GRUB_DISABLE_OS_PROBER=.*/GRUB_DISABLE_OS_PROBER=true/' /etc/default/grub ||
			echo 'GRUB_DISABLE_OS_PROBER=true' >>/etc/default/grub
		# 超时为 0 时引导失败没有任何补救窗口（VPS 面板无法按键），保底 5 秒
		if grep -q '^GRUB_TIMEOUT=' /etc/default/grub; then
			local t
			t="$(sed -n 's/^GRUB_TIMEOUT=\([0-9]*\).*/\1/p' /etc/default/grub | head -1)"
			if [ -n "$t" ] && [ "$t" -lt 5 ]; then
				sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub
				echo "GRUB 超时由 ${t}s 调整为 5s（留出引导失败时的选择窗口）"
			fi
		fi
		write_grub_policy
		update-grub || err "更新 GRUB 配置失败（内核参数无法写入引导项）"
	else
		err "/etc/default/grub 未找到，无法生成可靠的引导参数"
	fi

	# initramfs 在装内核时已生成，但 fstab/根设备参数是之后才定的；
	# 重建一遍确保 resume/root 参数与最终 fstab 一致（否则部分机器会卡在 initramfs）
	if command -v update-initramfs >/dev/null 2>&1; then
		rebuild_initramfs "最终 fstab" ||
			echo "警告：initramfs 可能未反映最终 fstab；若重启后卡在 initramfs，见 /root/INITRAMFS-REBUILD-FAILED"
	fi

	# 先写接口配置再启用服务：反过来的话 enable 成功但配置还没落地也无从判断
	write_network_interfaces
	enable_unit_offline networking.service || err "无法启用 networking.service，重启后将没有网络"

	harden_first_boot

	if ! grep -q '^\* soft nofile 65535' /etc/security/limits.conf 2>/dev/null; then
		cat >>/etc/security/limits.conf <<EOF
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
EOF
	fi

	mkdir -p /etc/systemd/system/networking.service.d/
	printf "[Service]\nTimeoutStartSec=15sec\n" >/etc/systemd/system/networking.service.d/timeout.conf

	echo "配置最终系统 DNS..."
	apply_dns_config "/etc/resolv.conf"
	echo "老的 DNS 备份在 /etc/resolv.conf.old"

	grep -qxF 'precedence ::ffff:0:0/96 100' /etc/gai.conf 2>/dev/null || echo "precedence ::ffff:0:0/96 100" >>/etc/gai.conf

	echo "$hostname" >/etc/hostname
	# 整份重写而不是追加：镜像自带的 /etc/hosts 常带 127.0.1.1 LXC_NAME 之类的
	# 容器痕迹，追加会留下一个解析到本机但主机名不对的条目，sudo 会因此变慢。
	cat >/etc/hosts <<EOF
127.0.0.1	localhost
127.0.1.1	$hostname
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
EOF
	echo "已重写 /etc/hosts"

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

	if [ "$download_tcpx" -eq 1 ]; then
		echo "尝试下载 tcpx.sh ..."
		local tcpx_sh_url="https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
		[ "$region" = "cn" ] && tcpx_sh_url="https://ghproxy.net/https://raw.githubusercontent.com/ylx2016/Linux-NetSpeed/master/tcpx.sh"
		echo "警告：tcpx.sh 取自可变分支且没有完整性校验，运行前请自行审阅内容"

		if wget --connect-timeout=15 -T 10 -O /root/tcpx.sh "$tcpx_sh_url" && [ -s /root/tcpx.sh ]; then
			chmod 0700 /root/tcpx.sh
			echo "tcpx.sh 已下载到 /root/tcpx.sh（不会自动执行）"
		else
			rm -f /root/tcpx.sh
			echo "警告：tcpx.sh 下载失败，跳过此步骤"
		fi
	fi
}

# 探测承载默认路由的网卡，并数一数物理网卡数量。
# 新系统强制 net.ifnames=0，单网卡时内核一定把它叫 eth0，所以默认 eth0 是安全的；
# 多网卡时枚举顺序不保证，必须靠 MAC 把「现在这块」钉死成 eth0，否则静态配置
# 可能写到另一块网卡上。
detect_primary_nic() {
	local nic=""
	nic=$(ip -4 route show default 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
	if [ -z "$nic" ]; then
		nic=$(ip -o link show up 2>/dev/null | awk -F': ' '{print $2}' |
			grep -vE '^(lo|docker|veth|br-|virbr|bond|tun|tap|wg|tailscale|sit|ip6tnl|gre|dummy)' | head -1)
	fi
	primary_nic="$nic"

	if [ -n "$nic" ] && [ -r "/sys/class/net/$nic/address" ]; then
		primary_nic_mac=$(cat "/sys/class/net/$nic/address" 2>/dev/null)
	fi

	# 只数真正挂在总线上的网卡：bond0 / sit0 / ip6tnl0 / tailscale0 / docker0 都
	# 没有 /sys/class/net/<name>/device，按网卡名黑名单数会得到"物理网卡数：5"这种假值，
	# 进而误判成多网卡、走 MAC 固定逻辑。
	nic_count=0
	local _l=""
	for _l in /sys/class/net/*; do
		[ -e "$_l/device" ] || continue
		[ "${_l##*/}" = "lo" ] && continue
		nic_count=$((nic_count + 1))
	done
	if [ "$nic_count" -eq 0 ]; then
		# 容器/受限环境没有 device 链接，退回按名字过滤
		nic_count=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' |
			grep -vE '^(lo|docker|veth|br-|virbr|bond|tun|tap|wg|tailscale|sit|ip6tnl|gre|dummy)' | wc -l)
	fi

	echo "主网卡：${primary_nic:-未识别}（MAC ${primary_nic_mac:-未知}），物理网卡数：$nic_count"
	return 0
}

# 判定当前系统是 DHCP 还是静态，而不是只看配置文件：
#  - 运行时最可靠的信号是 `ip -4 addr` 里的 dynamic 标记（DHCP 租约才带）
#  - 其次看各网络管理栈的配置声明（ifupdown / netplan / networkd / NetworkManager）
# 尽量沿用当前获取方式；无明确租约/配置时只是保守推断，不能保证提供商网络不变。
detect_ip_mode() {
	ip_mode="unknown"
	local line=""

	# 判定顺序：运行时 dynamic 标记（最硬的 DHCP 证据）→ 配置声明 dhcp →
	# 配置声明 static → 最后才用"有地址但没 dynamic 标记"兜底当静态。
	# 不能把这条兜底放最前：udhcpc（Alpine 等精简发行版）和部分 ifupdown
	# 拿到租约后不设 dynamic 标志，机器明明是 DHCP 会被判成静态，
	# 重装时就按静态 IP 写配置，IP 一变就失联。
	if [ -n "$primary_nic" ]; then
		line=$(ip -4 addr show dev "$primary_nic" scope global 2>/dev/null | awk '/inet [0-9]/ {print; exit}')
	fi
	if echo "$line" | grep -qw 'dynamic'; then
		ip_mode="dhcp"
	fi

	# 只认主网卡的配置；不能让第二块卡的 DHCP 或 NM 的 IPv6 method=auto
	# 把当前 IPv4 静态连接误判为 DHCP。全局扫描所有配置文件不是有效证据。
	if [ "$ip_mode" = "unknown" ] && [ -n "$primary_nic" ]; then
		local declared="" file="" connection="" method=""
		for file in /etc/network/interfaces /etc/network/interfaces.d/*; do
			[ -f "$file" ] || continue
			declared="$(awk -v nic="$primary_nic" '$1 == "iface" && $2 == nic && $3 == "inet" {print $4; exit}' "$file")"
			case "$declared" in dhcp | static) ip_mode="$declared"; break ;; esac
		done
		if [ "$ip_mode" = "unknown" ] && command -v nmcli >/dev/null 2>&1; then
			connection="$(nmcli -g GENERAL.CON-UUID device show "$primary_nic" 2>/dev/null)" || connection=""
			if [[ "$connection" =~ ^[0-9a-fA-F-]{36}$ ]]; then
				method="$(nmcli -g ipv4.method connection show uuid "$connection" 2>/dev/null)" || method=""
				case "$method" in auto) ip_mode=dhcp ;; manual) ip_mode=static ;; esac
			fi
		fi
		if [ "$ip_mode" = "unknown" ]; then
			file="/etc/sysconfig/network-scripts/ifcfg-$primary_nic"
			if [ -f "$file" ]; then
				if grep -qiE "^[[:space:]]*BOOTPROTO=['\"]?dhcp['\"]?[[:space:]]*$" "$file"; then
					ip_mode=dhcp
				elif grep -qiE "^[[:space:]]*BOOTPROTO=['\"]?(static|none)['\"]?[[:space:]]*$" "$file"; then
					ip_mode=static
				fi
			fi
		fi
	fi

	# 所有声明都读不到时，才用"有地址但没 dynamic 标记"兜底当静态
	if [ "$ip_mode" = "unknown" ] && [ -n "$line" ]; then
		ip_mode="static"
	fi

	# 记录到 work_dir（此时 $root_dir 还没创建），便于事后排查默认值从哪来
	if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
		echo "${ip_mode}" >"${work_dir}/ip_mode.src" 2>/dev/null || true
	fi
	case "$ip_mode" in
	dhcp) echo "当前 IP 获取方式：DHCP（重装默认同样使用 DHCP）" ;;
	static) echo "当前 IP 获取方式：静态（重装默认同样使用静态配置）" ;;
	*) echo "当前 IP 获取方式：未能识别（稍后询问）" ;;
	esac
	return 0
}

# 采集 DHCP 身份（client-id / DUID / hostname）。
# 为什么必须做：不少 VPS 的 DHCP 服务器按 client-id 或 DUID 绑定固定 IP。
# 重装后如果换成另一个 DHCP 客户端、或 DUID 重新生成，拿到的地址可能不同，
# 甚至直接不给地址 —— 那就是装完失联。把原身份原样带过去最稳。
capture_dhcp_identity() {
	dhcp_client_id=""
	dhcp6_client_id=""
	dhcp_hostname=""
	dhcp_id_source=""
	local f="" v=""

	# 1) dhclient 的显式配置：直接抄，行为完全一致
	for f in /etc/dhcp/dhclient.conf /etc/dhcp/dhclient6.conf; do
		[ -f "$f" ] || continue
		if [ -z "$dhcp_client_id" ]; then
			v="$(sed -n 's/^[[:space:]]*send[[:space:]]\+dhcp-client-identifier[[:space:]]\+\([^;]*\);.*/\1/p' "$f" | head -n 1)"
			[ -n "$v" ] && {
				dhcp_client_id="$v"
				dhcp_id_source="$f"
			}
		fi
		if [ -z "$dhcp6_client_id" ]; then
			v="$(sed -n 's/^[[:space:]]*send[[:space:]]\+dhcp6\.client-id[[:space:]]\+\([^;]*\);.*/\1/p' "$f" | head -n 1)"
			[ -n "$v" ] && dhcp6_client_id="$v"
		fi
	done

	# 2) 客户端自己留下的状态文件（dhclient 各发行版路径不同，全试一遍）
	if [ -z "$dhcp_client_id" ] || [ -z "$dhcp_hostname" ]; then
		for f in /var/lib/dhcp/dhclient.leases /var/lib/dhclient/dhclient.leases \
			/var/lib/NetworkManager/*.lease /var/lib/NetworkManager/dhclient*.conf \
			/etc/NetworkManager/dhclient*.conf; do
			[ -f "$f" ] || continue
			if [ -z "$dhcp_client_id" ]; then
				v="$(sed -n 's/^[[:space:]]*\(send[[:space:]]\+\)\{0,1\}dhcp-client-identifier[[:space:]="]*\([^;"]*\).*/\2/p' "$f" | head -n 1)"
				[ -n "$v" ] && {
					dhcp_client_id="$v"
					dhcp_id_source="$f"
				}
			fi
			if [ -z "$dhcp_hostname" ]; then
				v="$(sed -n 's/^[[:space:]]*\(option[[:space:]]\+\)\{0,1\}host-name[[:space:]="]*\([^;"]*\).*/\2/p' "$f" | head -n 1)"
				[ -n "$v" ] && dhcp_hostname="$v"
			fi
		done
	fi

	# 3) dhcpcd 的 DUID（原始十六进制，要转成 dhclient 的冒号格式）
	if [ -z "$dhcp6_client_id" ] && [ -s /var/lib/dhcpcd/duid ]; then
		v="$(tr -d '\r\n' </var/lib/dhcpcd/duid 2>/dev/null | tr -dc '0-9a-fA-F')"
		if [ "${#v}" -ge 8 ] && [ $((${#v} % 2)) -eq 0 ]; then
			dhcp6_client_id="$(printf '%s' "$v" | sed 's/../&:/g; s/:$//' | tr 'A-F' 'a-f')"
		fi
	fi

	# 4) 兜底：老系统按 MAC 派生 client-id（isc-dhcp 默认 type 1）时，
	#    新系统只要还是 isc-dhcp-client 就自动一致，无需显式写。
	[ -n "$dhcp_hostname" ] || dhcp_hostname="$(cat /etc/hostname 2>/dev/null | head -n 1)"

	# 只接受不会破坏 dhclient.conf 语法的取值（拒绝分号/换行等注入）
	local ok_id="$dhcp_client_id" ok_duid="$dhcp6_client_id"
	case "$ok_id" in *[\;\ ]* | *";"*) [ -n "$ok_id" ] && dhcp_client_id="" ;; esac
	case "$ok_duid" in *";"*) [ -n "$ok_duid" ] && dhcp6_client_id="" ;; esac

	if [ -n "$dhcp_client_id" ] || [ -n "$dhcp6_client_id" ]; then
		echo "已采集 DHCP 身份：client-id=${dhcp_client_id:-无}，DUID=${dhcp6_client_id:-无}（来源 ${dhcp_id_source:-状态文件}）"
	else
		echo "未发现自定义 DHCP 身份（新系统按 MAC 派生 client-id，与原有行为一致）"
	fi
	return 0
}

# 采集 IPv6 细节：所有全局地址、默认网关、额外路由，以及地址是否由 RA/DHCPv6 自动获得。
capture_ipv6_config() {
	ipv6_addrs=()
	ipv6_gw=""
	ipv6_routes=()
	ipv6_dynamic=0
	local nic="${primary_nic:-$network_adapter}"
	[ -n "$nic" ] || return 0

	local line="" a="" r="" gw="" prefix=""
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		a="$(awk '{print $4}' <<<"$line")"
		case "$a" in *:*/*) ;; *) continue ;; esac
		ipv6_addrs+=("$a")
		case "$line" in *" dynamic "*) ipv6_dynamic=1 ;; esac
	done <<<"$(ip -6 -o addr show dev "$nic" scope global 2>/dev/null)"

	gw="$(ip -6 route show default dev "$nic" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit }}')"
	ipv6_gw="$gw"

	# 只保留「前缀 + via 网关」这种显式路由；RA 自动生成的路由（proto ra/kernel）
	# 在新系统里会由内核/SLAAC 自己再生成，写死反而可能与现状冲突。
	while IFS= read -r line; do
		[ -n "$line" ] || continue
		case "$line" in default* | fe80:* | *" proto kernel "* | *" proto ra "*) continue ;; esac
		prefix="$(awk '{print $1}' <<<"$line")"
		r="$(awk '{for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit }}' <<<"$line")"
		[ -n "$prefix" ] && [ -n "$r" ] && ipv6_routes+=("$prefix via $r")
	done <<<"$(ip -6 route show dev "$nic" 2>/dev/null)"

	if [ "${#ipv6_addrs[@]}" -gt 0 ]; then
		echo "已采集 IPv6：地址 ${ipv6_addrs[*]}，网关 ${ipv6_gw:-无}，额外路由 ${#ipv6_routes[@]} 条，自动获取=$ipv6_dynamic"
	fi
	return 0
}

get_ip() {
	[ -n "$primary_nic" ] || return 1
	local addresses=""
	addresses="$(ip -4 -o addr show dev "$primary_nic" scope global 2>/dev/null)" || return 1
	main_ip=$(ip -4 route get 1 oif "$primary_nic" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')
	[ -z "$main_ip" ] && main_ip=$(awk '$3=="inet" {split($4,a,"/"); print a[1]; exit}' <<<"$addresses")

	if [ -z "$main_ip" ]; then
		echo "警告：无法自动检测主 IP"
		return 1
	fi

	gateway_ip=$(ip -4 route show default dev "$primary_nic" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="via") {print $(i+1); exit}}')
	if [ -z "$gateway_ip" ]; then
		echo "警告：无法自动检测网关"
		return 1
	fi

	subnet=$(awk -v ip="$main_ip" '$3=="inet" {split($4,a,"/"); if(a[1]==ip) {print a[2]; exit}}' <<<"$addresses")
	[[ "$subnet" =~ ^[0-9]+$ ]] && [ "$subnet" -le 32 ] || return 1

	local value=$((0xffffffff ^ ((1 << (32 - subnet)) - 1)))
	netmask="$(((value >> 24) & 0xff)).$(((value >> 16) & 0xff)).$(((value >> 8) & 0xff)).$((value & 0xff))"
	return 0
}

check_ipv6() {
	local line="" ipv6_addr="" iface="" nic="${primary_nic:-$network_adapter}"

	# 只认主网卡（承载默认路由那块）上的全局地址。全接口扫描会把 tailscale0 的
	# fd7a:115c:a1e0::/48（Tailscale 自己的 ULA）当成"这台机器的 IPv6"写进新系统，
	# 换台机器根本连不通；docker/bridge/tun 同理。
	if [ -n "$nic" ]; then
		line="$(ip -6 -o addr show dev "$nic" scope global 2>/dev/null | head -n 1)"
		if [ -n "$line" ]; then
			iface="$nic"
			ipv6_addr="$(awk '{print $4}' <<<"$line")"
		fi
	fi
	if [ -z "$ipv6_addr" ]; then
		line="$(ip -6 -o addr show scope global 2>/dev/null |
			awk '$2 !~ /^(lo|tailscale|tun|tap|wg|docker|veth|br-|virbr)/ {print; exit}')"
		if [ -n "$line" ]; then
			iface="$(awk '{print $2}' <<<"$line")"
			ipv6_addr="$(awk '{print $4}' <<<"$line")"
		fi
	fi

	if [ -n "$ipv6_addr" ]; then
		echo "检测到 IPv6 地址：$ipv6_addr（接口：${iface:-未知}）"
		has_ipv6=1
	else
		echo "未检测到 IPv6 地址"
		has_ipv6=0
	fi

	case "$iface" in
	eth* | en*) native_ipv6_iface="$iface" ;;
	*) native_ipv6_iface="" ;;
	esac

	if [ -n "$native_ipv6_iface" ]; then
		echo "检测到原生 IPv6（接口：$native_ipv6_iface）"
		has_native_ipv6=1
		native_ipv6_addr="$(echo "$ipv6_addr" | cut -d'/' -f1)"
		native_ipv6_mask="$(echo "$ipv6_addr" | cut -d'/' -f2)"
		native_ipv6_gw="$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)"
		echo "原生 IPv6 信息：地址: $native_ipv6_addr，掩码: $native_ipv6_mask，网关: $native_ipv6_gw"
	else
		has_native_ipv6=0
	fi

	if [ "$has_ipv6" -eq 1 ] && [ -n "$iface" ] &&
		ip tunnel show "$iface" 2>/dev/null | grep -q "ipv6/ip"; then
		if echo "$ipv6_addr" | grep -q "^2001:470:"; then
			echo "检测到 HE.net 6in4 隧道（接口：$iface）"
			he_tunnel=1
			he_client_ipv4="$(ip tunnel show "$iface" | grep -oP 'local \K[\d.]+')"
			he_server_ipv4="$(ip tunnel show "$iface" | grep -oP 'remote \K[\d.]+')"
			he_client_ipv6="$(echo "$ipv6_addr" | cut -d'/' -f1)"
			he_netmask="$(echo "$ipv6_addr" | cut -d'/' -f2)"
			he_server_ipv6="$(ip -6 route show | grep -oP 'default via \K[0-9a-f:]+' | head -1)"
			[ -n "$he_server_ipv6" ] || he_server_ipv6="$(echo "$he_client_ipv6" | sed 's/::2$/::1/')"
			echo "隧道信息：客户端 IPv4: $he_client_ipv4，服务器 IPv4: $he_server_ipv4，客户端 IPv6: $he_client_ipv6，服务器 IPv6: $he_server_ipv6"
		else
			he_tunnel=0
		fi
	else
		he_tunnel=0
	fi

	[ "$has_ipv6" -eq 0 ] && [ "$he_tunnel" -eq 0 ] && [ "$has_native_ipv6" -eq 0 ] && return 1
	return 0
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

	# 先看系统现在到底怎么拿 IP（运行时信号优先），再决定新系统的默认值：
	# 现在跑 DHCP 就默认 DHCP，现在跑静态就默认静态。这样即使配置文件写得
	# 混乱（netplan/networkd/NetworkManager 各说各话），默认值也跟事实一致。
	detect_primary_nic || true
	detect_ip_mode || true

	case "$ip_mode" in
	dhcp) is_auto=0 ;;
	static) is_auto=1 ;;
	*) is_auto=0 ;;
	esac

	# 运行时判不出来时，才退回读配置文件的老办法
	if [ "$ip_mode" = "unknown" ]; then
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
	fi

	check_ipv6 || true
	# 采集原系统的 DHCP 身份与 IPv6 细节：两者都是「重装后一变就失联」的信息
	capture_dhcp_identity || true
	capture_ipv6_config || true
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
	# 当前系统怎么拿 IP，新系统就默认怎么拿 —— 不再无条件问一遍。
	# 只有「判不出来」时才询问，避免 VPS 上无 DHCP 却默认 DHCP 导致失联。
	case "$ip_mode" in
	dhcp)
		is_auto=0
		# 打一行当前实际地址，确认脚本认定的那块网卡就是承载业务的那块
		local _cur=""
		_cur=$(ip -4 -o addr show dev "${primary_nic:-$network_adapter}" scope global 2>/dev/null | awk '{print $4; exit}')
		echo "沿用当前系统的 DHCP 方式（不再询问）。当前地址：${_cur:-未知}，网关：${gateway_ip:-未知}"
		;;
	static)
		is_auto=1
		echo "沿用当前系统的静态 IP 方式。"
		;;
	*)
		if [ "$is_auto" -eq 0 ]; then
			read -r -p "未能判定当前 IP 获取方式，新系统是否动态获取 IP (DHCP)？[Y/n]: " input
			[ -z "$input" ] && input="y"
			case "$input" in
			[yY][eE][sS] | [yY]) ;;
			[nN][oO] | [nN]) is_auto=1 ;;
			*) err "用户取消操作" ;;
			esac
		fi
		;;
	esac

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

	# 引导盘必须就是承载 / 的那块盘。选错了会怎样：引导代码写进 A 盘，
	# 根文件系统抹掉重装在 B 盘，重启后 BIOS 从 A 盘引导、grub.cfg 指向的
	# 却是不存在的根 —— 直接掉进 grub rescue。多盘机器上这是最容易犯的错。
	local root_src="" root_disk=""
	root_src=$(findmnt -no SOURCE / 2>/dev/null)
	if [ -n "$root_src" ]; then
		root_disk=$(lsblk -no PKNAME "$root_src" 2>/dev/null | head -n 1)
		if [ -n "$root_disk" ]; then
			if [ "/dev/$root_disk" != "$grub_device" ]; then
				err "引导设备 $grub_device 与根文件系统所在磁盘 /dev/$root_disk 不是同一块盘。引导代码写错盘会导致重启后无法引导，已中止"
			fi
			echo "引导盘与根分区一致：/dev/$root_disk"
		else
			echo "警告：根分区 $root_src 未落在普通磁盘上（LVM/RAID/网络存储），无法校验引导盘是否与之一致"
		fi
	fi
}

# GPT 磁盘开头（MBR 1 扇区 + GPT 主表 1-33 扇区）到第一个分区之间的空洞，
# 单位 512 字节扇区。grub-install 在 GPT 上找不到 BIOS Boot 分区时会把 core.img
# 嵌进这个空洞——只要够大就完全不需要 --force，也不动分区表。
# 第二个参数只给单元测试用（假 sysfs 根）。
gpt_boot_gap_sectors() {
	# $1 允许是 /dev/vda 或 vda：调用方传的是 grub_device（带 /dev/ 前缀），
	# 直接拼 sysfs 路径会变成 /sys/block//dev/vda/... 而永远匹配不到 → 误判 0。
	local disk="${1##*/}" sysroot="${2:-/sys/block}" p start min_start=""
	case "$disk" in '' | */*) echo -1; return 0 ;; esac
	for p in "$sysroot/$disk/$disk"*; do
		[ -r "$p/start" ] || continue
		start="$(cat "$p/start" 2>/dev/null)" || continue
		case "$start" in '' | *[!0-9]*) continue ;; esac
		if [ -z "$min_start" ] || [ "$start" -lt "$min_start" ]; then
			min_start="$start"
		fi
	done
	# -1 表示读不到任何分区起始扇区（读不到 ≠ 空洞为 0，不能当成"装不上"）
	[ -n "$min_start" ] || { echo -1; return 0; }
	if [ "$min_start" -gt 34 ]; then
		echo $((min_start - 34))
	else
		echo 0
	fi
}

# 读现有系统的引导方式：MBR 前 440 字节的引导代码 + 字符串特征。
# 目的不是猜，而是拿到证据：这台机器现在到底靠什么启动，抹盘后就再也读不到了。
# 结果写进 EXISTING_MBR_CODE（1=有引导代码）、EXISTING_BOOT_HINT（grub/syslinux/unknown）。
detect_existing_bootloader() {
	local disk="$1" tmp raw hint="unknown"

	EXISTING_MBR_CODE=0
	EXISTING_BOOT_HINT="unknown"
	[ -n "$disk" ] && [ -b "$disk" ] || return 0
	tmp="$(mktemp "${work_dir:-/tmp}/mbr.XXXXXX" 2>/dev/null)" || return 0
	if ! dd if="$disk" of="$tmp" bs=512 count=1 2>/dev/null; then
		rm -f "$tmp"
		echo "[检测] 无法读取 $disk 的引导扇区（无权限或设备不可读）"
		return 0
	fi
	raw="$(dd if="$tmp" bs=1 count=440 2>/dev/null | tr -d '\000' | tr -c '[:print:]\n' ' ')"
	# 全零 = 没有引导代码（走固件/其他介质引导），任何非空都算有
	[ -n "$(printf '%s' "$raw" | tr -d '[:space:]')" ] && EXISTING_MBR_CODE=1

	if printf '%s' "$raw" | grep -Eqi 'GRUB|stage1|Geom|Read Error'; then
		hint="grub"
	elif printf '%s' "$raw" | grep -Eqi 'SYSLINUX|LILO|EXTLINUX'; then
		hint="syslinux-or-lilo"
	fi
	EXISTING_BOOT_HINT="$hint"
	rm -f "$tmp"

	case "$hint" in
	grub) echo "[检测] 现有引导：MBR 里有 GRUB 引导代码" ;;
	syslinux-or-lilo) echo "[检测] 现有引导：MBR 里是 SYSLINUX/LILO，不是 GRUB" ;;
	*) echo "[检测] 现有引导：MBR 引导代码特征无法识别（可能由固件/网卡/其他介质引导）" ;;
	esac
	if [ "$EXISTING_MBR_CODE" -eq 1 ]; then
		echo "[检测] MBR 引导代码区非空，说明当前系统确实从这块盘引导"
	fi
	return 0
}

# 在磁盘开头空洞（GPT 主表之后、第一个分区之前）补一个 BIOS Boot 分区。
# grub 在 GPT 上只认 ef02 分区，不认空洞，所以这一步是把"有空间"变成"装得上"。
# 只新增一个分区，不动任何已有分区、不移动数据。成功返回 0。
ensure_bios_boot_partition() {
	local disk="$1" gap="$2" start=34 end sgdisk_bin=""

	case "${gap:-0}" in '' | *[!0-9]*) return 1 ;; esac
	[ "$gap" -ge 1024 ] || return 1
	end=$((34 + gap - 1))

	# 优先 sgdisk（GPT 原生，只改目标条目）；没有就用 fdisk/parted 提示手工处理
	if command -v sgdisk >/dev/null 2>&1; then
		sgdisk_bin="sgdisk"
	elif command -v apt-get >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gdisk >/dev/null 2>&1 &&
			command -v sgdisk >/dev/null 2>&1 && sgdisk_bin="sgdisk"
	elif command -v apk >/dev/null 2>&1; then
		apk add --no-cache gdisk >/dev/null 2>&1 && command -v sgdisk >/dev/null 2>&1 && sgdisk_bin="sgdisk"
	fi
	if [ -z "$sgdisk_bin" ]; then
		echo "[警告] 没有 sgdisk，无法自动创建 BIOS Boot 分区"
		return 1
	fi

	echo "[操作] 在 $disk 的扇区 $start..$end 建立 BIOS Boot 分区（ef02，约 $((gap / 2)) KiB）"
	# --new=0 让 sgdisk 自己挑第一个空闲号；typecode/name 一起写，避免残留旧类型
	if ! "$sgdisk_bin" --new=0:"$start":"$end" --typecode=0:ef02 --change-name=0:"BIOS boot" "$disk" >/dev/null 2>&1; then
		echo "[警告] sgdisk 创建 BIOS Boot 分区失败"
		return 1
	fi
	# 让内核重读分区表（设备忙时会失败，不影响 grub 直接读磁盘，只提示）
	partprobe "$disk" >/dev/null 2>&1 || blockdev --rereadpt "$disk" >/dev/null 2>&1 || true
	if fdisk -l "$disk" 2>/dev/null | grep -q "BIOS boot"; then
		echo "[操作] BIOS Boot 分区已建立"
		return 0
	fi
	echo "[警告] 分区表里没有出现 BIOS boot 条目"
	return 1
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

	# 探测失败（fdisk 缺失、磁盘不存在、输出格式变了）时 label_type 为空。
	# 这时绝不能当成 "MBR" —— Legacy+GPT 会被判成 standard 并在抹盘后第一次
	# grub-install 就失败，只能靠 --force 自救。未知就要求显式选择。
	if [ -z "$label_type" ]; then
		echo "[警告] 无法确定 $target_disk 的分区表类型（fdisk 输出为空）"
		if [ "$IS_EFI" -eq 1 ]; then
			echo "[决策] 按 UEFI 模式继续（EFI 与分区表类型无关）"
			GRUB_STRATEGY="efi"
			echo "------------------------------------------------"
			return 0
		fi
		echo "请手工指定引导模式："
		echo "1. standard（MBR 磁盘，或有 BIOS boot 分区的 GPT）"
		echo "2. force_embed（Legacy + GPT 且无 BIOS boot 分区；需 --force-embed）"
		while true; do
			read -r -p "请输入数字 (1 或 2)： " choice || err "读取标准输入失败"
			case "$choice" in
			1) GRUB_STRATEGY="standard"; break ;;
			2)
				if [ "${force_embed_optin:-0}" -ne 1 ]; then
					err "选择了强制嵌入模式，但没有加 --force-embed。该模式会写入 GPT 保护扇区附近、可能破坏分区表，必须显式开启。已中止（现有系统未改动）"
				fi
				GRUB_STRATEGY="force_embed"
				break
				;;
			*) echo "无效输入，请输入 1 或 2" ;;
			esac
		done
		echo "[决策] 使用 $GRUB_STRATEGY 模式"
		echo "------------------------------------------------"
		return 0
	fi
	echo "[检测结果] 分区表类型: $label_type"

	# 抹盘前把这台机器现在怎么引导的记下来：抹完就再也读不到了，
	# 而「现有系统能启动」本身就是最强的可行性证据（比如 GPT+Legacy 无空洞
	# 却开得起来，说明它本来就用 blocklists）。
	detect_existing_bootloader "$target_disk"

	if [ "$IS_EFI" -eq 1 ]; then
		GRUB_STRATEGY="efi"
	elif [ "$label_type" = "gpt" ]; then
		if pipe_grep_q "BIOS boot" fdisk -l "$target_disk"; then
			echo "[状态] 发现标准 BIOS Boot 分区，使用标准模式。"
			GRUB_STRATEGY="standard"
		else
			# 关键事实：grub 在 GPT 上**不使用**磁盘开头空洞（那是 msdos 标签的行为），
			# 只认 BIOS Boot 分区（ef02）。所以空洞够大时不是"直接嵌入"，而是先在
			# 空洞里补一个 ef02 分区，再走标准安装 —— 不动任何已有分区、不移动数据。
			local gap_sectors
			gap_sectors="$(gpt_boot_gap_sectors "$target_disk")"
			# 门槛用 1024 扇区（512 KiB）：ef02 分区实际只放 core.img（几十 KiB）。
			# 注意标准 1MiB 对齐布局是「第一个分区起于 2048 扇区，减去 GPT 占的 34
			# 扇区 = 2014 扇区空洞」，门槛写成 2048 会把最常见的布局判成"没空间"。
			if [ "${gap_sectors:--1}" -ge 1024 ] &&
				ensure_bios_boot_partition "$target_disk" "$gap_sectors"; then
				echo "[决策] 已在磁盘开头空洞建立 BIOS Boot 分区，使用标准模式（不改动任何已有分区）"
				GRUB_STRATEGY="standard"
			elif [ "${EXISTING_BOOT_HINT:-unknown}" = "grub" ] &&
				[ "${EXISTING_MBR_CODE:-0}" -eq 1 ] && [ "${force_embed_optin:-0}" -ne 1 ]; then
				# 空洞不够时唯一可行的路就是 blocklists。而这台机器现在就是
				# 「GPT + Legacy + 无 ef02 + 无空洞」却开得起来 —— 证据表明它本来
				# 就靠 blocklists 引导，复刻同样的方式风险可控，不必再要求 --force-embed。
				echo "[状态] 开头空洞不足以嵌入 core.img，但 MBR 里有 GRUB 引导代码 —— 现有系统本来就是 blocklists 引导"
				echo "[决策] 复刻现有方式：用 blocklists 强制嵌入 core.img（grub-install --force）"
				GRUB_STRATEGY="force_embed"
			elif [ "${force_embed_optin:-0}" -ne 1 ]; then
				# 空洞不够且无法证明现有系统用 GRUB blocklists：只能让操作者自己决定。
				# 交互时问一次；--yes 批处理仍需显式 --force-embed（否则无人复核）。
				if [ "${gap_sectors:--1}" -lt 0 ]; then
					echo "[警告] 无法从 sysfs 读出 ${target_disk} 的分区起始扇区，无法判断磁盘开头空洞大小"
				else
					echo "[警告] Legacy + GPT 磁盘 ${target_disk} 无 BIOS Boot 分区，且开头空洞只有 ${gap_sectors} 扇区（约 $((gap_sectors / 2)) KiB，<512 KiB），不足以正常嵌入 core.img"
				fi
				if [ "${assume_yes:-0}" -eq 0 ] && [ -t 0 ] &&
					ask_confirm "只能使用 blocklists 强制嵌入（文件块被移动后可能引导失败），继续？"; then
					echo "[决策] 使用 force_embed 模式（blocklists）"
					GRUB_STRATEGY="force_embed"
				else
					err "已中止（现有系统未改动）。要使用 blocklists 强制嵌入，请显式加 --force-embed 重跑；或先在分区表中创建 BIOS Boot 分区（ef02，1MiB）"
				fi
			else
				echo "[警告] GPT 磁盘缺失 BIOS Boot 分区，且已显式指定 --force-embed"
				# 这一步在抹盘之前：现在问，操作者还能 Ctrl-C 全身而退；
				# 等 install_grub 里再问，旧系统已经没了，拒绝也等于把机器留在不可引导状态。
				ask_confirm "强制嵌入会写入 GPT 保护扇区附近并可能破坏分区表，确认使用该模式？" ||
					err "用户取消强制嵌入模式（尚未抹盘，系统未改动）"
				# 确认之后必须把策略真正落到变量上：只问不赋值会让抹盘前的确认形同虚设
				# （策略仍是 standard，抹盘后 grub-install 失败，再走 --force 自救）
				GRUB_STRATEGY="force_embed"
			fi
		fi
	else
		echo "[状态] 分区表类型为 $label_type，使用标准模式。"
		GRUB_STRATEGY="standard"
	fi
	echo "------------------------------------------------"
}

# 引导菜单自检：grub.cfg 生成成功 ≠ 内容正确。
# 这里核对三件抹盘后无法补救的事：
#  1) 菜单里的 root=UUID 就是当前根文件系统（写错 = 直接掉进 initramfs 救援 shell）
#  2) 菜单里确实有一条 linux/vmlinuz 项（只有 submenu 头说明内核没被识别）
#  3) EFI 系统里 ESP 上有可执行引导文件，且 fstab 记了 ESP（否则内核升级会失败）
verify_boot_menu() {
	local cfg="/boot/grub/grub.cfg"
	[ -s "$cfg" ] || err "引导自检失败：$cfg 为空"
	grep -qE '^[[:space:]]*(linux|linuxefi)[[:space:]]' "$cfg" ||
		err "引导自检失败：$cfg 里没有任何 linux 引导项（内核没有被 update-grub 识别）"

	grub-script-check "$cfg" || err "引导自检失败：GRUB 菜单语法错误"
	grep -qE '^[[:space:]]*set default="0"[[:space:]]*$' "$cfg" ||
		err "引导自检失败：实际生成菜单没有默认选择第 0 项"
	if [ -e /boot/grub/grubenv ]; then
		local grub_state=""
		grub_state="$(grub-editenv /boot/grub/grubenv list)" || err "无法读取 GRUB 启动状态"
		if grep -qE '^(next_entry|saved_entry|prev_saved_entry|recordfail)=.+' <<<"$grub_state"; then
			err "引导自检失败：grubenv 仍有旧启动选择/失败状态"
		fi
	fi
	[ "$(awk '/^[[:space:]]*(menuentry|submenu)[[:space:]]/ {print $1; exit}' "$cfg")" = menuentry ] ||
		err "引导自检失败：首项不是可直接引导的内核菜单"
	local first_entry="" linux_line="" initrd_line=""
	first_entry="$(awk '/^[[:space:]]*(menuentry|submenu)[[:space:]]/ {n++; if(n>1) exit} n==1 {print}' "$cfg")"
	linux_line="$(awk '$1 == "linux" || $1 == "linuxefi" {print; exit}' <<<"$first_entry")"
	initrd_line="$(awk '$1 == "initrd" || $1 == "initrdefi" {print; exit}' <<<"$first_entry")"
	[ -n "$linux_line" ] && [ -n "$initrd_line" ] || err "引导自检失败：默认项缺少内核或 initramfs"

	local uuid="" cfg_uuid=""
	if [ -s "${root_dir}/root.uuid.src" ]; then
		IFS= read -r uuid <"${root_dir}/root.uuid.src" || true
	fi
	if [ -n "$uuid" ]; then
		cfg_uuid="$(awk '{for(i=1;i<=NF;i++) if ($i ~ /^root=UUID=/) {sub(/^root=UUID=/,"",$i); print $i; exit}}' <<<"$linux_line")"
		[ -n "$cfg_uuid" ] || err "引导自检失败：默认项没有 root=UUID，无法核对根设备"
		if [ "$cfg_uuid" != "$uuid" ]; then
			err "引导自检失败：grub.cfg 里的 root=UUID=$cfg_uuid 与当前根文件系统 UUID=$uuid 不一致，重启后无法挂载根"
		fi
		[ -n "$cfg_uuid" ] && echo "引导自检通过：grub.cfg 指向根文件系统 UUID=$cfg_uuid"
	else
		echo "警告：无法确定根文件系统 UUID，跳过 grub.cfg 指向校验"
	fi

	if grep -qE '(^|[[:space:]])net.ifnames=0([[:space:]]|$)' <<<"$linux_line"; then
		echo "引导自检通过：默认项内核参数包含 net.ifnames=0"
	else
		err "引导自检失败：默认项未包含 net.ifnames=0，网卡配置可能失效"
	fi

	# 旧机若在串口控制台上跑（console=ttyS0,...），新系统丢了它 = 面板上再也看不到
	# 开机过程，出问题只能重装。这属于"装完就失联"的隐形形态，必须显式校验。
	if [ -s "${root_dir}/old.cmdline.src" ] && grep -qE '^(console=ttyS|console=ttyAMA|console=hvc)' "${root_dir}/old.cmdline.src"; then
		if grep -qE 'console=ttyS|console=ttyAMA|console=hvc' <<<"$linux_line"; then
			echo "引导自检通过：新系统保留了串口控制台参数"
		else
			err "引导自检失败：旧机使用串口控制台（$(grep -E '^(console=ttyS|console=ttyAMA|console=hvc)' "${root_dir}/old.cmdline.src" | tr '
' ' ')），但 grub.cfg 里没有继承。重启后面板上将完全看不到开机过程"
		fi
	fi

	# 独立 /boot 时 GRUB 路径是 /vmlinuz-*，不是宿主命名空间的 /boot/vmlinuz-*。
	# 核对真正选中的一对文件，而不是统计安装了几个内核（多个内核本身完全正常）。
	local kernel_ref="" kernel_ver="" ref="" host_ref="" matched_initrd=0
	local -a initrd_words=()
	kernel_ref="$(awk '{print $2}' <<<"$linux_line")"
	case "$kernel_ref" in /boot/vmlinuz-* | /vmlinuz-*) ;; *) err "无法识别默认内核路径：$kernel_ref" ;; esac
	kernel_ver="${kernel_ref##*/vmlinuz-}"
	host_ref="$kernel_ref"
	if [ "${boot_separate:-0}" -eq 1 ] && [[ "$host_ref" != /boot/* ]]; then host_ref="/boot$host_ref"; fi
	[ -s "$host_ref" ] || err "引导自检失败：默认内核文件不存在或为空：$host_ref"
	read -r -a initrd_words <<<"$initrd_line"
	for ref in "${initrd_words[@]:1}"; do
		[[ "$ref" == /* ]] || err "无法识别默认 initramfs 路径：$ref"
		host_ref="$ref"
		if [ "${boot_separate:-0}" -eq 1 ] && [[ "$host_ref" != /boot/* ]]; then host_ref="/boot$host_ref"; fi
		[ -s "$host_ref" ] || err "引导自检失败：默认 initramfs 文件不存在或为空：$host_ref"
		case "${ref##*/}" in "initrd.img-$kernel_ver" | "initramfs-$kernel_ver.img") matched_initrd=1 ;; esac
	done
	[ "$matched_initrd" -eq 1 ] || err "引导自检失败：默认 initramfs 与内核 $kernel_ver 版本不匹配"
	echo "引导自检通过：默认内核/initramfs 存在且版本配对（$kernel_ver）"

	# BIOS 模式：引导代码在磁盘第一个扇区的 440 字节里。grub-install 报成功
	# 但实际没写进去的情况真的存在（设备被 dm/multipath 包了一层时尤甚），
	# 这里直接读盘确认那段不是全零。
	if [ "${IS_EFI:-0}" -ne 1 ]; then
		local mbr_hex=""
		mbr_hex="$(dd if="$grub_device" bs=440 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')"
		case "$mbr_hex" in
		"")
			echo "警告：无法读取 $grub_device 的第一个扇区，跳过 MBR 引导代码校验"
			;;
		*[!0]*)
			echo "引导自检通过：$grub_device 的 MBR 引导代码区非空"
			;;
		*) err "引导自检失败：$grub_device 的 MBR 引导代码区全为零，grub-install 实际没有写入引导" ;;
		esac
	fi

	if [ "${IS_EFI:-0}" -eq 1 ]; then
		local efi_dir="/boot/efi"
		if [ -s "${root_dir}/esp.src" ]; then
			IFS= read -r efi_dir <"${root_dir}/esp.src" || true
		fi
		[ -n "$efi_dir" ] || efi_dir="/boot/efi"
		if [ -f "$efi_dir/EFI/BOOT/BOOTX64.EFI" ] || [ -f "$efi_dir/EFI/BOOT/BOOTAA64.EFI" ]; then
			echo "引导自检通过：$efi_dir 上存在固件默认引导文件"
		else
			err "引导自检失败：$efi_dir/EFI/BOOT/ 下没有 BOOTX64.EFI/BOOTAA64.EFI，部分固件将找不到引导项"
		fi
		grep -q "$efi_dir" /etc/fstab 2>/dev/null ||
			echo "警告：/etc/fstab 中没有 $efi_dir 条目，后续内核升级可能失败"

		# NVRAM 里有没有我们的引导项，决定了固件会不会主动去找它。
		# 没有的话只能靠 EFI/BOOT/BOOTX64.EFI 默认路径，部分服务器固件不认，需要人工加。
		if command -v efibootmgr >/dev/null 2>&1; then
			if pipe_grep_qi "$system" efibootmgr; then
				echo "引导自检通过：NVRAM 中存在 $system 引导项"
			else
				echo "警告：NVRAM 中没有 $system 引导项（efivarfs 可能只读）。重启后在固件里手工添加 $efi_dir/EFI/BOOT/BOOTX64.EFI 作为引导项"
			fi
		fi
	fi
	return 0
}

finalize_install() {
	if command -v apt >/dev/null 2>&1; then
		echo "检测到 apt，系统安装成功"
	else
		err "系统安装失败，未找到 apt 命令"
	fi

	# 重启前的最后自检：这些都是"重启后才发现坏了"的东西，此时补救成本极高
	local kernel="" initrd=""
	kernel="$(find /boot -maxdepth 1 -type f -name 'vmlinuz-*' 2>/dev/null | head -1)"
	initrd="$(find /boot -maxdepth 1 -type f \( -name 'initrd.img-*' -o -name 'initramfs-*' \) 2>/dev/null | head -1)"
	[ -n "$kernel" ] || err "自检失败：/boot 下没有内核（重启将无法引导）"
	[ -n "$initrd" ] || err "自检失败：/boot 下没有 initramfs（重启将无法引导）"
	[ -s /boot/grub/grub.cfg ] || err "自检失败：/boot/grub/grub.cfg 缺失或为空（GRUB 没有生成菜单）"
	[ -s /etc/fstab ] || echo "警告：/etc/fstab 为空，建议重启后手工补齐非根挂载"
	[ -f /etc/ssh/sshd_config ] || err "自检失败：/etc/ssh/sshd_config 缺失，重启后将无法 SSH 登录"
	[ -x /usr/sbin/sshd ] || [ -x /usr/local/sbin/sshd ] || [ -x /sbin/sshd ] ||
		err "自检失败：sshd 未安装"

	# 内核必须有根磁盘的存储驱动，否则重启后连根文件系统都挂不上
	verify_root_driver_installed

	# 引导菜单必须真的指向新根 — grub.cfg 生成成功不等于内容对
	verify_boot_menu

	echo "重启前自检通过：内核 $kernel，initramfs $initrd"

	if [ -n "$root_dir" ] && [ "$root_dir" != "/" ]; then
		rm -rf "$root_dir" || echo "警告：无法删除 $root_dir 目录"
	else
		echo "警告：root_dir 取值异常（'$root_dir'），跳过清理以免误删"
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
	# 只读查询：不需要 root，也不应触发任何交互或网络访问
	if [ "$print_image_pins" -eq 1 ]; then
		local rows=""
		rows="$(image_pin_table | grep -vE '^[[:space:]]*(#|$)')"
		if [ -z "$rows" ]; then
			echo "内置镜像指纹表为空。"
			echo "补录方式：curl -fsSL '<镜像站>/<version>/<arch>/cloud/<timestamp>/SHA256SUMS'"
			echo "取其中 rootfs.tar.xz 那一行，按 system|version|arch|timestamp|sha256 写入 image_pin_table()。"
		else
			printf '%s\n' "$rows"
		fi
		exit 0
	fi

	require_root
	ensure_usr_bin_bash

	# 半新半旧检测：抹盘阶段被中断（脚本被 Ctrl-C 杀掉、机器掉电、被 kill -9）
	# 时 /bin/sh 可能已经没了，二次运行会在一个既非旧系统也非新系统的环境里
	# 重新选盘、重新抹盘 —— 必须显式确认。
	if [ -f "${root_dir}/WIPE_STARTED" ]; then
		echo "检测到上次运行在删除旧系统阶段中断："
		sed 's/^/  /' "${root_dir}/WIPE_STARTED"
		echo "  / 顶层剩余条目：$(find / -xdev -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
		if [ "$resume_partial" -ne 1 ]; then
			err "系统可能处于部分删除状态。确认要继续请加 --resume-partial（或先用救援系统检查）"
		fi
		echo "已按 --resume-partial 继续"
	fi

	init_work_dir
	resolve_password_source
	# 口令读完立刻从环境里清掉：否则后续 apt-get/dpkg 的 maintainer script
	# 都能在 /proc/<pid>/environ 里看到新 root 口令
	unset REINSTALL_PASSWORD 2>/dev/null || true

	# 破坏窗口内的信号处理：默认行为下 Ctrl-C/SIGHUP 会在删到一半时退出，
	# 留下既进不去旧系统也没有新系统的机器。这里在 EXIT 时给出可操作的处置提示。
	# 抹盘前阶段不能沿用同一句文案（那时旧系统完好，说"可能处于部分删除状态"会误导）。
	trap 'if [ "${wipe_phase:-0}" -eq 1 ]; then echo "错误：重装过程中收到中断信号，系统可能处于部分删除状态，请勿重启，进救援介质处理" >&2; else echo "已中断（抹盘尚未开始，旧系统未改动）" >&2; fi; exit 130' INT TERM HUP

	require_tools
	set_arch_vars
	set_network
	net_mode
	choose_system
	# RTC 偏差大时 HTTPS 证书都验不过，连镜像列表都取不到；下载前先校一次时间。
	# 用镜像站首页的 Date 头，不依赖具体版本目录是否可访问。
	sync_clock_from_url "$base_url/" || true
	get_versions
	detect_disk
	auto_detect_grub_mode
	download_image
	preflight_image

	# 破坏性动作前的最后确认：文案必须说清"抹的是运行中的根"，而不是 $grub_device
	local root_src=""
	if command -v findmnt >/dev/null 2>&1; then
		root_src="$(findmnt -no SOURCE / 2>/dev/null)"
	fi
	echo "------------------------------------------------"
	# 内核选型要在抹盘前算出来：抹盘后 root.driver.src 才有值，
	# 但 dry-run 摘要和"到底装哪个内核"的提示必须提前给操作者看见。
	detected_root_driver="$(probe_root_driver || true)"
	resolve_kernel_packages || err "无法确定内核软件包"

	echo "将抹除：/ 所在文件系统（${root_src:-未知设备}）上的全部文件"
	echo "引导设备：$grub_device（引导模式：$GRUB_STRATEGY）"
	if [ "${boot_separate:-0}" -eq 1 ]; then
		echo "额外清理：独立 /boot 中的旧内核与 GRUB 文件（保留 ESP/EFI 目录）"
	fi
	echo "将安装：$system $selected_version（$image_arch）"
	echo "网络：$( [ "$is_auto" -eq 1 ] && echo "静态 $main_ip/$netmask 网关 $gateway_ip" || echo "DHCP（$network_adapter）" )"
	echo "内核：$kernel_pkg"
	echo "------------------------------------------------"

	if [ "$dry_run" -eq 1 ]; then
		echo "[dry-run] 预检全部通过，未执行任何破坏性动作。"
		echo "[dry-run] 去掉 --dry-run 即为实际执行。已下载镜像将被清理，不占磁盘。"
		# 只删本次产生的下载产物；/os 原本不存在时整个目录一起清掉。
		# --dry-run 不该在别人机器上留下 128MB 的 rootfs.tar.xz。
		if [ "${root_dir_created:-0}" -eq 1 ]; then
			rm -rf "$root_dir"
		else
			rm -f "$root_dir/os.tar.xz" "$root_dir/busybox" "$root_dir"/busybox.part.* \
				"$root_dir/SHA256SUMS" "$root_dir/resolv.conf.bak" 2>/dev/null
		fi
		return 0
	fi

	ask_confirm "以上操作不可逆，确认抹除并继续？" || err "用户取消"

	# 抹盘前最后一次「不依赖旧系统也能活下去」的准备：
	# 把新系统开机必需的包落到 $root_dir（抹盘时唯一被排除的目录）。
	stage_offline_packages || true

	# 从这里开始进入不可逆阶段：信号 trap 的文案据此切换
	wipe_phase=1
	delete_old_system || err "删除旧系统失败，已中止"
	extract_image
	init_os
	finalize_install
	reboot_prompt
}

main "$@"
