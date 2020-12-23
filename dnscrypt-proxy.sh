dnsmasq_install=1
if [[ ${dnsmasq_install} == 1 ]]; then
  if [[ ! -d /etc/dnscrypt-proxy/ ]]; then
    mkdir /etc/dnscrypt-proxy/
  fi
ipv6_true="false"
block_ipv6="true"
if [[ -n ${myipv6} ]]; then
  ping -6 ipv6.google.com -c 2 || ping -6 2620:fe::10 -c 2
  if [[ $? -eq 0 ]]; then
    ipv6_true="true"
    block_ipv6="false"
  fi
fi
rm -rf /etc/dnscrypt-proxy/dnscrypt-proxy.toml
    cat > '/etc/dnscrypt-proxy/dnscrypt-proxy.toml' << EOF
#!!! Do not change these settings unless you know what you are doing !!!
listen_addresses = ['127.0.0.1:53','[::1]:53']
#user_name = 'nobody'
max_clients = 51200
ipv4_servers = true
ipv6_servers = $ipv6_true
dnscrypt_servers = true
doh_servers = true
require_dnssec = false
require_nolog = true
require_nofilter = true
#disabled_server_names = ['cisco', 'cisco-ipv6', 'cisco-familyshield']
force_tcp = false
timeout = 5000
keepalive = 30
lb_estimator = true
log_level = 2
use_syslog = true
log_file = '/var/log/dnscrypt-proxy/dnscrypt-proxy.log'
cert_refresh_delay = 86400
tls_disable_session_tickets = false
#tls_cipher_suite = [4865]
fallback_resolvers = ['1.1.1.1:53', '8.8.8.8:53']
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '1.1.1.1:53'
# Maximum log files size in MB - Set to 0 for unlimited.
log_files_max_size = 1024
# How long to keep backup files, in days
log_files_max_age = 7
# Maximum log files backups to keep (or 0 to keep all backups)
log_files_max_backups = 0
block_ipv6 = false
## Immediately respond to A and AAAA queries for host names without a domain name
block_unqualified = true
## Immediately respond to queries for local zones instead of leaking them to
## upstream resolvers (always causing errors or timeouts).
block_undelegated = true
## TTL for synthetic responses sent when a request has been blocked (due to
## IPv6 or blacklists).
reject_ttl = 600
cache = true
cache_size = 4096
cache_min_ttl = 2400
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
#[local_doh]
#
#listen_addresses = ['127.0.0.1:3001']
#path = "/dns-query"
#cert_file = "/etc/certs/${domain}_ecc/fullchain.cer"
#cert_key_file = "/etc/certs/${domain}_ecc/${domain}.key"
[query_log]
  file = '/var/log/dnscrypt-proxy/query.log'
  format = 'tsv'

#[blacklist]

  #blacklist_file = '/etc/dnscrypt-proxy/blacklist.txt'

[sources]
  ## An example of a remote source from https://github.com/DNSCrypt/dnscrypt-resolvers
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md']
  cache_file = 'public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  prefix = ''
  [sources.'opennic']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/opennic.md', 'https://download.dnscrypt.info/dnscrypt-resolvers/v3/opennic.md']
  cache_file = 'opennic.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  prefix = ''
  ## Anonymized DNS relays
  [sources.'relays']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md', 'https://download.dnscrypt.info/resolvers-list/v3/relays.md']
  cache_file = 'relays.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  prefix = ''
EOF
rm -rf /etc/systemd/system/dnscrypt-proxy.service
  cat > '/etc/systemd/system/dnscrypt-proxy.service' << EOF
[Unit]
Description=DNSCrypt client proxy
Documentation=https://github.com/DNSCrypt/dnscrypt-proxy/wiki
After=network.target
Before=nss-lookup.target netdata.service
Wants=nss-lookup.target

[Service]
#User=nobody
NonBlocking=true
ExecStart=/usr/sbin/dnscrypt-proxy -config /etc/dnscrypt-proxy/dnscrypt-proxy.toml
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
CacheDirectory=dnscrypt-proxy
LogsDirectory=dnscrypt-proxy
RuntimeDirectory=dnscrypt-proxy
LimitNOFILE=51200
LimitNPROC=51200
Restart=on-failure
RestartSec=3s
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable dnscrypt-proxy.service
clear
colorEcho ${INFO} "Install dnscrypt-proxy ing"
if [[ $(systemctl is-active dnsmasq) == active ]]; then
	systemctl stop dnsmasq
	systemctl disable dnsmasq
fi
dnsver=$(curl -s "https://api.github.com/repos/DNSCrypt/dnscrypt-proxy/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
curl -LO --progress-bar https://github.com/DNSCrypt/dnscrypt-proxy/releases/download/${dnsver}/dnscrypt-proxy-linux_x86_64-${dnsver}.tar.gz
tar -xvf dnscrypt-proxy-linux_x86_64-${dnsver}.tar.gz
rm dnscrypt-proxy-linux_x86_64-${dnsver}.tar.gz
cd linux-x86_64
cp -f dnscrypt-proxy /usr/sbin/dnscrypt-proxy
chmod +x /usr/sbin/dnscrypt-proxy
cd ..
rm -rf linux-x86_64
setcap CAP_NET_BIND_SERVICE=+eip /usr/sbin/dnscrypt-proxy
wget --no-check-certificate -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md -q --show-progress
wget --no-check-certificate -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/opennic.md -q --show-progress
wget --no-check-certificate -P /etc/dnscrypt-proxy/ https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md -q --show-progress
fi
chmod -R 755 /etc/dnscrypt-proxy/
clear
if [[ $dnsmasq_install -eq 1 ]]; then
			if [[ $dist = ubuntu ]]; then
	 			systemctl stop systemd-resolved
	 			systemctl disable systemd-resolved
 			fi
			if [[ $(systemctl is-active dnsmasq) == active ]]; then
				systemctl stop dnsmasq
				systemctl disable dnsmasq
			fi
		rm /etc/resolv.conf
		touch /etc/resolv.conf
		echo "nameserver 127.0.0.1" > '/etc/resolv.conf'
		echo "options edns0 single-request-reopen" > '/etc/resolv.conf'
		systemctl start dnscrypt-proxy
fi
