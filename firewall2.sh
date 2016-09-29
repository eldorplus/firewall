#!/bin/bash
#
# firewall based iptables script
#
# Written by Patrick LUZOLO SIASIA <p_luzolo@medlib.fr>
#
# Version:	@(#)firewall  1.0.1  2015-04-25 p_luzolo@medlib.fr

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
export PATH

__DAEMON__=`which iptables`
#__NAME__=firewall
__DESC__="firewall based iptables"
__init_d__=$(cd $(dirname `which $0`) && pwd)

test -x ${__DAEMON__} || exit 0

set -e

__version__=1.0.1
__lanch__=`$(which basename) $0`

iptables=`which iptables`
ip6tables=`which ip6tables`
intif=eth0					# internal interface eth0 (local)
intip=178.32.216.110		# internal IP 178.32.216.110/32 (local)
intip6=2001:41d0:8:da6e::1	# internal IP 2001:41d0:8:da6e::1/128 (local)
ssh_port=2248

function version() {
	echo "${__lanch__} version ${__version__}"
}

# Display usage.
function show_usage() {
  echo "Usage:
  $* [-v] Version 
  $* [start] Starting, [stop] Stopping, [restart] Restarting, [reload] | [force-reload] Reloading" >&2
}


function iptables_v4() {
	$iptables $@
}

function iptables_v6() {
	$ip6tables $@
}

function iptables_v4_v6() {
	$iptables $@
	$ip6tables $@
}

function start_firewall() {
	# Network protection
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies                              		# Enable syn cookies (prevent against the common 'syn flood attack')
	echo 1 > /proc/sys/net/ipv4/ip_forward                                  		# Disable Packet forwarning between interfaces
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts                 		# Ignore all ICMP ECHO and TIMESTAMP requests sent to it via broadcast/multicast
	echo 1 > /proc/sys/net/ipv4/conf/all/log_martians                       		# Log packets with impossible addresses to kernel log.
	#for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done			# Log packets with impossible addresses to kernel log.
	echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses           		# Disable logging of bogus responses to broadcast frames
	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter                          		# Do source validation by reversed path (Recommended option for single homed hosts)
	#for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done				# Enable IP spoofing protection
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects;							# Don't accept ICMP redirects.
	#for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done 		# Don't accept ICMP redirects.
	echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects                     		# Don't send ICMP redirects
	#for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done 		# Don't send ICMP redirects.
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route                		# Don't accept packets with SRR option
	#for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done	# Don't accept source routed packets.
	echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all								# Ignore all incoming ICMP echo requests.
	#for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do echo 0 > $i; done			# Disable multicast routing.
	for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done				# Disable proxy_arp.
	for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done		# Enable secure redirects, i.e. only accept ICMP redirects for gateways Helps against MITM attacks.
	for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done			# Disable bootp_relay.
	
	echo "kern.warning   /var/log/custom.log" > /etc/syslog.conf
	
	# Default policy
	iptables_v4_v6 -F
	iptables_v4_v6 -t filter -F
	iptables_v4_v6 -t mangle -F
	iptables_v4_v6 -t nat -F
	
	iptables_v4_v6 -X
	iptables_v4_v6 -t filter -X
	iptables_v4_v6 -t mangle -X
	iptables_v4_v6 -t nat -X
	
	iptables_v4_v6 -P INPUT   DROP
	iptables_v4_v6 -P FORWARD DROP
	iptables_v4_v6 -P OUTPUT  ACCEPT
	
	# Drop broadcast (do not log)
	iptables_v4 -A INPUT  -i ${intif} -d 255.255.255.255 -j DROP
	iptables_v4 -A INPUT  -i ${intif} -d 192.168.255.255 -j DROP
	iptables_v4 -A INPUT  -i ${intif} -d 192.168.1.255   -j DROP
	iptables_v4 -A INPUT              -d 10.0.0.0/8      -j DROP
	iptables_v4 -A INPUT              -d 169.254.0.0/16  -j DROP
	
	# Drop Bad Guys
	iptables_v4_v6 -A INPUT -m recent --rcheck --seconds 60 -m limit --limit 10/second -j LOG --log-prefix "BG "
	iptables_v4_v6 -A INPUT -m recent --update --seconds 60 -j DROP
	
	# Drop spoofed packets (i.e. packets with local source addresses coming from outside etc.), mark as Bad Guy
	iptables_v4 -A INPUT -i ${initif} -s ${initip} -m recent --set -j DROP
	iptables_v6 -A INPUT -i ${initif} -s ${initip6} -m recent --set -j DROP

	# Drop silently well-known virus/port scanning attempts
	iptables_v4_v6 -A INPUT  -i ${intif} -m multiport -p tcp --dports 53,113,135,137,139,445 -j DROP
	iptables_v4_v6 -A INPUT  -i ${intif} -m multiport -p udp --dports 53,113,135,137,139,445 -j DROP
	iptables_v4_v6 -A INPUT  -i ${intif} -p udp --dport 1026 -j DROP
	iptables_v4_v6 -A INPUT  -i ${intif} -m multiport -p tcp --dports 1433,4899 -j DROP
	
	# Accept everything from loopback
	iptables_v4_v6 -A INPUT -i lo -j ACCEPT
	iptables_v4_v6 -A OUTPUT -o lo -j ACCEPT
	
	# Forward
	iptables_v4 -t nat -A POSTROUTING -s 192.168.56.0/24 -o eth0 -j MASQUERADE

	# Accept ICMP packets (ping et.al.)
	iptables_v4_v6 -A INPUT -p icmp -m recent --name ICMP --update --seconds 60 --hitcount 6 -j DROP
	iptables_v4_v6 -A INPUT -p icmp -m recent --set --name ICMP -j ACCEPT

	# Internet (established and out)
	iptables_v4_v6 -A OUTPUT -o ${intif} -j ACCEPT
	iptables_v4_v6 -A INPUT  -i ${intif} -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	# Public services
	iptables_v4 -A INPUT -i ${intif} -p tcp -d ${intip} -m multiport --dports domain,http,https,ftp-data,ftp,8080,9000,9001 -j ACCEPT	# smtp,imap,imaps
	iptables_v6 -A INPUT -i ${intif} -p tcp -d ${intip6} -m multiport --dports domain,http,https,ftp-data,ftp,8080,9000,9001 -j ACCEPT # smtp,imap,imaps
	
	# Accept ssh connections (max 2/minute from the same IP address)
	iptables_v4_v6 -N LOGGINGSSH
	
	iptables_v4_v6 -A INPUT -p tcp --dport 2248 -m recent --rcheck --seconds 60 --hitcount 2 --name SSH -j LOG --log-prefix "Firewall-Dropped-SSH " --log-level 7
	iptables_v4_v6 -A INPUT -p tcp --dport 2248 -m recent --update --seconds 60 --hitcount 2 --name SSH -j DROP
	iptables_v4_v6 -A INPUT -p tcp --dport 2248 -m state --state NEW -m recent --set --name SSH -j ACCEPT
	
	# Log all the rest before dropping
	log="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
	log="$log --log-ip-options"
	rlimit="-m limit --limit 1/min --limit-burst 8"
	prefix="--log-prefix Paquet-inattendu: "
	
	iptables_v4_v6 -A INPUT -p tcp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -p tcp -j REJECT --reject-with tcp-reset
	iptables_v4_v6 -A INPUT -p udp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -p icmp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -j REJECT
	
	iptables_v4_v6 -A OUTPUT  -j $log $rlimit $prefix
	iptables_v4_v6 -A FORWARD -j $log $rlimit $prefix
}

function start_fallback() {
	
	# Flush rules
	iptables_v4_v6 -F
	iptables_v4_v6 -t filter -F
	iptables_v4_v6 -t mangle -F
	iptables_v4_v6 -t nat -F
	
	iptables_v4_v6 -X
	iptables_v4_v6 -t filter -X
	iptables_v4_v6 -t mangle -X
	iptables_v4_v6 -t nat -X
	
	# Default policy
	iptables_v4_v6 -P INPUT DROP
	iptables_v4_v6 -P FORWARD DROP
	iptables_v4_v6 -P OUTPUT DROP
	
	# Accept everything from loopback
	iptables_v4_v6 -A INPUT  -i lo -j ACCEPT
	iptables_v4_v6 -A OUTPUT -o lo -j ACCEPT
	
	# accept ICMP packets (ping et.al.)
	iptables_v4 -A INPUT  -i ${intif} -d ${intip} -p icmp -j ACCEPT
	iptables_v6 -A INPUT  -i ${intif} -d ${intip6} -p icmp -j ACCEPT
	
	# internet (established and out)
	iptables_v4_v6 -A OUTPUT -o ${intif} -j ACCEPT
	iptables_v4_v6 -A INPUT  -i ${intif} -m state --state ESTABLISHED,RELATED -j ACCEPT

	# public services
	iptables_v4 -A INPUT -i ${intif} -p tcp -d ${intip} -m multiport --dports domain,http,https,ftp-data,ftp -j ACCEPT
	iptables_v6 -A INPUT -i ${intif} -p tcp -d ${intip6} -m multiport --dports domain,http,https,ftp-data,ftp -j ACCEPT
	
	# log all the rest before dropping
	log="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
	log="$log --log-ip-options"
	rlimit="-m limit --limit 1/min --limit-burst 8"
	prefix="--log-prefix Paquet-inattendu: "
	
	iptables_v4_v6 -A INPUT -p tcp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -p tcp -j REJECT --reject-with tcp-reset
	iptables_v4_v6 -A INPUT -p udp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -p icmp -j $log $rlimit $prefix
	iptables_v4_v6 -A INPUT -j REJECT
	
	iptables_v4_v6 -A OUTPUT  -j $log $rlimit $prefix
	iptables_v4_v6 -A FORWARD -j $log $rlimit $prefix	
}

function stop_firewall() {
	# Flush rules
	iptables_v4_v6 -F
	iptables_v4_v6 -t filter -F
	iptables_v4_v6 -t mangle -F
	iptables_v4_v6 -t nat -F
	
	iptables_v4_v6 -X
	iptables_v4_v6 -t filter -X
	iptables_v4_v6 -t mangle -X
	iptables_v4_v6 -t nat -X

	# Default policy
	iptables_v4_v6 -P INPUT   ACCEPT
	iptables_v4_v6 -P FORWARD ACCEPT
	iptables_v4_v6 -P OUTPUT  ACCEPT
}

function reload_firewall() {
	stop_firewall
	sleep 1
	#iptables_v4_v6 -L | grep ACCEPT | grep ${ssh_port} > /dev/null
	#if [ $? == "0" ] && [ $1 != "force-reload" ]; then
	#	continue
	#fi
	start_firewall || start_fallback
	
}

function error() {
  echo "${__lanch__} ERROR: $*" >/dev/stderr
  #echo "${__lanch__} ERROR: $*" 1>&2
}

function check_root() {
  # Check that we're root.
  if [ `whoami` != 'root' ]; then
    error "Please run this script as root."
    exit 1
  fi
}

function firewall_main() {

  check_root
  case ${1} in
  	start)
  		echo -n "Starting ${__DESC__}: "
  		start_firewall || start_fallback
  		echo "done."
  		;;
  	stop)
  		echo -n "Stopping ${__DESC__}: "
  		stop_firewall
  		echo "done."
  		;;
  	restart|reload|force-reload)
  		echo -n "Restarting $DESC: "
  		reload_firewall
  		echo "done."
  		;;
  	-v)
  		version
  		;;
  	*)
		#N=/etc/init.d/$__NAME__
		N=$__init_d__/$__lanch__
		show_usage $N
		exit 1
		;;
	esac
	
	exit 0
}

firewall_main $@
