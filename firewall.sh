#!/bin/sh
### BEGIN INIT INFO
# Provides:          firewall
# Required-Start:    mountkernfs $local_fs $remote_fs $syslog
# Required-Stop:
# X-Start-Before:    networking
# X-Stop-After:      networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Firewall Medlib
# Description:       Prepare the web server and clustering
### END INIT INFO
export PATH=/sbin:/usr/sbin:/bin:/usr/bin

DESC="Firewall Medlib based iptables"
NAME=firewall
DEAMON=/usr/sbin/$NAME
VERSION=1.0.0
PIDFILE=/var/run/$NAME/pid
SUCCESSFILE=/var/run/$NAME/success
FAILFILE=/var/run/$NAME/fail

iptables=`which iptables`
intif=eth0					      # External interface eth0 (Internet)
intip=164.132.110.78			# External IP 164.132.110.78/32 (Internet)
ssh_port=22					      # Open SSH connection in 22 for Firewall & DNS Server

### check the command exist status
test -x $iptables || exit 0
set -e

if [ ! -d /var/run/$NAME/ ]; then
   mkdir -p /var/run/$NAME/
fi

SCRIPTNAME="${0##*/}"
SCRIPTNAME="${SCRIPTNAME##[KS] [0-9][0-9]}"

function print_error_msg() {}

function print_version() {
	echo $NAME version v$VERSION
	exit 0
}

function print_usage() {
	echo "Usage:
	$* [-v] Version
	$* [start] Starting, [stop] Stopping, [restart] Restarting" >&2
	exit 0
}

function iptables_v4() {
	$iptables $@
}

function flush_tables() {
 	# -- On vide les règles --
	iptables_v4 -F
	iptables_v4 -t filter -F
	iptables_v4 -t mangle -F
	iptables_v4 -t nat -F

	iptables_v4 -X
	iptables_v4 -t filter -X
	iptables_v4 -t mangle -X
	iptables_v4 -t nat -X
}

function do_start() {
	echo 1 > /proc/sys/net/ipv4/ip_forward
	flush_tables
	# Default policy
	iptables_v4 -P INPUT DROP
	iptables_v4 -P FORWARD DROP
	iptables_v4 -P OUTPUT DROP

	# Accept everything from loopback
	iptables_v4 -A INPUT  -i lo -j ACCEPT
	iptables_v4 -A OUTPUT -o lo -j ACCEPT

	# accept ICMP packets (ping et.al.)
	iptables_v4 -A INPUT  -i ${intif} -d ${intip} -p icmp -j ACCEPT

	# internet (established and out)
	iptables_v4 -A OUTPUT -o ${intif} -j ACCEPT
	iptables_v4 -A INPUT  -i ${intif} -m state --state ESTABLISHED,RELATED -j ACCEPT

	# public services
	iptables_v4 -A INPUT -i ${intif} -p tcp -d ${intip} -m multiport --dports domain,http,https,ftp-data,ftp -j ACCEPT

	# log all the rest before dropping
	log="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
	log="$log --log-ip-options"
	rlimit="-m limit --limit 1/min --limit-burst 8"
	prefix="--log-prefix Paquet-inattendu: "

	iptables_v4 -A INPUT -p tcp -j $log $rlimit $prefix
	iptables_v4 -A INPUT -p tcp -j REJECT --reject-with tcp-reset
	iptables_v4 -A INPUT -p udp -j $log $rlimit $prefix
	iptables_v4 -A INPUT -p icmp -j $log $rlimit $prefix
	iptables_v4 -A INPUT -j REJECT

	iptables_v4 -A OUTPUT  -j $log $rlimit $prefix
	iptables_v4 -A FORWARD -j $log $rlimit $prefix

	#$DAEMON
   	if [ "${?}" = "0" ]; then
   		touch /var/run/$NAME/success
   		return 0
   	else
   		touch /var/run/$NAME/fail
   		return 2
   	fi
}
