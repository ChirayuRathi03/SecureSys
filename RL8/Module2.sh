#!/usr/bin/env bash

# Task 2.1.1: Ensure time synchronization is in use
dnf install chrony

# Task 2.1.2: Ensure chrony is configured
read -p "Enter the remote server address: " remote_server

conf_file="/etc/chrony.conf"
conf_dir="/etc/chrony.d"
conf_additional="${conf_dir}/remote_server.conf"

add_or_edit_server_line() {
  local file="$1"
  local server="$2"
  if grep -q "^server" "$file"; then
    # If the line exists, modify it
    sed -i "s/^server.*/server $server/" "$file"
  else
    # If the line does not exist, add it to the end of the file
    echo "server $server" >> "$file"
  fi
}

# Add or edit the server line in the main configuration file
add_or_edit_server_line "$conf_file" "$remote_server"

if [ ! -d "$conf_dir" ]; then
  mkdir "$conf_dir"
fi

add_or_edit_server_line "$conf_additional" "$remote_server"

# Check if the operation was successful
if grep -q "^server $remote_server" "$conf_file" || grep -q "^server $remote_server" "$conf_additional"; then
  echo "Successfully added/modified the server line in chrony configuration."
else
  echo "Failed to add/modify the server line in chrony configuration."
fi

systemctl restart chronyd

# Task 2.1.3: Ensure chrony is not run as the root user
sysconfig_file="/etc/sysconfig/chronyd"
service_name="chronyd"

remove_root_chrony() {
  if grep -q '^OPTIONS=' "$sysconfig_file"; then
    # Remove -u root from OPTIONS line
    sed -i 's/\(OPTIONS="[^"]*\)-u root\([^"]*"\)/\1\2/' "$sysconfig_file"
    echo "Updated OPTIONS line to remove '-u root'."
  else
    # If OPTIONS line doesn't exist, do nothing
    echo "OPTIONS line not found in $sysconfig_file."
  fi
}

remove_root_chrony

if systemctl reload-or-restart "$service_name"; then
  echo "Successfully reloaded/restarted $service_name service."
else
  echo "Failed to reload/restart $service_name service. Please check the service status."
fi

# Task 2.2.1: Ensure autofs services are not in use
systemctl stop autofs.service
systemctl mask autofs.service

# Task 2.2.2: Ensure avahi daemon services are not in use
systemctl stop avahi-daemon.socket avahi-daemon.service
systemctl mask avahi-daemon.socket avahi-daemon.service

# Task 2.2.3: Ensure dhcp server services are not in use
systemctl stop dhcpd.service dhcpd6.service
systemctl mask dhcpd.service dhcpd6.service

# Task 2.2.4: Ensure dns server services are not in use
systemctl stop named.service
systemctl mask named.service

# Task 2.2.5: Ensure dnsmasq services are not in use
systemctl stop dnsmasq.service
systemctl mask dnsmasq.service

# Task 2.2.6: Ensure samba file server services are not in use
systemctl stop smb.service
systemctl mask smb.service

# Task 2.2.7: Ensure ftp server services are not in use
systemctl stop vsftpd.service
systemctl mask vsftpd.service

# Task 2.2.8 Ensure message access server services are not in use
systemctl stop dovecot.socket dovecot.service cyrus-imapd.service
systemctl mask dovecot.socket dovecot.service cyrus-imapd.service

# Task 2.2.9: Ensure network file system services are not in use
systemctl stop nfs-server.service
systemctl mask nfs-server.service

# Task 2.2.10: Ensure nis server services are not in use
systemctl stop ypserv.service
systemctl mask ypserv.service

# Task 2.2.11: Ensure print server services are not in use
systemctl stop cups.socket cups.service
systemctl mask cups.socket cups.service

# Task 2.2.12: Ensure rpcbind services are not in use
systemctl stop rpcbind.socket rpcbind.service
systemctl mask rpcbind.socket rpcbind.service

# Task 2.2.13: Ensure rsync services are not in use
systemctl stop rsyncd.socket rsyncd.service
systemctl mask rsyncd.socket rsyncd.service

# Task 2.2.14: Ensure snmp services are not in use
systemctl stop snmpd.service
systemctl mask snmpd.service

# Task 2.2.15: Ensure telnet server services are not in use
systemctl stop telnet.socket
systemctl mask telnet.socket

# Task 2.2.16: Ensure tftp server services are not in use
systemctl stop tftp.socket tftp.service
systemctl mask tftp.socket tftp.service

# Task 2.2.17: Ensure web proxy server services are not in use
systemctl stop squid.service
systemctl mask squid.service

# Task 2.2.18: Ensure web server services are not in use
systemctl stop httpd.socket httpd.service nginx.service
systemctl mask httpd.socket httpd.service nginx.service

# Task 2.2.19: Ensure xinetd services are not in use
systemctl stop xinetd.service
systemctl mask xinetd.service

# Task 2.2.20: Ensure X window server services are not in use
dnf remove xorg-x11-server-common &> /dev/null

# Task 2.2.21: Ensure mail transfer agents are configured for local-only mode
conf_file="/etc/postfix/main.cf"
line_to_add="inet_interfaces = loopback-only"

if [ ! -f "$conf_file" ]; then
  echo "Error: File $conf_file does not exist."
fi

# Add or modify the line in the configuration file
if grep -q "^inet_interfaces" "$conf_file"; then
  sed -i "s/^inet_interfaces.*/$line_to_add/" "$conf_file"
else
  echo "$line_to_add" >> "$conf_file"
fi

if grep -q "^inet_interfaces = loopback-only" "$conf_file"; then
  echo "Successfully added/modified the line in $conf_file."
else
  echo "Failed to add/modify the line in $conf_file."
  exit 1
fi

systemctl restart postfix

if systemctl is-active --quiet postfix; then
  echo "Postfix has been successfully restarted."
else
  echo "Failed to restart postfix. Please check the service status."
fi

# Task 2.2.22: Ensure only approved services are listening on a network interface (Manual)

# Task 2.3.1: Ensure ftp client is not installed
dnf remove ftp

# Task 2.3.2: Ensure ldap client is not installed
dnf remove openldap-clients

# Task 2.3.3: Ensure nis client is not installed
dnf remove ypbind

# Task 2.3.4: Ensure telnet client is not installed
dnf remove telnet

# Task 2.3.5: Ensure tftp client is not installed
dnf remove tftp

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################