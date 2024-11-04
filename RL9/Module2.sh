#!/usr/bin/env bash

# Task 2.1.1: Ensure autofs services are not in use
systemctl stop autofs.service
systemctl mask autofs.service

# Task 2.1.2: Ensure avahi daemon services are not in use
systemctl stop avahi-daemon.socket avahi-daemon.service
systemctl mask avahi-daemon.socket avahi-daemon.service

# Task 2.1.3: Ensure dhcp server services are not in use
systemctl stop dhcpd.service dhcpd6.service
systemctl mask dhcpd.service dhcpd6.service

# Task 2.1.4: Ensure dns server services are not in use
systemctl stop named.service
systemctl mask named.service

# Task 2.1.5: Ensure dnsmasq services are not in use
systemctl stop dnsmasq.service
systemctl mask dnsmasq.service

# Task 2.1.6: Ensure samba file server services are not in use
systemctl stop smb.service
systemctl mask smb.service

# Task 2.1.7: Ensure ftp server services are not in use
systemctl stop vsftpd.service
systemctl mask vsftpd.service

# Task 2.1.8 Ensure message access server services are not in use
systemctl stop dovecot.socket dovecot.service cyrus-imapd.service
systemctl mask dovecot.socket dovecot.service cyrus-imapd.service

# Task 2.1.9: Ensure network file system services are not in use
systemctl stop nfs-server.service
systemctl mask nfs-server.service

# Task 2.1.10: Ensure nis server services are not in use
systemctl stop ypserv.service
systemctl mask ypserv.service

# Task 2.1.11: Ensure print server services are not in use
systemctl stop cups.socket cups.service
systemctl mask cups.socket cups.service

# Task 2.1.12: Ensure rpcbind services are not in use
systemctl stop rpcbind.socket rpcbind.service
systemctl mask rpcbind.socket rpcbind.service

# Task 2.1.13: Ensure rsync services are not in use
systemctl stop rsyncd.socket rsyncd.service
systemctl mask rsyncd.socket rsyncd.service

# Task 2.1.14: Ensure snmp services are not in use
systemctl stop snmpd.service
systemctl mask snmpd.service

# Task 2.1.15: Ensure telnet server services are not in use
systemctl stop telnet.socket
systemctl mask telnet.socket

# Task 2.1.16: Ensure tftp server services are not in use
systemctl stop tftp.socket tftp.service
systemctl mask tftp.socket tftp.service

# Task 2.1.17: Ensure web proxy server services are not in use
systemctl stop squid.service
systemctl mask squid.service

# Task 2.1.18: Ensure web server services are not in use
systemctl stop httpd.socket httpd.service nginx.service
systemctl mask httpd.socket httpd.service nginx.service

# Task 2.1.19: Ensure xinetd services are not in use
systemctl stop xinetd.service
systemctl mask xinetd.service

# Task 2.1.20: Ensure X window server services are not in use
dnf remove xorg-x11-server-common &> /dev/null

# Task 2.1.21: Ensure mail transfer agents are configured for local-only mode
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

# Task 2.1.22: Ensure only approved services are listening on a network interface (Manual)

# Task 2.2.1: Ensure ftp client is not installed
dnf remove ftp

# Task 2.2.2: Ensure ldap client is not installed
dnf remove openldap-clients

# Task 2.2.3: Ensure nis client is not installed
dnf remove ypbind

# Task 2.2.4: Ensure telnet client is not installed
dnf remove telnet

# Task 2.2.5: Ensure tftp client is not installed
dnf remove tftp

# Task 2.3.1: Ensure time synchronization is in use
dnf install chrony

# Task 2.3.2: Ensure chrony is configured
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

# Task 2.3.3: Ensure chrony is not run as the root user
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

# Task 2.4.1.1: Ensure cron daemon is enabled and active
systemctl unmask "$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')"
systemctl --now enable "$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')"

# Task 2.4.1.2: Ensure permissions on /etc/crontab are configured
chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# Task 2.4.1.3: Ensure permissions on /etc/cron.hourly are configured
chown root:root /etc/cron.hourly/
chmod og-rwx /etc/cron.hourly/

# Task 2.4.1.4: Ensure permissions on /etc/cron.daily are configured
chown root:root /etc/cron.daily/
chmod og-rwx /etc/cron.daily/

# Task 2.4.1.5: Ensure permissions on /etc/cron.weekly are configured
chown root:root /etc/cron.weekly/
chmod og-rwx /etc/cron.weekly/

# Task 2.4.1.6: Ensure permissions on /etc/cron.monthly are configured
chown root:root /etc/cron.monthly/
chmod og-rwx /etc/cron.monthly/

# Task 2.4.1.7: Ensure permissions on /etc/cron.d are configured
chown root:root /etc/cron.d/
chmod og-rwx /etc/cron.d/

# Task 2.4.1.8: Ensure crontab is restricted to authorized users
if command -v crontab > /dev/null 2>&1; then
  echo "Cron is installed on the system."

  # Create /etc/cron.allow if it doesn't exist
  [ ! -e "/etc/cron.allow" ] && touch /etc/cron.allow

  # Change owner to user root and group owner to group root
  chown root:root /etc/cron.allow

  # Change mode to 640 or more restrictive
  chmod 640 /etc/cron.allow

  echo "Configured /etc/cron.allow with the correct permissions."

  # If /etc/cron.deny exists, change its owner and mode
  if [ -e "/etc/cron.deny" ]; then
    chown root:root /etc/cron.deny
    chmod 640 /etc/cron.deny
    echo "Configured /etc/cron.deny with the correct permissions."
  else
    echo "/etc/cron.deny does not exist."
  fi
else
  echo "Cron is not installed on the system."
fi

# Task 2.4.2.1: Ensure at is restricted to authorized users:
if command -v at > /dev/null 2>&1; then
  echo "The 'at' package is installed on the system."

  # Determine if the group 'daemon' exists, else use 'root'
  grep -Pq '^daemon\b' /etc/group && l_group="daemon" || l_group="root"

  [ ! -e "/etc/at.allow" ] && touch /etc/at.allow && echo "Created /etc/at.allow"

  chown root:"$l_group" /etc/at.allow && echo "Changed owner and group of /etc/at.allow to root:$l_group"

  # Change mode to 640 or more restrictive
  chmod 640 /etc/at.allow && echo "Set permissions of /etc/at.allow to 640"

  # If /etc/at.deny exists, change its owner and permissions
  if [ -e "/etc/at.deny" ]; then
    chown root:"$l_group" /etc/at.deny && echo "Changed owner and group of /etc/at.deny to root:$l_group"
    chmod 640 /etc/at.deny && echo "Set permissions of /etc/at.deny to 640"
  else
    echo "/etc/at.deny does not exist."
  fi
else
  echo "The 'at' package is not installed on the system."
fi

### Written By: 
###     1. Aditi Jamsandekar
###     2. Siddhi Jani
###     3. Chirayu Rathi
############################