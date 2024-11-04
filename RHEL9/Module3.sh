#!/usr/bin/env bash

# Task 3.1.1: Ensure IPv6 status is identified (Manual)
if sysctl -a 2>/dev/null | grep -q 'net.ipv6.conf.all.disable_ipv6 = 0'; then
  echo "IPv6 is enabled on the system."
else
  echo "IPv6 is disabled on the system."
fi

# Task 3.1.2: Ensure wireless interfaces are disabled
module_fix() {
  if ! modprobe -n -v "$l_mname" | grep -P -- '^\s*install\s+/bin/(true|false)'; then
    echo " - Setting module: \"$l_mname\" to be un-loadable"
    echo "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mname".conf
  fi

  if lsmod | grep "$l_mname" > /dev/null 2>&1; then
    echo " - Unloading module \"$l_mname\""
    modprobe -r "$l_mname"
  fi

  if ! grep -Pq -- "^\s*blacklist\s+$l_mname\b" /etc/modprobe.d/*; then
    echo " - Deny listing \"$l_mname\""
    echo "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
  fi
}

if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
  l_dname=$(find /sys/class/net/*/ -type d -name wireless | xargs -I{} dirname {} | xargs -I{} readlink -f {}/device/driver/module | xargs -I{} basename {} | sort -u)
  for l_mname in $l_dname; do
    module_fix
  done
fi

# Task 3.1.3: Ensure bluetooth services are not in use
systemctl stop bluetooth.service
systemctl mask bluetooth.service

# Task 3.2.x: Ensure 'x' kernel module is not available
f_module_fix() {
  l_dl="y"
  a_showconfig=()

  while IFS= read -r l_showconfig; do
    a_showconfig+=("$l_showconfig")
  done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_name//-/_}"'\b')

  if lsmod | grep "$l_mod_name" &> /dev/null; then
    a_output2+=("Unloading kernel module: \"$l_mod_name\"")
    modprobe -r "$l_mod_name" 2>/dev/null
    rmmod "$l_mod_name" 2>/dev/null
  fi

  if ! grep -Pq -- '\binstall\h+'"${l_mod_name//-/_}"'\h+\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
    a_output2+=("Setting kernel module: \"$l_mod_name\" to \"/bin/false\"")
    printf 'install %s /bin/false\n' "$l_mod_name" > /etc/modprobe.d/"$l_mod_name".conf
  fi

  if ! grep -Pq -- '\bblacklist\h+'"${l_mod_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
    a_output2+=("Denylisting kernel module: \"$l_mod_name\"")
    printf 'blacklist %s\n' "$l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
  fi
}

# Task 3.2.1: Ensure dccp kernel module is not available
l_mod_name="dccp"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.2.2: Ensure tipc kernel module is not available
l_mod_name="tipc"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.2.3: Ensure rds kernel module is not available
l_mod_name="rds"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.2.4: Ensure sctp kernel module is not available
l_mod_name="sctp"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.3.1: Ensure ip forwarding is disabled
ipv4_config_file="/etc/sysctl.d/60-netipv4_sysctl.conf"
printf '%s\n' "net.ipv4.ip_forward = 0" > "$ipv4_config_file"

sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

# Check if IPv6 is enabled
if sysctl -a | grep -q '^net.ipv6.conf.all.forwarding'; then
  ipv6_config_file="/etc/sysctl.d/60-netipv6_sysctl.conf"
  printf '%s\n' "net.ipv6.conf.all.forwarding = 0" > "$ipv6_config_file"

  sysctl -w net.ipv6.conf.all.forwarding=0
  sysctl -w net.ipv6.route.flush=1
fi

# Task 3.3.2: Ensure packet redirect sending is disabled
printf '%s\n' "net.ipv4.conf.all.send_redirects = 0" \
"net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# Task 3.3.3: Ensure bogus icmp responses are ignored
printf '%s\n' "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.4: Ensure broadcast icmp requests are ignored
printf '%s\n' "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.5: Ensure icmp redirects are not accepted
printf '%s\n' "net.ipv4.conf.all.accept_redirects = 0" \
"net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

# Check if IPv6 is enabled
if sysctl -a | grep -q 'net.ipv6.conf.all.forwarding'; then
  printf '%s\n' "net.ipv6.conf.all.accept_redirects = 0" \
  "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
  
  sysctl -w net.ipv6.conf.all.accept_redirects=0
  sysctl -w net.ipv6.conf.default.accept_redirects=0
  sysctl -w net.ipv6.route.flush=1
fi


# Task 3.3.6: Ensure secure icmp redirects are not accepted
printf '%s\n' "net.ipv4.conf.all.secure_redirects = 0" \
"net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1


# Task 3.3.7: Ensure reverse path filtering is enabled
printf '%s\n' "net.ipv4.conf.all.rp_filter = 1" \
"net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.8: Ensure source routed packets are not accepted
printf '%s\n' "net.ipv4.conf.all.accept_source_route = 0" \
"net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

if sysctl -a | grep -q 'net.ipv6.conf.all.forwarding'; then
  printf '%s\n' "net.ipv6.conf.all.accept_source_route = 0" \
  "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf

  sysctl -w net.ipv6.conf.all.accept_source_route=0
  sysctl -w net.ipv6.conf.default.accept_source_route=0
  sysctl -w net.ipv6.route.flush=1
fi

# Task 3.3.9: Ensure suspicious packets are logged
printf '%s\n' "net.ipv4.conf.all.log_martians = 1" \
"net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.10: Ensure tcp syn cookies is enabled
printf '%s\n' "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.11: Ensure ipv6 router advertisements are not accepted
if sysctl -a | grep -q 'net.ipv6.conf.all.accept_ra'; then
  printf '%s\n' "net.ipv6.conf.all.accept_ra = 0" \
  "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf

  sysctl -w net.ipv6.conf.all.accept_ra=0
  sysctl -w net.ipv6.conf.default.accept_ra=0
  sysctl -w net.ipv6.route.flush=1
fi


### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################