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

# Task 3.4.1.1: Ensure nftables is installed
dnf install nftables -y

# Task 3.4.1.2: Ensure a single firewall configuration utility is in use
l_fwd_status="" l_nft_status="" l_fwutil_status=""

rpm -q firewalld > /dev/null 2>&1 && l_fwd_status="$(systemctl is-enabled firewalld.service):$(systemctl is-active firewalld.service)"
rpm -q nftables > /dev/null 2>&1 && l_nft_status="$(systemctl is-enabled nftables.service):$(systemctl is-active nftables.service)"

l_fwutil_status="$l_fwd_status:$l_nft_status"

case $l_fwutil_status in
    enabled:active:masked:inactive|enabled:active:disabled:inactive)
        echo -e "\n - FirewallD is enabled and active\n - NFTables is disabled or masked and inactive\n - no remediation required" ;;
    masked:inactive:enabled:active|disabled:inactive:enabled:active)
        echo -e "\n - NFTables is enabled and active\n - FirewallD is disabled or masked and inactive\n - no remediation required" ;;
    enabled:active:enabled:active)
        echo -e "\n - Both FirewallD and NFTables are enabled and active\n - stopping and masking NFTables"
        systemctl stop nftables && systemctl --now mask nftables ;;
    enabled:*:enabled:*)
        echo -e "\n - Both FirewallD and NFTables are enabled\n - remediating"
        if [ "$(awk -F: '{print $2}' <<< "$l_fwutil_status")" = "active" ] && [ "$(awk -F: '{print $4}' <<< "$l_fwutil_status")" = "inactive" ]; then
            echo " - masking NFTables"
            systemctl stop nftables && systemctl --now mask nftables
        elif [ "$(awk -F: '{print $4}' <<< "$l_fwutil_status")" = "active" ] && [ "$(awk -F: '{print $2}' <<< "$l_fwutil_status")" = "inactive" ]; then
            echo " - masking FirewallD"
            systemctl stop firewalld && systemctl --now mask firewalld
        fi ;;
    *:active:*:active)
        echo -e "\n - Both FirewallD and NFTables are active\n - remediating"
        if [ "$(awk -F: '{print $1}' <<< "$l_fwutil_status")" = "enabled" ] && [ "$(awk -F: '{print $3}' <<< "$l_fwutil_status")" != "enabled" ]; then
            echo " - stopping and masking NFTables"
            systemctl stop nftables && systemctl --now mask nftables
        elif [ "$(awk -F: '{print $3}' <<< "$l_fwutil_status")" = "enabled" ] && [ "$(awk -F: '{print $1}' <<< "$l_fwutil_status")" != "enabled" ]; then
            echo " - stopping and masking FirewallD"
            systemctl stop firewalld && systemctl --now mask firewalld
        fi ;;
    :enabled:active)
        echo -e "\n - NFTables is enabled and active\n - FirewallD is not installed\n - no remediation required" ;;
    :)
        echo -e "\n - Neither FirewallD nor NFTables is installed.\n - installing NFTables"
        dnf -q install nftables ;;
    *:*:)
        echo -e "\n - NFTables is not installed on the system\n - installing NFTables"
        dnf -q install nftables ;;
    *)
        echo -e "\n - Unable to determine firewall state\n - MANUAL REMEDIATION REQUIRED: Configure either NFTables or FirewallD" ;;
esac
# Task 3.4.2: Configure NFTables
cat << 'EOF' > /etc/nftables/nftables_rules.nft
#!/usr/sbin/nft -f
# flush nftables rulesset
flush ruleset

# Load nftables ruleset
# nftables config with inet table named filter
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        # allow loopback if not forged
        iif lo accept
        iif != lo ip saddr 127.0.0.1/8 drop
        iif != lo ip6 saddr ::1/128 drop
        # allow connections made by ourselves
        ip protocol tcp ct state established accept
        ip protocol udp ct state established accept
        ip protocol icmp ct state established accept
        # allow from anywhere
        ip protocol igmp accept
        tcp dport ssh accept
        # allow some icmp
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-done, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report } accept
        icmp type { destination-unreachable, router-advertisement, router-solicitation, time-exceeded, parameter-problem } accept
    }
    chain forward {
        # drop all forward
        type filter hook forward priority 0; policy drop;
    }
    chain output {
        # can omit this as its accept by default
        type filter hook output priority 0; policy accept;
    }
}
EOF

nft -f /etc/nftables/nftables_rules.nft
echo 'include "/etc/nftables/nftables_rules.nft"' >> /etc/sysconfig/nftables.conf
echo "nftables rules have been set up and made permanent."

# Task 3.4.2.1: Ensure nftables base chains exist
if systemctl is-enabled nftables.service | grep -q 'enabled'; then
    echo "NFTables is in use on the system."

    TABLE_NAME="filter"
    BASE_CHAINS=("input" "forward" "output")

    for CHAIN in "${BASE_CHAINS[@]}"; do
        nft create chain inet $TABLE_NAME $CHAIN "{ type filter hook $CHAIN priority 0 \; }" 2>/dev/null
        
        if [ $? -ne 0 ]; then
            echo "Chain '$CHAIN' already exists or could not be created. Skipping creation."
        else
            echo "Chain '$CHAIN' created successfully."
        fi
    done
else
    echo "NFTables is not in use on this system."
fi

# Task 3.4.2.2: Ensure host based firewall loopback traffic is configured
{
  l_hbfw=""

  if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    echo -e "\n - FirewallD is in use on the system"
    l_hbfw="fwd"
  elif systemctl is-enabled nftables.service 2>/dev/null | grep -q 'enabled'; then
    echo -e "\n - nftables is in use on the system \n - Recommendation is NA \n - Remediation Complete"
    l_hbfw="nft"
  fi

  if [ "$l_hbfw" = "fwd" ]; then
    l_ipsaddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -P -- 'ip\h+saddr')"

    if ! nft list ruleset | awk '/hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -Pq -- '\H+\h+"lo"\h+accept'; then
      echo -e "\n - Enabling input to accept for loopback address"
      firewall-cmd --permanent --zone=trusted --add-interface=lo
      firewall-cmd --reload
    else
      echo -e "\n - firewalld input correctly set to accept for loopback address"

      if ! grep -Pq -- 'ip\h+saddr\h+127\.0\.0\.0\/8\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<< "$l_ipsaddr" && ! grep -Pq -- 'ip\h+daddr\h+\!\=\h+127\.0\.0\.1\h+ip\h+saddr\h+127\.0\.0\.1\h+drop' <<< "$l_ipsaddr"; then
        echo -e "\n - Setting IPv4 network traffic from loopback address to drop"
        firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
        firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
        firewall-cmd --reload
      else
        echo -e "\n - firewalld correctly set IPv4 network traffic from loopback address to drop"
      fi

      if grep -Pq -- '^\h*0\h*$' /sys/module/ipv6/parameters/disable; then
        l_ip6saddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr')"

        if ! grep -Pq 'ip6\h+saddr\h+::1\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<< "$l_ip6saddr" && ! grep -Pq -- 'ip6\h+daddr\h+\!=\h+::1\h+ip6\h+saddr\h+::1\h+drop' <<< "$l_ip6saddr"; then
          echo -e "\n - Setting IPv6 network traffic from loopback address to drop"
          firewall-cmd --permanent --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
          firewall-cmd --permanent --zone=trusted --add-rich-rule='rule family=ipv6 source address="::1" destination not address="::1" drop'
          firewall-cmd --reload
        else
          echo -e "\n - firewalld correctly set IPv6 network traffic from loopback address to drop"
        fi
      fi
    fi
  fi

  if [ "$l_hbfw" = "nft" ]; then
    l_ipsaddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -P -- 'ip\h+saddr')"

    if ! nft list ruleset | awk '/hook\s+input\s+/,/\}\s*(#.*)?$/' | grep -Pq -- '\H+\h+"lo"\h+accept'; then
      echo -e "\n - Enabling input to accept for loopback address"
      nft add rule inet filter input iif lo accept
    else
      echo -e "\n - nftables input correctly configured to accept for loopback address"
    fi

    if ! grep -Pq -- 'ip\h+saddr\h+127\.0\.0\.0\/8\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<< "$l_ipsaddr" && \
       ! grep -Pq -- 'ip\h+daddr\h+\!\=\h+127\.0\.0\.1\h+ip\h+saddr\h+127\.0\.0\.1\h+drop' <<< "$l_ipsaddr"; then
      echo -e "\n - Setting IPv4 network traffic from loopback address to drop"
      nft add rule inet filter input ip saddr 127.0.0.0/8 counter drop
    else
      echo -e "\n - nftables correctly configured IPv4 network traffic from loopback address to drop"
    fi

    if grep -Pq -- '^\h*0\h*$' /sys/module/ipv6/parameters/disable; then
      l_ip6saddr="$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr')"

      if ! grep -Pq 'ip6\h+saddr\h+::1\h+(counter\h+packets\h+\d+\h+bytes\h+\d+\h+)?drop' <<< "$l_ip6saddr" && \
         ! grep -Pq -- 'ip6\h+daddr\h+\!=\h+::1\h+ip6\h+saddr\h+::1\h+drop' <<< "$l_ip6saddr"; then
        echo -e "\n - Setting IPv6 network traffic from loopback address to drop"
        nft add rule inet filter input ip6 saddr ::1 counter drop
      else
        echo -e "\n - nftables IPv6 network traffic from loopback address to drop"
      fi
    fi
  fi
}

# Task 3.4.2.4: Ensure nftables established connections are configured (Manual)
if systemctl is-enabled nftables.service | grep -q 'enabled'; then
    nft add rule inet filter input ip protocol tcp ct state established accept
    echo " - Rule added: Allow established TCP connections."

    nft add rule inet filter input ip protocol udp ct state established accept
    echo " - Rule added: Allow established UDP connections."

    nft add rule inet filter input ip protocol icmp ct state established accept
    echo " - Rule added: Allow established ICMP connections."
else
    echo " - NFTables service is not enabled on the system. No rules were added."
fi

# Task 3.4.2.5: Ensure nftables default deny firewall policy
if systemctl is-enabled nftables.service | grep -q 'enabled'; then
  nft chain inet filter input { policy drop \; }
  if [ $? -ne 0 ]; then
    echo "Failed to apply DROP policy to input chain."
  else
    echo "Default DROP policy applied to input chain."
  fi

  nft chain inet filter forward { policy drop \; }
  if [ $? -ne 0 ]; then
    echo "Failed to apply DROP policy to forward chain."
  else
    echo "Default DROP policy applied to forward chain."
  fi

  nft chain inet filter output { policy drop \; }
  if [ $? -ne 0 ]; then
    echo "Failed to apply DROP policy to output chain."
  else
    echo "Default DROP policy applied to output chain."
  fi
else
  echo "NFTables is not enabled on this system."
fi

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################