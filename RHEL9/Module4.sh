#!/usr/bin/env bash

# Task 4.1.1: Ensure nftables is installed
dnf install nftables -y

# Task 4.1.2: Ensure a single firewall configuration utility is in use
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

# Task 4.2 
FILE_PATH="/etc/firewalld/zones/securezone.xml"

mkdir -p /etc/firewalld/zones

cat << EOF > "$FILE_PATH"
<?xml version="1.0" encoding="utf-8"?>
<zone target="DROP">
  <description>For use with CIS Linux Benchmark. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description>
  <service name="ssh"/>
  <service name="dhcpv6-client"/>
  <icmp-block name="destination-unreachable"/>
  <icmp-block name="packet-too-big"/>
  <icmp-block name="time-exceeded"/>
  <icmp-block name="parameter-problem"/>
  <icmp-block name="neighbour-advertisement"/>
  <icmp-block name="neighbour-solicitation"/>
  <icmp-block name="router-advertisement"/>
  <icmp-block name="router-solicitation"/>
  <rule family="ipv4">
    <source address="127.0.0.1"/>
    <destination address="127.0.0.1" invert="True"/>
    <drop/>
  </rule>
  <rule family="ipv6">
    <source address="::1"/>
    <destination address="::1" invert="True"/>
    <drop/>
  </rule>
  <icmp-block-inversion/>
</zone>
EOF

if [ -f "$FILE_PATH" ]; then
  echo "securezone.xml file created successfully at $FILE_PATH"
  INTERFACE=$(ip route | grep default | awk '{print $5}')

  if [ -z "$INTERFACE" ]; then
    echo "No active network interface found."
    exit 1
  else
    firewall-cmd --reload
    firewall-cmd --permanent --zone=securezone --change-interface="$INTERFACE"
    firewall-cmd --reload
    echo "Secure zone applied to interface: $INTERFACE"
  fi
else
  echo "Failed to create securezone.xml file."
fi

# Task 4.2.1: Ensure firewalld drops unnecessary services and ports (manual)

# Task 4.2.2: Ensure firewalld loopback traffic is configured (raising errors)
{
  l_hbfw=""

  if systemctl is-enabled firewalld.service | grep -q 'enabled'; then
    echo -e "\n - FirewallD is in use on the system" && l_hbfw="fwd"
  elif systemctl is-enabled nftables.service 2>/dev/null | grep -q 'enabled'; then
    echo -e "\n - nftables is in use on the system \n - Recommendation is NA \n - Remediation Complete" && l_hbfw="nft"
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
}

# Task 4.3: Configure NFTables
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

# Task 4.3.1: Ensure nftables base chains exist
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

# Task 4.3.2: Ensure nftables established connections are configured (Manual)
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

# Task 4.3.3: Ensure nftables default deny firewall policy
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

# Task 4.3.4: Ensure nftables loopback traffic is configured
{
  l_hbfw=""

  if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
    echo -e "\n - FirewallD is in use on the system\n - Recommendation is NA \n - Remediation Complete"
    l_hbfw="fwd"
  elif systemctl is-enabled nftables.service | grep -q 'enabled'; then
    l_hbfw="nft"
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

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################