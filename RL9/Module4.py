import os
import pandas as pd
from tabulate import tabulate
import subprocess
import shlex
import re

true_counter = 0
false_counter = 0
true_tasks = []
false_tasks = []
task_data =[]

task_data = []
def show_results():
    df = pd.DataFrame(task_data, columns=["Task Number", "Value", "Expected Output", "Actual Output"])
    table = tabulate(df, headers="keys", tablefmt="grid", showindex=False)
    
    print(table)

    print(f"\nTrue Counter: {true_counter}")
    print(f"True Tasks: {true_tasks}")
    print(f"False Counter: {false_counter}")
    print(f"False Tasks: {false_tasks}")
    
    print()
    print(df)
    excel_file = "CIS_RL9_Hardening_Report.xlsx"
    module_name = os.path.splitext(os.path.basename(__file__))[0]
    with pd.ExcelWriter(excel_file, engine="openpyxl", mode="a" if os.path.exists(excel_file) else "w") as writer:
        df.to_excel(writer, sheet_name=module_name, index=False)

    print(f"Results written to sheet '{module_name}' in {excel_file}")


def normalize_whitespace(content: str) -> str:
    return ' '.join(content.split())


task_no = "4.1.1"
expected_output_prefix = "nftables-"
try:
    command = "rpm -q nftables"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip() if process.stdout else "Package not installed"
    
    if actual_output.startswith(expected_output_prefix):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_prefix}x", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"{expected_output_prefix}x", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_prefix}x", f"Error: {str(e)}"])
    
task_no = "4.1.2"
output = []
actual_output = []
try:
    firewalld_installed = subprocess.run("rpm -q firewalld", shell=True, capture_output=True, text=True).returncode == 0
    firewalld_status = ""
    if firewalld_installed:
        firewalld_enabled = subprocess.run("systemctl is-enabled firewalld.service", shell=True, capture_output=True, text=True).stdout.strip()
        firewalld_active = subprocess.run("systemctl is-active firewalld.service", shell=True, capture_output=True, text=True).stdout.strip()
        firewalld_status = f"{firewalld_enabled}:{firewalld_active}"
    
    nftables_installed = subprocess.run("rpm -q nftables", shell=True, capture_output=True, text=True).returncode == 0
    nftables_status = ""
    if nftables_installed:
        nftables_enabled = subprocess.run("systemctl is-enabled nftables.service", shell=True, capture_output=True, text=True).stdout.strip()
        nftables_active = subprocess.run("systemctl is-active nftables.service", shell=True, capture_output=True, text=True).stdout.strip()
        nftables_status = f"{nftables_enabled}:{nftables_active}"
    
    fwutil_status = f"{firewalld_status}:{nftables_status}"

    if fwutil_status in ["enabled:active:masked:inactive", "enabled:active:disabled:inactive"]:
        actual_output.append("\n - FirewallD utility is in use, enabled and active\n - NFTables utility is correctly disabled or masked and inactive\n - Only configure the recommendations found in the Configure Firewalld subsection")
        result = "True"
    elif fwutil_status in ["masked:inactive:enabled:active", "disabled:inactive:enabled:active"]:
        actual_output.append("\n - NFTables utility is in use, enabled and active\n - FirewallD utility is correctly disabled or masked and inactive\n - Only configure the recommendations found in the Configure NFTables subsection")
        result = "True"
    elif fwutil_status == "enabled:active:enabled:active":
        actual_output.append("\n - Both FirewallD and NFTables utilities are enabled and active. Configure only ONE firewall either NFTables OR Firewalld")
        result = "False"
    elif "enabled" in fwutil_status and "enabled" in fwutil_status.split(":")[2]:
        actual_output.append("\n - Both FirewallD and NFTables utilities are enabled\n - Configure only ONE firewall: either NFTables OR Firewalld")
        result = "False"
    elif ":active" in fwutil_status and fwutil_status.split(":")[2] == "active":
        actual_output.append("\n - Both FirewallD and NFTables utilities are enabled\n - Configure only ONE firewall: either NFTables OR Firewalld")
        result = "False"
    elif ":enabled:active" in fwutil_status:
        actual_output.append("\n - NFTables utility is in use, enabled, and active\n - FirewallD package is not installed\n - Only configure the recommendations found in the Configure NFTables subsection")
        result = "True"
    elif fwutil_status == "::":
        actual_output.append("\n - Neither FirewallD nor NFTables is installed. Configure only ONE firewall either NFTables OR Firewalld")
        result = "False"
    elif "*:*:" in fwutil_status:
        actual_output.append("\n - NFTables package is not installed on the system. Install NFTables and configure only ONE firewall either NFTables OR Firewalld")
        result = "False"
    else:
        actual_output.append("\n - Unable to determine firewall state. Configure only ONE firewall either NFTables OR Firewalld")
        result = "False"

    if result == "True":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", "\n".join(actual_output)])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", "\n".join(actual_output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "4.2.1"
output = []
actual_output = []
expected_output = ""
try:
    firewalld_enabled = subprocess.run("systemctl is-enabled firewalld.service", shell=True, capture_output=True, text=True).stdout.strip()

    if firewalld_enabled == "enabled":
        active_zone = subprocess.run("firewall-cmd --list-all | awk '/\\(active\\)/ { print $1 }'", shell=True, capture_output=True, text=True).stdout.strip()
        services_ports = subprocess.run(f"firewall-cmd --list-all --zone={active_zone} | grep -P -- '^\\h*(services:|ports:)'", shell=True, capture_output=True, text=True).stdout.strip()

        actual_output.append(services_ports)

    if not services_ports:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, "\n".join(actual_output)])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "\n".join(actual_output)])
        
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "4.2.2"
expected_output_ipv4_drop = 'rule family=ipv4 source address="127.0.0.1" destination not address="127.0.0.1" drop'
expected_output_ipv6_drop = 'rule family=ipv6 source address="::1" destination not address="::1" drop'
expected_output = f"{expected_output_ipv4_drop}\n{expected_output_ipv6_drop}"
output = []
try:
    l_hbfw = ""
    if subprocess.run("systemctl is-enabled firewalld.service", shell=True, capture_output=True, text=True).stdout.strip() == 'enabled':
        l_hbfw = "fwd"
    elif subprocess.run("systemctl is-enabled nftables.service", shell=True, capture_output=True, text=True).stdout.strip() == 'enabled':
        l_hbfw = "nft"
    
    if l_hbfw == "fwd":
        nft_rules = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True).stdout
        
        if re.search(r'\s+"lo"\s+accept', nft_rules):
            output.append("- Network traffic to the loopback address is correctly set to accept")
        else:
            output.append("- Network traffic to the loopback address is not set to accept")

        ipv4_drop_check = (re.search(r'ip\s+saddr\s+127\.0\.0\.0\/8\s+drop', nft_rules) or 
                           re.search(r'ip\s+daddr\s+!=\s+127\.0\.0\.1\s+ip\s+saddr\s+127\.0\.0\.1\s+drop', nft_rules))
        if ipv4_drop_check:
            output.append("- IPv4 network traffic from loopback address correctly set to drop")
        else:
            output.append("- IPv4 network traffic from loopback address not set to drop")

        if subprocess.run("cat /sys/module/ipv6/parameters/disable", shell=True, capture_output=True, text=True).stdout.strip() == '0':
            ipv6_drop_check = (re.search(r'ip6\s+saddr\s+::1\s+drop', nft_rules) or 
                               re.search(r'ip6\s+daddr\s+!=\s+::1\s+ip6\s+saddr\s+::1\s+drop', nft_rules))
            if ipv6_drop_check:
                output.append("- IPv6 network traffic from loopback address correctly set to drop")
            else:
                output.append("- IPv6 network traffic from loopback address not set to drop")

    if l_hbfw == "nft" or not output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, "\n".join(output)])
    else:
        actual_output = "\n".join(output)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "4.3.1"
expected_output_input = "type filter hook input"
expected_output_forward = "type filter hook forward"
expected_output_output = "type filter hook output"
expected_output = f"{expected_output_input}\n{expected_output_forward}\n{expected_output_output}"
output = []
actual_output = []
try:
    nft_rules = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True).stdout

    input_check = expected_output_input in nft_rules
    forward_check = expected_output_forward in nft_rules
    output_check = expected_output_output in nft_rules

    if input_check and forward_check and output_check:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, "All base chains exist."])
    else:
        if not input_check:
            output.append("- INPUT filter hook base chain does not exist.")
        if not forward_check:
            output.append("- FORWARD filter hook base chain does not exist.")
        if not output_check:
            output.append("- OUTPUT filter hook base chain does not exist.")

        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "\n".join(output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "4.3.2"
expected_output_tcp = "ip protocol tcp ct state established accept"
expected_output_udp = "ip protocol udp ct state established accept"
expected_output_icmp = "ip protocol icmp ct state established accept"
expected_output = f"{expected_output_tcp}\n{expected_output_udp}\n{expected_output_icmp}"
output = []
actual_output = []
try:
    nft_service_enabled = subprocess.run("systemctl is-enabled nftables.service", shell=True, capture_output=True, text=True).stdout.strip()
    
    if "enabled" in nft_service_enabled:
        nft_rules = subprocess.run("nft list ruleset", shell=True, capture_output=True, text=True).stdout
        rules_check = []

        if expected_output_tcp in nft_rules:
            rules_check.append("TCP rule is present.")
        else:
            rules_check.append("- TCP rule for established connections is missing.")

        if expected_output_udp in nft_rules:
            rules_check.append("UDP rule is present.")
        else:
            rules_check.append("- UDP rule for established connections is missing.")

        if expected_output_icmp in nft_rules:
            rules_check.append("ICMP rule is present.")
        else:
            rules_check.append("- ICMP rule for established connections is missing.")

        if len(rules_check) == 3:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, "All required rules for established connections are present."])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, "\n".join(rules_check)])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "NFTables service is not enabled."])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "4.3.3"
expected_output = ""
actual_output = []
try:
    nft_service_enabled = subprocess.run("systemctl is-enabled nftables.service", shell=True, capture_output=True, text=True).stdout.strip()
    
    if "enabled" in nft_service_enabled:
        input_policy_check = subprocess.run("nft list ruleset | grep 'hook input' | grep -v 'policy drop'", shell=True, capture_output=True, text=True).stdout.strip()
        forward_policy_check = subprocess.run("nft list ruleset | grep 'hook forward' | grep -v 'policy drop'", shell=True, capture_output=True, text=True).stdout.strip()
        
        if input_policy_check == "" and forward_policy_check == "":
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, ""])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            actual_output.append("- INPUT hook policy is not DROP." if input_policy_check else "")
            actual_output.append("- FORWARD hook policy is not DROP." if forward_policy_check else "")
            task_data.append([task_no, "False", expected_output, "\n".join(filter(None, actual_output))])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "NFTables service is not enabled."])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "4.3.4"
expected_output = "Loopback interface is correctly configured."
actual_output = []
try:
    nft_service_enabled = subprocess.run("systemctl is-enabled nftables.service", shell=True, capture_output=True, text=True).stdout.strip()

    if "enabled" in nft_service_enabled:
        loopback_accept_check = subprocess.run("nft list ruleset | awk '/hook input/,/}/' | grep -Pq 'iif lo accept'", shell=True)
        if loopback_accept_check.returncode == 0:
            actual_output.append("- Network traffic to the loopback address is correctly set to accept")
        else:
            actual_output.append("- Network traffic to the loopback address is not set to accept")

        ipv4_drop_check = subprocess.run("nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip saddr 127.0.0.0/8 drop'", shell=True)
        if ipv4_drop_check.returncode == 0:
            actual_output.append("- IPv4 network traffic from loopback address is correctly set to drop")
        else:
            actual_output.append("- IPv4 network traffic from loopback address is not set to drop")

        ipv6_drop_check = subprocess.run("nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr ::1 drop'", shell=True)
        if ipv6_drop_check.returncode == 0:
            actual_output.append("- IPv6 network traffic from loopback address is correctly set to drop")
        else:
            actual_output.append("- IPv6 network traffic from loopback address is not set to drop")

        if all("correctly set" in message for message in actual_output):
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, "\n".join(actual_output)])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, "\n".join(actual_output)])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "NFTables service is not enabled."])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

show_results()

### Written By: 
###     1. Aditi Jamsandekar
###     2. Chirayu Rathi
###     3. Siddhi Jani
############################