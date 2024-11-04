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
    excel_file = "CIS_RL8_Hardening_Report.xlsx"
    module_name = os.path.splitext(os.path.basename(__file__))[0]
    with pd.ExcelWriter(excel_file, engine="openpyxl", mode="a" if os.path.exists(excel_file) else "w") as writer:
        df.to_excel(writer, sheet_name=module_name, index=False)

    print(f"Results written to sheet '{module_name}' in {excel_file}")


def normalize_whitespace(content: str) -> str:
    return ' '.join(content.split())

task_no = "3.1.1"
output = ""
actual_output = ""
try:
    command = "! grep -Pqs -- '^\\h*0\\b' /sys/module/ipv6/parameters/disable"
    process = subprocess.run(command, shell=True, capture_output=True)

    if process.returncode == 0:
        output += "IPv6 is not enabled\n"
    else:
        output += "IPv6 is enabled\n"

    command = "sysctl net.ipv6.conf.all.disable_ipv6"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output_all = process.stdout.strip()

    command = "sysctl net.ipv6.conf.default.disable_ipv6"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output_default = process.stdout.strip()

    actual_output = f"{actual_output_all}\n{actual_output_default}"

    if "net.ipv6.conf.all.disable_ipv6 = 0" in actual_output and "net.ipv6.conf.default.disable_ipv6 = 0" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "net.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.disable_ipv6 = 0", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "net.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv6.conf.default.disable_ipv6 = 0", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

import os
import subprocess

task_no = "3.1.2"
output = ""
actual_output = ""
try:
    command = "find /sys/class/net/*/ -type d -name wireless"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    wireless_interfaces = process.stdout.strip()

    if wireless_interfaces:
        l_dname = ""
        for driverdir in wireless_interfaces.splitlines():
            module_path = os.path.realpath(os.path.join(driverdir, 'device', 'driver', 'module'))
            l_dname += f"{os.path.basename(module_path)}\n"

        l_dname = sorted(set(l_dname.splitlines()))

        for l_mname in l_dname:
            module_chk = ""
            command = f"modprobe -n -v {l_mname}"
            loadable_process = subprocess.run(command, shell=True, capture_output=True, text=True)
            l_loadable = loadable_process.stdout.strip()

            if re.search(r'^\h*install \/bin\/(true|false)', l_loadable):
                output += f"\nmodule: \"{l_mname}\" is not loadable: \"{l_loadable}\""
            else:
                actual_output += f"\nmodule: \"{l_mname}\" is loadable: \"{l_loadable}\""

            command = f"lsmod | grep {l_mname}"
            loaded_process = subprocess.run(command, shell=True)
            if loaded_process.returncode != 0:
                output += f"\nmodule: \"{l_mname}\" is not loaded"
            else:
                actual_output += f"\nmodule: \"{l_mname}\" is loaded"

            command = f"modprobe --showconfig | grep -P \"^\\h*blacklist\\h+{l_mname}\\b\""
            blacklist_process = subprocess.run(command, shell=True)
            if blacklist_process.returncode == 0:
                output += f"\nmodule: \"{l_mname}\" is deny listed"
            else:
                actual_output += f"\n module: \"{l_mname}\" is not deny listed"

    if not output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No wireless interfaces are active", actual_output.strip()])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", output.strip(), actual_output.strip()])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "3.1.3"
expected_output = "package bluez is not installed"
try:
    command = "rpm -q bluez"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip() if process.stdout else "error"
    
    if actual_output == expected_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "3.2.1"
output = []
actual_output = []
mod_name = "dccp"
mod_type = "net"
try:
    command = f"find /lib/modules/*/kernel/{mod_type} -type d"
    mod_paths = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.strip().splitlines()
    
    module_exists = False

    for mod_base_directory in mod_paths:
        if os.path.isdir(os.path.join(mod_base_directory, mod_name.replace("-", "/"))):
            module_exists = True
            output.append(f"\n - \"{mod_base_directory}\"")
            break

    if not module_exists:
        output.append(f"\n - kernel module: \"{mod_name}\" doesn't exist")

    a_showconfig = subprocess.run("modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\s+'", shell=True, capture_output=True, text=True).stdout.strip().splitlines()

    loaded_check = subprocess.run(f"lsmod | grep '{mod_name}'", shell=True)
    if loaded_check.returncode != 0:
        output.append(f" - kernel module: \"{mod_name}\" is not loaded")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loaded")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loaded")

    loadable = any(re.search(r'\binstall\s+' + re.escape(mod_name) + r'\s+/bin/(true|false)\b', line) for line in a_showconfig)
    if loadable:
        output.append(f" - kernel module: \"{mod_name}\" is not loadable")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loadable")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loadable")

    deny_listed = any(re.search(r'\bblacklist\s+' + re.escape(mod_name) + r'\b', line) for line in a_showconfig)
    if deny_listed:
        output.append(f" - kernel module: \"{mod_name}\" is deny listed")
        actual_output.append(f" - kernel module: \"{mod_name}\" is deny listed")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is not deny listed")

    if all(x in output for x in [
        f" - kernel module: \"{mod_name}\" is not loaded",
        f" - kernel module: \"{mod_name}\" is not loadable",
        f" - kernel module: \"{mod_name}\" is deny listed"
    ]):
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "\n".join(output), "\n".join(actual_output)])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No additional configuration is necessary", "\n".join(actual_output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "3.2.2"
output = []
actual_output = []
mod_name = "tipc"
mod_type = "net"
try:
    command = f"find /lib/modules/*/kernel/{mod_type} -type d"
    mod_paths = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.strip().splitlines()
    
    module_exists = False

    for mod_base_directory in mod_paths:
        if os.path.isdir(os.path.join(mod_base_directory, mod_name.replace("-", "/"))):
            module_exists = True
            output.append(f"\n - \"{mod_base_directory}\"")
            break

    if not module_exists:
        output.append(f"\n - kernel module: \"{mod_name}\" doesn't exist")

    a_showconfig = subprocess.run("modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\s+'", shell=True, capture_output=True, text=True).stdout.strip().splitlines()

    loaded_check = subprocess.run(f"lsmod | grep '{mod_name}'", shell=True)
    if loaded_check.returncode != 0:
        output.append(f" - kernel module: \"{mod_name}\" is not loaded")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loaded")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loaded")

    loadable = any(re.search(r'\binstall\s+' + re.escape(mod_name) + r'\s+/bin/(true|false)\b', line) for line in a_showconfig)
    if loadable:
        output.append(f" - kernel module: \"{mod_name}\" is not loadable")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loadable")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loadable")

    deny_listed = any(re.search(r'\bblacklist\s+' + re.escape(mod_name) + r'\b', line) for line in a_showconfig)
    if deny_listed:
        output.append(f" - kernel module: \"{mod_name}\" is deny listed")
        actual_output.append(f" - kernel module: \"{mod_name}\" is deny listed")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is not deny listed")

    if all(x in output for x in [
        f" - kernel module: \"{mod_name}\" is not loaded",
        f" - kernel module: \"{mod_name}\" is not loadable",
        f" - kernel module: \"{mod_name}\" is deny listed"
    ]):
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "\n".join(output), "\n".join(actual_output)])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No additional configuration is necessary", "\n".join(actual_output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "3.2.3"
output = []
actual_output = []
mod_name = "rds"
mod_type = "net"
try:
    command = f"find /lib/modules/*/kernel/{mod_type} -type d"
    mod_paths = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.strip().splitlines()
    
    module_exists = False

    for mod_base_directory in mod_paths:
        if os.path.isdir(os.path.join(mod_base_directory, mod_name.replace("-", "/"))):
            module_exists = True
            output.append(f"\n - \"{mod_base_directory}\"")
            break

    if not module_exists:
        output.append(f"\n - kernel module: \"{mod_name}\" doesn't exist")

    a_showconfig = subprocess.run("modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\s+'", shell=True, capture_output=True, text=True).stdout.strip().splitlines()

    loaded_check = subprocess.run(f"lsmod | grep '{mod_name}'", shell=True)
    if loaded_check.returncode != 0:
        output.append(f" - kernel module: \"{mod_name}\" is not loaded")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loaded")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loaded")

    loadable = any(re.search(r'\binstall\s+' + re.escape(mod_name) + r'\s+/bin/(true|false)\b', line) for line in a_showconfig)
    if loadable:
        output.append(f" - kernel module: \"{mod_name}\" is not loadable")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loadable")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loadable")

    deny_listed = any(re.search(r'\bblacklist\s+' + re.escape(mod_name) + r'\b', line) for line in a_showconfig)
    if deny_listed:
        output.append(f" - kernel module: \"{mod_name}\" is deny listed")
        actual_output.append(f" - kernel module: \"{mod_name}\" is deny listed")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is not deny listed")

    if all(x in output for x in [
        f" - kernel module: \"{mod_name}\" is not loaded",
        f" - kernel module: \"{mod_name}\" is not loadable",
        f" - kernel module: \"{mod_name}\" is deny listed"
    ]):
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "\n".join(output), "\n".join(actual_output)])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No additional configuration is necessary", "\n".join(actual_output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "3.2.4"
output = []
actual_output = []
mod_name = "sctp"
mod_type = "net"
try:
    command = f"find /lib/modules/*/kernel/{mod_type} -type d"
    mod_paths = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.strip().splitlines()
    
    module_exists = False

    for mod_base_directory in mod_paths:
        if os.path.isdir(os.path.join(mod_base_directory, mod_name.replace("-", "/"))):
            module_exists = True
            output.append(f"\n - \"{mod_base_directory}\"")
            break

    if not module_exists:
        output.append(f"\n - kernel module: \"{mod_name}\" doesn't exist")

    a_showconfig = subprocess.run("modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\s+'", shell=True, capture_output=True, text=True).stdout.strip().splitlines()

    loaded_check = subprocess.run(f"lsmod | grep '{mod_name}'", shell=True)
    if loaded_check.returncode != 0:
        output.append(f" - kernel module: \"{mod_name}\" is not loaded")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loaded")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loaded")

    loadable = any(re.search(r'\binstall\s+' + re.escape(mod_name) + r'\s+/bin/(true|false)\b', line) for line in a_showconfig)
    if loadable:
        output.append(f" - kernel module: \"{mod_name}\" is not loadable")
        actual_output.append(f" - kernel module: \"{mod_name}\" is not loadable")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is loadable")

    deny_listed = any(re.search(r'\bblacklist\s+' + re.escape(mod_name) + r'\b', line) for line in a_showconfig)
    if deny_listed:
        output.append(f" - kernel module: \"{mod_name}\" is deny listed")
        actual_output.append(f" - kernel module: \"{mod_name}\" is deny listed")
    else:
        actual_output.append(f" - kernel module: \"{mod_name}\" is not deny listed")

    if all(x in output for x in [
        f" - kernel module: \"{mod_name}\" is not loaded",
        f" - kernel module: \"{mod_name}\" is not loadable",
        f" - kernel module: \"{mod_name}\" is deny listed"
    ]):
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "\n".join(output), "\n".join(actual_output)])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No additional configuration is necessary", "\n".join(actual_output)])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "3.3.1"
output = []
actual_output = []
expected_output1 = "net.ipv4.ip_forward = 0"
expected_output2 = "net.ipv6.conf.all.forwarding = 0"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    ipv4_forward = subprocess.run("sysctl net.ipv4.ip_forward", shell=True, capture_output=True, text=True).stdout.strip()
    ipv6_forward = subprocess.run("sysctl net.ipv6.conf.all.forwarding", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(ipv4_forward)
    actual_output.append(ipv6_forward)

    if ipv4_forward == expected_output1 and ipv6_forward == expected_output2:
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

task_no = "3.3.2"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.send_redirects = 0"
expected_output2 = "net.ipv4.conf.default.send_redirects = 0"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    all_send_redirects = subprocess.run("sysctl net.ipv4.conf.all.send_redirects", shell=True, capture_output=True, text=True).stdout.strip()
    default_send_redirects = subprocess.run("sysctl net.ipv4.conf.default.send_redirects", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(all_send_redirects)
    actual_output.append(default_send_redirects)

    if all_send_redirects == expected_output1 and default_send_redirects == expected_output2:
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

task_no = "3.3.3"
output = []
actual_output = []
expected_output = "net.ipv4.icmp_ignore_bogus_error_responses = 1"
try:
    icmp_ignore_bogus = subprocess.run("sysctl net.ipv4.icmp_ignore_bogus_error_responses", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(icmp_ignore_bogus)

    if icmp_ignore_bogus == expected_output:
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

task_no = "3.3.4"
output = []
actual_output = []
expected_output = "net.ipv4.icmp_echo_ignore_broadcasts = 1"
try:
    icmp_echo_ignore_broadcasts = subprocess.run("sysctl net.ipv4.icmp_echo_ignore_broadcasts", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(icmp_echo_ignore_broadcasts)

    if icmp_echo_ignore_broadcasts == expected_output:
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

task_no = "3.3.5"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.accept_redirects = 0"
expected_output2 = "net.ipv4.conf.default.accept_redirects = 0"
expected_output3 = "net.ipv6.conf.all.accept_redirects = 0"
expected_output4 = "net.ipv6.conf.default.accept_redirects = 0"
expected_output = f"{expected_output1}\n{expected_output2}\n{expected_output3}\n{expected_output4}"
try:
    accept_redirects_all_ipv4 = subprocess.run("sysctl net.ipv4.conf.all.accept_redirects", shell=True, capture_output=True, text=True).stdout.strip()
    accept_redirects_default_ipv4 = subprocess.run("sysctl net.ipv4.conf.default.accept_redirects", shell=True, capture_output=True, text=True).stdout.strip()
    accept_redirects_all_ipv6 = subprocess.run("sysctl net.ipv6.conf.all.accept_redirects", shell=True, capture_output=True, text=True).stdout.strip()
    accept_redirects_default_ipv6 = subprocess.run("sysctl net.ipv6.conf.default.accept_redirects", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(accept_redirects_all_ipv4)
    actual_output.append(accept_redirects_default_ipv4)
    actual_output.append(accept_redirects_all_ipv6)
    actual_output.append(accept_redirects_default_ipv6)

    if (accept_redirects_all_ipv4 == expected_output1 and
        accept_redirects_default_ipv4 == expected_output2 and
        accept_redirects_all_ipv6 == expected_output3 and
        accept_redirects_default_ipv6 == expected_output4):
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

task_no = "3.3.6"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.secure_redirects = 0"
expected_output2 = "net.ipv4.conf.default.secure_redirects = 0"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    secure_redirects_all_ipv4 = subprocess.run("sysctl net.ipv4.conf.all.secure_redirects", shell=True, capture_output=True, text=True).stdout.strip()
    secure_redirects_default_ipv4 = subprocess.run("sysctl net.ipv4.conf.default.secure_redirects", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(secure_redirects_all_ipv4)
    actual_output.append(secure_redirects_default_ipv4)

    if (secure_redirects_all_ipv4 == expected_output1 and
        secure_redirects_default_ipv4 == expected_output2):
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

task_no = "3.3.7"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.rp_filter = 1"
expected_output2 = "net.ipv4.conf.default.rp_filter = 1"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    rp_filter_all_ipv4 = subprocess.run("sysctl net.ipv4.conf.all.rp_filter", shell=True, capture_output=True, text=True).stdout.strip()
    rp_filter_default_ipv4 = subprocess.run("sysctl net.ipv4.conf.default.rp_filter", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(rp_filter_all_ipv4)
    actual_output.append(rp_filter_default_ipv4)

    if (rp_filter_all_ipv4 == expected_output1 and
        rp_filter_default_ipv4 == expected_output2):
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

task_no = "3.3.8"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.accept_source_route = 0"
expected_output2 = "net.ipv4.conf.default.accept_source_route = 0"
expected_output3 = "net.ipv6.conf.all.accept_source_route = 0"
expected_output4 = "net.ipv6.conf.default.accept_source_route = 0"
expected_output = f"{expected_output1}\n{expected_output2}\n{expected_output3}\n{expected_output4}"
try:
    accept_source_route_all_ipv4 = subprocess.run("sysctl net.ipv4.conf.all.accept_source_route", shell=True, capture_output=True, text=True).stdout.strip()
    accept_source_route_default_ipv4 = subprocess.run("sysctl net.ipv4.conf.default.accept_source_route", shell=True, capture_output=True, text=True).stdout.strip()
    accept_source_route_all_ipv6 = subprocess.run("sysctl net.ipv6.conf.all.accept_source_route", shell=True, capture_output=True, text=True).stdout.strip()
    accept_source_route_default_ipv6 = subprocess.run("sysctl net.ipv6.conf.default.accept_source_route", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(accept_source_route_all_ipv4)
    actual_output.append(accept_source_route_default_ipv4)
    actual_output.append(accept_source_route_all_ipv6)
    actual_output.append(accept_source_route_default_ipv6)

    if (accept_source_route_all_ipv4 == expected_output1 and
        accept_source_route_default_ipv4 == expected_output2 and
        accept_source_route_all_ipv6 == expected_output3 and
        accept_source_route_default_ipv6 == expected_output4):
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

task_no = "3.3.9"
output = []
actual_output = []
expected_output1 = "net.ipv4.conf.all.log_martians = 1"
expected_output2 = "net.ipv4.conf.default.log_martians = 1"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    log_martians_all_ipv4 = subprocess.run("sysctl net.ipv4.conf.all.log_martians", shell=True, capture_output=True, text=True).stdout.strip()
    log_martians_default_ipv4 = subprocess.run("sysctl net.ipv4.conf.default.log_martians", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(log_martians_all_ipv4)
    actual_output.append(log_martians_default_ipv4)

    if (log_martians_all_ipv4 == expected_output1 and
        log_martians_default_ipv4 == expected_output2):
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

task_no = "3.3.10"
output = []
actual_output = []
expected_output = "net.ipv4.tcp_syncookies = 1"
try:
    tcp_syncookies = subprocess.run("sysctl net.ipv4.tcp_syncookies", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(tcp_syncookies)

    if tcp_syncookies == expected_output:
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

task_no = "3.3.11"
output = []
actual_output = []
expected_output1 = "net.ipv6.conf.all.accept_ra = 0"
expected_output2 = "net.ipv6.conf.default.accept_ra = 0"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    accept_ra_all_ipv6 = subprocess.run("sysctl net.ipv6.conf.all.accept_ra", shell=True, capture_output=True, text=True).stdout.strip()
    accept_ra_default_ipv6 = subprocess.run("sysctl net.ipv6.conf.default.accept_ra", shell=True, capture_output=True, text=True).stdout.strip()

    actual_output.append(accept_ra_all_ipv6)
    actual_output.append(accept_ra_default_ipv6)

    if (accept_ra_all_ipv6 == expected_output1 and
        accept_ra_default_ipv6 == expected_output2):
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

task_no = "3.4.1.1"
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

task_no = "3.4.2.1"
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

task_no = "3.4.2.2"
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

task_no = "3.4.2.2"
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

task_no = "3.4.2.3"
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

task_no = "3.4.2.4"
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

task_no = "3.4.2.5"
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


show_results()

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################