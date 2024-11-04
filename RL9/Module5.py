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


task_no = "5.1.1"
output = []
actual_output = []
perm_mask = '0177'
maxperm = f"{(0o777 & ~int(perm_mask, 8)):o}"
def check_ssh_files(file_path):
    file_data = subprocess.run(f"stat -Lc '%#a:%U:%G' {file_path}", shell=True, capture_output=True, text=True).stdout.strip()
    mode, user, group = file_data.split(':')
    details = []
    
    if int(mode, 8) & int(perm_mask, 8) > 0:
        details.append(f"- Mode is '{mode}', should be '{maxperm}' or more restrictive")
    if user != "root":
        details.append(f"- Owned by '{user}', should be owned by 'root'")
    if group != "root":
        details.append(f"- Group owned by '{group}', should be 'root'")

    if details:
        output.append(f"- File: '{file_path}':\n" + "\n".join(details))
    else:
        output.append(f"- File: '{file_path}': Correct mode ({mode}), owner ({user}), and group owner ({group})")
try:
    if os.path.exists("/etc/ssh/sshd_config"):
        check_ssh_files("/etc/ssh/sshd_config")
    
    ssh_config_files = subprocess.run("find -L /etc/ssh/sshd_config.d -type f", shell=True, capture_output=True, text=True).stdout.splitlines()
    for ssh_file in ssh_config_files:
        check_ssh_files(ssh_file)

    actual_output = "\n".join(output)
    true_counter += 1
    true_tasks.append(task_no)
    task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.2"
output = []
actual_output = []
ssh_group_name = subprocess.run("awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group", shell=True, capture_output=True, text=True).stdout.strip()
def check_file_permissions(file_path, ssh_group_name):
    file_data = subprocess.run(f"stat -Lc '%#a:%U:%G' {file_path}", shell=True, capture_output=True, text=True).stdout.strip()
    mode, owner, group = file_data.split(':')
    details = []

    pmask = '0137' if group == ssh_group_name else '0177'
    maxperm = f"{(0o777 & ~int(pmask, 8)):o}"

    if int(mode, 8) & int(pmask, 8) > 0:
        details.append(f"- Mode: '{mode}', should be '{maxperm}' or more restrictive")

    if owner != "root":
        details.append(f"- Owned by: '{owner}', should be owned by 'root'")
    
    if group not in (ssh_group_name, 'root'):
        details.append(f"- Owned by group '{group}', should be group owned by: '{ssh_group_name}' or 'root'")
    
    if details:
        output.append(f"- File: '{file_path}':\n" + "\n".join(details))
    else:
        output.append(f"- File: '{file_path}'\n - Correct: mode '{mode}', owner '{owner}', and group owner '{group}' configured")
try:
    ssh_files = subprocess.run("find -L /etc/ssh -xdev -type f", shell=True, capture_output=True, text=True).stdout.splitlines()
    for ssh_file in ssh_files:
        if subprocess.run(f"ssh-keygen -lf {ssh_file}", shell=True, capture_output=True, text=True).returncode == 0:
            if "private key" in subprocess.run(f"file {ssh_file}", shell=True, capture_output=True, text=True).stdout.lower():
                check_file_permissions(ssh_file, ssh_group_name)

    if not output:
        output.append("- No openSSH private keys found")

    actual_output = "\n".join(output)
    true_counter += 1
    true_tasks.append(task_no)
    task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.3"
output = []
actual_output = []
def check_public_key_permissions(file_path):
    file_data = subprocess.run(f"stat -Lc '%#a:%U:%G' {file_path}", shell=True, capture_output=True, text=True).stdout.strip()
    mode, owner, group = file_data.split(':')
    details = []

    pmask = '0133'
    maxperm = f"{(0o777 & ~int(pmask, 8)):o}"

    if int(mode, 8) & int(pmask, 8) > 0:
        details.append(f"- Mode: '{mode}', should be '{maxperm}' or more restrictive")

    if owner != "root":
        details.append(f"- Owned by: '{owner}', should be owned by 'root'")
    
    if group != "root":
        details.append(f"- Owned by group '{group}', should be group owned by 'root'")
    
    if details:
        output.append(f"- File: '{file_path}':\n" + "\n".join(details))
    else:
        output.append(f"- File: '{file_path}'\n - Correct: mode '{mode}', owner '{owner}', and group owner '{group}' configured")
try:
    ssh_files = subprocess.run("find -L /etc/ssh -xdev -type f", shell=True, capture_output=True, text=True).stdout.splitlines()
    for ssh_file in ssh_files:
        if subprocess.run(f"ssh-keygen -lf {ssh_file}", shell=True, capture_output=True, text=True).returncode == 0:
            if "public key" in subprocess.run(f"file {ssh_file}", shell=True, capture_output=True, text=True).stdout.lower():
                check_public_key_permissions(ssh_file)

    if not output:
        output.append("- No openSSH public keys found")

    actual_output = "\n".join(output)
    true_counter += 1
    true_tasks.append(task_no)
    task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.4"
output = []
actual_output = []
weak_ciphers = ["3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"]
weak_ciphers_found = []
expected_output="Weak ciphers: 3des-cbc, aes128-cbc, aes192-cbc, aes256-cbc"
try:
    sshd_output = subprocess.run("sshd -T | grep -Pi '^ciphers\\s+\"?([^#\\n\\r]+)'", shell=True, capture_output=True, text=True).stdout.strip()

    if sshd_output:
        ciphers = sshd_output.split()[1].split(',')
        output.append(f"Ciphers found: {', '.join(ciphers)}")

        for cipher in ciphers:
            if cipher in weak_ciphers:
                weak_ciphers_found.append(cipher)

        if weak_ciphers_found:
            output.append(f"Weak ciphers found: {', '.join(weak_ciphers_found)}")
        else:
            output.append("No weak ciphers found.")
    else:
        output.append("No ciphers found in the SSH configuration.")

    actual_output = "\n".join(output)
    
    if weak_ciphers_found:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.5"
output = []
actual_output = []
weak_kex_algorithms = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]
weak_kex_found = []
expected_output = "Weak KEX: diffie-hellman-group1-sha1, diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha1"
try:
    sshd_output = subprocess.run("sshd -T | grep -Pi 'kexalgorithms\\s+([^#\\n\\r]+)'", shell=True, capture_output=True, text=True).stdout.strip()

    if sshd_output:
        kex_algorithms = sshd_output.split()[1].split(',')
        output.append(f"KEX algorithms found: {', '.join(kex_algorithms)}")

        for kex in kex_algorithms:
            if kex in weak_kex_algorithms:
                weak_kex_found.append(kex)

        if weak_kex_found:
            output.append(f"Weak KEX algorithms found: {', '.join(weak_kex_found)}")
        else:
            output.append("No weak KEX algorithms found.")
    else:
        output.append("No KEX algorithms found in the SSH configuration.")

    actual_output = "\n".join(output)
    
    if weak_kex_found:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.6"
output = []
actual_output = []
weak_macs = [
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com",
    "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
    "umac-64-etm@openssh.com", "umac-128-etm@openssh.com"
]
weak_macs_found = []
expected_output = "Weak MACs: hmac-md5, hmac-md5-96, hmac-sha1-96, umac-64@openssh.com,\nhmac-md5-etm@openssh.com, hmac-md5-96-etm@openssh.com, hmac-sha1-96-etm@openssh.com,\numac-64-etm@openssh.com, umac-128-etm@openssh.com"
try:
    sshd_output = subprocess.run("sshd -T | grep -Pi 'macs\\s+([^#\\n\\r]+)'", shell=True, capture_output=True, text=True).stdout.strip()

    if sshd_output:
        macs = sshd_output.split()[1].split(',')
        output.append(f"MAC algorithms found: {', '.join(macs)}")

        for mac in macs:
            if mac in weak_macs:
                weak_macs_found.append(mac)

        if weak_macs_found:
            output.append(f"Weak MAC algorithms found: {', '.join(weak_macs_found)}")
        else:
            output.append("No weak MAC algorithms found.")
    else:
        output.append("No MAC algorithms found in the SSH configuration.")

    actual_output = "\n".join(output)
    
    if weak_macs_found:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.7"
expected_output = "Valid patterns to match:\n" \
                  "allowusers <userlist>\n" \
                  "allowgroups <grouplist>\n" \
                  "denyusers <userlist>\n" \
                  "denygroups <grouplist>"

output = []
actual_output = []
valid_patterns = [
    r"allowusers\s+\S+",
    r"allowgroups\s+\S+",
    r"denyusers\s+\S+",
    r"denygroups\s+\S+"
]
try:
    sshd_output = subprocess.run("sshd -T | grep -Pi '^(allow|deny)(users|groups)\\s+\\S+'", shell=True, capture_output=True, text=True).stdout.strip()

    if sshd_output:
        output.append(f"Allow/Deny configuration found:\n{sshd_output}")

        match_found = any(re.search(pattern, sshd_output) for pattern in valid_patterns)

        if match_found:
            output.append("At least one valid configuration (allowusers, allowgroups, denyusers, denygroups) is present.")
        else:
            output.append("No valid allowusers, allowgroups, denyusers, or denygroups configuration found.")
    else:
        output.append("No Allow/Deny configuration found in the SSH settings.")

    actual_output = "\n".join(output)

    if match_found:
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

task_no = "5.1.8"
expected_output = "banner <banner>"
output = []
actual_output = []
try:
    banner_output = subprocess.run("sshd -T | grep -Pi '^banner\\h+/\\H+'", shell=True, capture_output=True, text=True).stdout.strip()

    if banner_output:
        output.append(banner_output)
        actual_output = banner_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "" 
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.9"
expected_output = "clientaliveinterval <x>\nclientalivecountmax <y>"
output = []
actual_output = []
try:
    alive_output = subprocess.run("sshd -T | grep -Pi -- '(clientaliveinterval|clientalivecountmax)'", shell=True, capture_output=True, text=True).stdout.strip()

    if alive_output:
        lines = alive_output.splitlines()
        valid = True
        for line in lines:
            key, value = line.split()
            if int(value) <= 0:
                valid = False
        if valid:
            actual_output = alive_output
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = alive_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.10"
expected_output = "disableforwarding yes"
output = []
actual_output = []
try:
    forward_output = subprocess.run("sshd -T | grep -i disableforwarding", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.11"
expected_output = "gssapiauthentication no"
output = []
actual_output = []
try:
    forward_output = subprocess.run("sshd -T | grep -i gssapiauthentication", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.12"
expected_output = "hostbasedauthentication no"
output = []
actual_output = []
try:
    forward_output = subprocess.run("sshd -T | grep hostbasedauthentication", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.13"
expected_output = "ignorerhosts yes"
output = []
actual_output = []
try:
    forward_output = subprocess.run("sshd -T | grep ignorerhosts", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.14"
output = []
actual_output = []
expected_output = "logingracetime <x>"
try:
    forward_output = subprocess.run("sshd -T | grep logingracetime", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        login_grace_time = int(actual_output.split()[1])
        if 1 <= login_grace_time <= 60:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.15"
output = []
actual_output = []
expected_output = "loglevel VERBOSE or loglevel INFO"
try:
    forward_output = subprocess.run("sshd -T | grep loglevel", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if "VERBOSE" in actual_output or "INFO" in actual_output:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.16"
output = []
actual_output = []
expected_output = "maxauthtries <x less than or equal to 4>"
try:
    forward_output = subprocess.run("sshd -T | grep maxauthtries", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        max_auth_tries = int(actual_output.split()[1])
        if max_auth_tries <= 4:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.17"
output = []
actual_output = []
try:
    forward_output = subprocess.run("sshd -T | awk '$1 ~ /^\s*maxstartups/{split($2, a, \":\");if(a[1] > 10 || a[2] > 30 || a[3] > 60) print $0}'", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "5.1.18"
output = []
actual_output = []
expected_output = "maxsessions <x less than or equal to 10>"
try:
    forward_output = subprocess.run("sshd -T | grep -i maxsessions", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        max_sessions = int(actual_output.split()[1])
        if max_sessions <= 10:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.1.19"
output = []
actual_output = []
expected_output = "permitemptypasswords no"
try:
    forward_output = subprocess.run("sshd -T | grep permitemptypasswords", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.20"
output = []
actual_output = []
expected_output = "permitrootlogin no"
try:
    forward_output = subprocess.run("sshd -T | grep permitrootlogin", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.21"
output = []
actual_output = []
expected_output = "permituserenvironment no"
try:
    forward_output = subprocess.run("sshd -T | grep permituserenvironment", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.1.22"
output = []
actual_output = []
expected_output = "usepam yes"
try:
    forward_output = subprocess.run("sshd -T | grep -i usepam", shell=True, capture_output=True, text=True).stdout.strip()

    if forward_output:
        actual_output = forward_output
        if actual_output.lower() == expected_output.lower():
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.2.1"
expected_output_prefix = "sudo-"
try:
    command = "rpm -q sudo"
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

task_no = "5.2.2"
expected_output = "Defaults use_pty"
output = []
actual_output = []
try:
    use_pty_output = subprocess.run(r"grep -rPi '^\s*Defaults\s+([^#\n\r]+,\s*)?use_pty\b' /etc/sudoers*", shell=True, capture_output=True, text=True).stdout.strip()

    no_use_pty_output = subprocess.run(r"grep -rPi '^\s*Defaults\s+([^#\n\r]+,\s*)?!use_pty\b' /etc/sudoers*", shell=True, capture_output=True, text=True).stdout.strip()

    if "Defaults use_pty" in use_pty_output and not no_use_pty_output:
        actual_output = use_pty_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = use_pty_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "5.2.3"
output = []
actual_output = []
expected_output = "<custom logfile configuration>"
try:
    logfile_output = subprocess.run(
        "grep -rP '^\\s*Defaults\\s+logfile\\s*=\\s*' /etc/sudoers*", 
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if logfile_output:
        actual_output = logfile_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.2.4"
output = []
actual_output = []
expected_output = "No NOPASSWD found"
try:
    nopasswd_output = subprocess.run(
        "grep -r '^[^#].*NOPASSWD' /etc/sudoers*", 
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if nopasswd_output:
        actual_output = nopasswd_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.2.5"
output = []
actual_output = []
expected_output = "No NOPASSWD found"
try:
    nopasswd_output = subprocess.run(
        " grep -r '^[^#].*\!authenticate' /etc/sudoers*", 
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if nopasswd_output:
        actual_output = nopasswd_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.2.6"
output = []
actual_output = []
expected_output = "timestamp_timeout <= 15"

try:
    timeout_output = subprocess.run(
        "grep -roP 'timestamp_timeout=\\K[0-9]*' /etc/sudoers", 
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if timeout_output:
        try:
            timeout_value = int(timeout_output.strip())
            if timeout_value <= 15:
                true_counter += 1
                true_tasks.append(task_no)
                task_data.append([task_no, "True", expected_output, f"timestamp_timeout={timeout_value}"])
            else:
                false_counter += 1
                false_tasks.append(task_no)
                task_data.append([task_no, "False", expected_output, f"timestamp_timeout={timeout_value}"])
        except ValueError:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, f"Invalid timeout value: {timeout_output}"])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.2.7"
output = []
actual_output = []
expected_output = "auth required pam_wheel.so use_uid group="
try:
    pam_output = subprocess.run(
        "grep -Pi '^[[:space:]]*auth[[:space:]]+(required|requisite)[[:space:]]+pam_wheel\\.so[[:space:]]+(use_uid[[:space:]]+group=[^#\\n\\r]+)' /etc/pam.d/su",
        shell=True, capture_output=True, text=True
    ).stdout.strip()

    if pam_output:
        actual_output = pam_output
        normalized_actual = normalize_whitespace(actual_output)
        normalized_expected = normalize_whitespace(expected_output)

        if normalized_expected in normalized_actual:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.1.1"
expected_output_prefix = "pam-"
try:
    command = "rpm -q pam"
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

task_no = "5.3.1.2"
expected_output_prefix = "authselect-"
try:
    command = "rpm -q authselect"
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

task_no = "5.3.1.3"
expected_output_prefix = "libpwquality-"
try:
    command = "rpm -q libpwquality"
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

task_no = "5.3.2.1"
output = []
actual_output = []
required_modules = ["pam_pwquality.so", "pam_pwhistory.so", "pam_faillock.so", "pam_unix.so"]
missing_modules = []
all_present = "All required modules are present"
try:
    authselect_profile = subprocess.run("head -1 /etc/authselect/authselect.conf", shell=True, capture_output=True, text=True).stdout.strip()
    grep_command = "grep -P -- '\\b({})\\b' /etc/authselect/{}/{{system,password}}-auth".format("|".join(required_modules), authselect_profile)    
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if module_output:
        actual_output = module_output
        for module in required_modules:
            if module not in module_output:
                missing_modules.append(module)
        if not missing_modules:
            actual_output += "\nAll required modules are present"
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", ", ".join(required_modules), all_present])
        else:
            actual_output += f"\nMissing modules: {', '.join(missing_modules)}"
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", ", ".join(required_modules), actual_output])
    else:
        actual_output = "No required modules found"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", ", ".join(required_modules), actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.2.2"
output = []
actual_output = []
expected_output = "pam_faillock.so"
all_present = "pam_faillock.so is present and enabled"
try:
    grep_command = "grep -P -- '\\bpam_faillock.so\\b' /etc/pam.d/{password,system}-auth"
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if expected_output in module_output:
        actual_output = module_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, all_present])
    else:
        actual_output = module_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "pam_faillock.so is not enabled"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.2.3"
output = []
actual_output = []
expected_output = "pam_pwquality.so"
all_present = "pam_pwquality.so is present and enabled"
try:
    grep_command = "grep -P -- '\\bpam_pwquality\.so\\b' /etc/pam.d/{password,system}-auth"                    
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if expected_output in module_output:
        actual_output = module_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, all_present])
    else:
        actual_output = module_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "pam_pwquality.so is not enabled"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.2.4"
output = []
actual_output = []
expected_output = "pam_pwhistory.so"
all_present = "pam_pwhistory.so is present and enabled"
try:
    grep_command = "grep -P -- '\\bpam_pwhistory\.so\\b' /etc/pam.d/{password,system}-auth"                    
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if expected_output in module_output:
        actual_output = module_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, all_present])
    else:
        actual_output = module_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "pam_pwhistory.so is not enabled"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.2.5"
output = []
actual_output = []
expected_output = "pam_unix.so"
all_present = "pam_unix.so is present and enabled"
try:
    grep_command = "grep -P -- '\\bpam_unix\.so\\b' /etc/pam.d/{password,system}-auth" 
    module_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if expected_output in module_output:
        actual_output = module_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, all_present])
    else:
        actual_output = module_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, "pam_unix.so is not enabled"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.1.1"
expected_output = "deny <= 5"

try:
    grep_command = "grep 'deny=' /etc/security/faillock.conf"
    deny_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    
    if deny_output:
        actual_output = deny_output
        # Extract the number after 'deny=' and handle any extra text or newline characters
        deny_value = int(deny_output.split('=')[1].strip().split()[0])
        
        if deny_value <= 5:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = "Not found in files"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


task_no = "5.3.3.1.2"
expected_output = "unlock_time = 0 or >= 900"

try:
    grep_command = "grep 'unlock_time=' /etc/security/faillock.conf"
    unlock_time_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    
    if unlock_time_output:
        actual_output = unlock_time_output
        # Extract the number after 'unlock_time=' and handle any extra text or newline characters
        unlock_time_value = int(unlock_time_output.split('=')[1].strip().split()[0])
        
        if unlock_time_value == 0 or unlock_time_value >= 900:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = "Not found in files"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


task_no = "5.3.3.1.3"
output = []
actual_output_deny = "even_root_deny"
actual_output_unlock = "root_unlock_time="
expected_output = "even_deny_root and/or root_unlock_time = 60 or more"
try:
    grep_command_1 = "grep 'even_deny_root' /etc/security/faillock.conf"
    grep_command_2 = "grep 'root_unlock_time' /etc/security/faillock.conf"
    deny_root_output = subprocess.run(grep_command_1, shell=True, capture_output=True, text=True).stdout.strip()
    root_unlock_time_output = subprocess.run(grep_command_2, shell=True, capture_output=True, text=True).stdout.strip()
    if deny_root_output:
        if actual_output_unlock in root_unlock_time_output:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output += f"\n{root_unlock_time_output}"
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.1"
expected_output = "difok = 2 or more"

try:
    grep_command = "grep -Psi -- '^\\h*difok\\h*=\\h*([2-9]|[1-9][0-9]+)\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    difok_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    
    if difok_output:
        actual_output = difok_output
        # Extract the number after 'difok=' and handle any extra text or newline characters
        difok_value = int(difok_output.split('=')[1].strip().split()[0])
        
        if difok_value >= 2:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = "Not found in files"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.2"
expected_output = "minlen = 14 or more"

try:
    grep_command = "grep -Psi -- '^\\h*minlen\\h*=\\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    minlen_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    
    if minlen_output:
        actual_output = minlen_output
        # Extract the number after 'minlen=' and handle any extra text or newline characters
        minlen_value = int(minlen_output.split('=')[1].strip().split()[0])
        
        if minlen_value >= 14:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = "Not found in files"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


task_no = "5.3.3.2.3"
output = []
actual_output = []
expected_output = "minclass=<x>\nor\ndcredit=<a>\nucredit=<b>\nlcredit=<c>\nocredit=<d>"
try:
    grep_command = "grep -Psi -- '^\\h*(minclass|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    complexity_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if complexity_output:
        minclass_set = None
        dulo_credits_set = {"dcredit": None, "ucredit": None, "lcredit": None, "ocredit": None}
        for line in complexity_output.splitlines():
            if "minclass" in line:
                minclass_set = line.strip()
            elif "dcredit" in line:
                dulo_credits_set["dcredit"] = line.strip()
            elif "ucredit" in line:
                dulo_credits_set["ucredit"] = line.strip()
            elif "lcredit" in line:
                dulo_credits_set["lcredit"] = line.strip()
            elif "ocredit" in line:
                dulo_credits_set["ocredit"] = line.strip()
        if minclass_set or all(dulo_credits_set.values()):
            actual_output = []
            if minclass_set:
                actual_output.append(minclass_set)
            if all(dulo_credits_set.values()):
                actual_output.extend(dulo_credits_set.values())
            actual_output = "\n".join(actual_output)
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = complexity_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.4"
output = []
actual_output = []
expected_output = "maxrepeat = 1-3"
try:
    grep_command = "grep -Psi -- '^\\h*maxrepeat\\h*=\\h*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    maxrepeat_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if maxrepeat_output:
        actual_output = maxrepeat_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.5"
output = []
actual_output = []
expected_output = "maxsequence = 1-3"
try:
    grep_command = "grep -Psi -- '^\\h*maxsequence\\h*=\\h*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    maxsequence_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if maxsequence_output:
        actual_output = maxsequence_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.6"
output = []
actual_output = []
expected_output = "dictcheck option is not set to 0"
try:
    grep_command = "grep -Psi -- '^\\h*dictcheck\\h*=\\h*0\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    dictcheck_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if not dictcheck_output:
        actual_output = "No output, dictcheck is not set to 0"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = dictcheck_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.2.7"
output = []
actual_output = []
expected_output = "enforce_for_root"
try:
    grep_command = "grep -Psi -- '^\\h*enforce_for_root\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf"
    enforce_for_root_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()

    if enforce_for_root_output:
        actual_output = enforce_for_root_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.3.1"
expected_output = "remember >= 24"

try:
    grep_command = "grep 'remember=' /etc/security/pwhistory.conf"
    remember_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    
    if remember_output:
        actual_output = remember_output
        remember_value = int(remember_output.split('=')[1].strip().split()[0])
        
        if remember_value >= 24:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = "Not found in files"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


task_no = "5.3.3.3.2"
output = []
actual_output = []
expected_output = "enforce_for_root"
try:
    grep_command = "grep -Pi -- '^\\h*enforce_for_root\\b' /etc/security/pwhistory.conf"
    enforce_for_root_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if enforce_for_root_output:
        actual_output = enforce_for_root_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.3.3"
output = []
actual_output = []
expected_output = "use_authtok"
try:
    grep_command = "grep -P -- '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_pwhistory\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' /etc/pam.d/{password,system}-auth"
    use_authtok_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if use_authtok_output:
        actual_output = use_authtok_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.4.1" 
output = []
actual_output = []
expected_output = "no nullok"
try:
    grep_command = "grep -P -- '^\h*(auth|account|password|session)\\h+(requisite|required|sufficient)\\h+pam_unix\\.so\\b' /etc/pam.d/{password,system}-auth"
    pam_unix_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if pam_unix_output:
        if "nullok" in pam_unix_output:
            actual_output = pam_unix_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
        else:
            actual_output = ""
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.4.2" 
output = []
actual_output = []
expected_output = "no remember"
try:
    grep_command = "grep -Pi '^\h*password\h+([^#\n\r]+\h+)?pam_unix\.so\b' /etc/pam.d/{password,system}-auth | grep -Pv '\bremember=\d\b'"
    pam_unix_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if pam_unix_output:
        if "remember" in pam_unix_output:
            actual_output = pam_unix_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
        else:
            actual_output = ""
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.3.3.4.3"
output = []
actual_output = []
expected_output = "strong password hashing algorithm (sha512 or yescrypt)"
try:
    grep_command = "grep -P -- '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512|yescrypt)\\b' /etc/pam.d/{password,system}-auth"
    pam_unix_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()

    if pam_unix_output:
        actual_output = pam_unix_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "5.3.3.4.4"
output = []
actual_output = []
expected_output = "use_authtok is set"
try:
    grep_command = "grep -P -- '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' /etc/pam.d/{password,system}-auth"
    pam_unix_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()

    if pam_unix_output:
        actual_output = pam_unix_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.1"
output = []
actual_output = []
expected_output = "PASS_MAX_DAYS is 365 or less"
try:
    grep_command = "grep -Pi -- '^\\h*PASS_MAX_DAYS\\h+\\d+\\b' /etc/login.defs"
    pass_max_days_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if pass_max_days_output:
        max_days_value = int(pass_max_days_output.split()[1])
        if max_days_value <= 365:
            actual_output = pass_max_days_output
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = pass_max_days_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.2"
output = []
actual_output = []
expected_output = "PASS_MIN_DAYS is greater than 0"
try:
    grep_command = "grep -Pi -- '^\\h*PASS_MIN_DAYS\\h+\\d+\\b' /etc/login.defs"
    pass_min_days_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if pass_min_days_output:
        min_days_value = int(pass_min_days_output.split()[1])
        if min_days_value > 0:
            actual_output = pass_min_days_output
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = pass_min_days_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.3"
output = []
actual_output = []
expected_output = "PASS_WARN_AGE is 7 or more"
try:
    grep_command = "grep -Pi -- '^\\h*PASS_WARN_AGE\\h+\\d+\\b' /etc/login.defs"
    pass_warn_age_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if pass_warn_age_output:
        warn_age_value = int(pass_warn_age_output.split()[1])
        if warn_age_value >= 7:
            actual_output = pass_warn_age_output
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = pass_warn_age_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.4"
output = []
actual_output = []
expected_output = "ENCRYPT_METHOD is sha512 or yescrypt"
try:
    grep_command = "grep -Pi -- '^\\h*ENCRYPT_METHOD\\h+(SHA512|yescrypt)\\b' /etc/login.defs"
    encrypt_method_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if encrypt_method_output:
        actual_output = encrypt_method_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.5"
output = []
actual_output = []
expected_output = "INACTIVE conforms to site policy (no more than 45 days)"
try:
    grep_command = "useradd -D | grep INACTIVE"
    inactive_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    if inactive_output:
        inactive_value = int(inactive_output.split('=')[1].strip())
        if inactive_value <= 45:
            actual_output = inactive_output
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = inactive_output
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.1.6"
output = []
actual_output = []
expected_output = "No output"
try:
    bash_command = """
    #!/usr/bin/env bash
    {
        while IFS= read -r l_user; do
            l_change=$(date -d "$(chage --list $l_user | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s)
            if [[ "$l_change" -gt "$(date +%s)" ]]; then
                echo "User: \"$l_user\" last password change was \"$(chage --list $l_user | grep '^Last password change' | cut -d: -f2)\""
            fi
        done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)
    }
    """
    script_output = subprocess.run(bash_command, shell=True, capture_output=True, text=True).stdout.strip()
    if script_output:
        actual_output = script_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.1"
output = []
actual_output = []
expected_output = "root"
try:
    awk_command = "awk -F: '($3 == 0) { print $1 }' /etc/passwd"
    root_output = subprocess.run(awk_command, shell=True, capture_output=True, text=True).stdout.strip()
    if root_output == expected_output:
        actual_output = root_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = root_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.2"
output = []
actual_output = []
expected_output = "root:0"
try:
    awk_command = "awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4==\"0\") {print $1\":\"$4}' /etc/passwd"
    gid_output = subprocess.run(awk_command, shell=True, capture_output=True, text=True).stdout.strip()
    if gid_output == expected_output:
        actual_output = gid_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = gid_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.3"
output = []
actual_output = []
expected_output = "root:0"
try:
    awk_command = "awk -F: '$3==\"0\"{print $1\":\"$3}' /etc/group"
    gid_output = subprocess.run(awk_command, shell=True, capture_output=True, text=True).stdout.strip()
    if gid_output == expected_output:
        actual_output = gid_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = gid_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.4"
output = []
actual_output = []
expected_output_set = "User: \"root\" Password is set"
expected_output_locked = "Password locked."
try:
    passwd_command = "passwd -S root | awk '$2 ~ /^P/ {print \"User: \\\"\" $1 \"\\\" Password is set\"; exit} $2 ~ /^L/ {print \"Password locked.\"}'"
    passwd_output = subprocess.run(passwd_command, shell=True, capture_output=True, text=True).stdout.strip()

    if passwd_output == expected_output_set or passwd_output == expected_output_locked:
        actual_output = passwd_output
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_set + ' or ' + expected_output_locked, actual_output])
    else:
        actual_output = passwd_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_set + ' or ' + expected_output_locked, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.5"
output = []
actual_output = []
expected_output_pass = "Root's path is correctly configured"
expected_output_fail = "Reasons for audit failure"
try:
    script_command = """#!/usr/bin/env bash
{
 l_output2=""
 l_pmask="0022"
 l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
 l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"
 unset a_path_loc && IFS=":" read -ra a_path_loc <<< "$l_root_path"
 grep -q "::" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a empty directory (::)"
 grep -Pq ":\h*$" <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains a trailing (:)"
 grep -Pq '(\h+|:)\.(:|\h*$)' <<< "$l_root_path" && l_output2="$l_output2\n - root's path contains current working directory (.)"
 while read -r l_path; do
 if [ -d "$l_path" ]; then
 while read -r l_fmode l_fown; do
 [ "$l_fown" != "root" ] && l_output2="$l_output2\n - Directory: \"$l_path\" is owned by: \"$l_fown\" should be owned by \"root\""
 [ $(( $l_fmode & $l_pmask )) -gt 0 ] && l_output2="$l_output2\n - Directory: \"$l_path\" is mode: \"$l_fmode\" and should be mode: \"$l_maxperm\" or more restrictive"
 done <<< "$(stat -Lc '%#a %U' "$l_path")"
 else
 l_output2="$l_output2\n - \"$l_path\" is not a directory"
 fi
 done <<< "$(printf "%s\n" "${a_path_loc[@]}")"
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n *** PASS ***\n - Root's path is correctly configured\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n"
 fi
}"""

    audit_result = subprocess.run(script_command, shell=True, capture_output=True, text=True)
    actual_output = audit_result.stdout.strip()
    if "PASS" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_fail, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.6"
output = []
actual_output = []
expected_output = "no umask set"
try:
    grep_command = "grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' /root/.bash_profile /root/.bashrc"
    umask_output = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip() 
    if umask_output:
        actual_output = umask_output
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.7"
output = []
actual_output = []
expected_output = "no invalid login shells"
try:
    bash_script = """#!/usr/bin/env bash
{
 l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
 awk -v pat="$l_valid_shells" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) && $(NF) ~ pat) {print "Service account: \"" $1 "\" has a valid shell: " $7}' /etc/passwd
}"""
    result = subprocess.run(bash_script, shell=True, capture_output=True, text=True)
    actual_output = result.stdout.strip()
    if actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.2.8"
output = []
actual_output = []
expected_output = "all non-root accounts without a valid login shell are locked"
try:
    bash_script = """#!/usr/bin/env bash
{
 l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
 while IFS= read -r l_user; do
     passwd -S "$l_user" | awk '$2 !~ /^L/ {print "Account: \"" $1 "\" does not have a valid login shell and is not locked"}'
 done < <(awk -v pat="$l_valid_shells" -F: '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)
}"""
    result = subprocess.run(bash_script, shell=True, capture_output=True, text=True)
    actual_output = result.stdout.strip()    
    if actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.3.1"
output = []
actual_output = []
expected_output = "nologin is not listed in /etc/shells"
try:
    grep_command = "grep -Ps '^\h*([^#\n\r]+)?/nologin\b' /etc/shells"
    result = subprocess.run(grep_command, shell=True, capture_output=True, text=True)
    actual_output = result.stdout.strip()
    
    if actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.3.2"
output = []
actual_output = []
expected_output = "TMOUT is configured to 900 seconds or less, readonly, and exported"
try:
    grep_command = "grep -Pls -- '^([^#\\n\\r]+)?\\bTMOUT\\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh"
    files = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip().splitlines()
    l_tmout_set = 900
    incorrect_files = []
    tmout_found = False    
    for file in files:
        tmout_value = subprocess.run(f"grep -Po -- '^([^#\\n\\r]+)?TMOUT=\\d+' {file} | awk -F= '{{print $2}}'", shell=True, capture_output=True, text=True).stdout.strip()
        readonly = subprocess.run(f"grep -P -- '^\h*(typeset\h\-xr\hTMOUT=\\d+|([^#\\n\\r]+)?\\breadonly\\h+TMOUT\\b)' {file}", shell=True, capture_output=True, text=True).stdout.strip()
        exported = subprocess.run(f"grep -P -- '^\h*(typeset\h\-xr\hTMOUT=\\d+|([^#\\n\\r]+)?\\bexport\\b([^#\\n\\r]+\\b)?TMOUT\\b)' {file}", shell=True, capture_output=True, text=True).stdout.strip()
        if tmout_value:
            tmout_value = int(tmout_value)
            tmout_found = True
            if tmout_value <= l_tmout_set and tmout_value > 0 and readonly and exported:
                output.append(f" - TMOUT is correctly set to {tmout_value} in {file}")
            else:
                incorrect_files.append(f" - TMOUT is incorrectly set or not properly configured in {file}")
        else:
            incorrect_files.append(f" - TMOUT is not set in {file}")
    if not tmout_found:
        incorrect_files.append(" - TMOUT is not configured in any relevant files.")
    if incorrect_files:
        actual_output = "\n".join(incorrect_files)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "5.4.3.3"
output = []
actual_output = []
expected_output = "Default user umask is set to 027 or u=rwx,g=rx,o="
try:
    grep_command = "grep -Ps '^\h*([^#\\n\\r]+)?\\/nologin\\b' /etc/shells"
    umask_found = subprocess.run(grep_command, shell=True, capture_output=True, text=True).stdout.strip()
    incorrect_files = []
    umask_correct = False
    if not umask_found:
        files_to_check = [
            "/etc/profile.d/*.sh",
            "/etc/profile",
            "/etc/bashrc",
            "/etc/bash.bashrc",
            "/etc/login.defs",
            "/etc/default/login"
        ]
        for pattern in files_to_check:
            matching_files = subprocess.run(f"find {pattern} -type f", shell=True, capture_output=True, text=True).stdout.strip().splitlines()
            for file in matching_files:
                if file:
                    umask_value = subprocess.run(f"grep -Psi '^\h*umask\h+' {file}", shell=True, capture_output=True, text=True).stdout.strip()
                    if umask_value:
                        if "027" in umask_value or "u=rwx,g=rx,o=" in umask_value:
                            umask_correct = True
                            output.append(f" - umask is set correctly in \"{file}\"")
                        else:
                            incorrect_files.append(f" - umask is incorrectly set in \"{file}\"")
        if not umask_correct:
            incorrect_files.append(" - umask is not configured in any relevant files.")
    if incorrect_files:
        actual_output = "\n".join(incorrect_files)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

show_results()

### Written By: 
###     1. Aditi Jamsandekar
###     2. Chirayu Rathi
###     3. Siddhi Jani
############################
