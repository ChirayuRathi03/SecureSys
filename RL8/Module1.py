import os
import pandas as pd
from tabulate import tabulate
import subprocess
import shlex

true_counter = 0
false_counter = 0
true_tasks = []
false_tasks = []
task_data =[]
task_data = []
status = ""

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
    excel_file = "CIS_RHEL8_Hardening_Report.xlsx"
    module_name = os.path.splitext(os.path.basename(__file__))[0]
    with pd.ExcelWriter(excel_file, engine="openpyxl", mode="a" if os.path.exists(excel_file) else "w") as writer:
        df.to_excel(writer, sheet_name=module_name, index=False)

    print(f"Results written to sheet '{module_name}' in {excel_file}")


def normalize_content(content):
    return ' '.join(content.split()).strip()


def check_file_content(file_name: str, expected_content: str, task_no: str) -> None:
    global true_counter, false_counter, true_tasks, false_tasks, task_data

    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            file_content = file.read()
        
        normalized_file_content = normalize_content(file_content)
        normalized_expected_content = normalize_content(expected_content)
        
        if normalized_file_content == normalized_expected_content:
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_content, file_content])
        else:
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_content, file_content])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_content, "File not found"])

def check_permissions(task_no, expected_permission, file_path):
    try:
        command = f"stat -c '%A %u %g' {file_path}"
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        actual_output = process.stdout.strip()

        normalized_expected = ' '.join(expected_permission.split()).strip()
        normalized_actual = ' '.join(actual_output.split()).strip()

        if normalized_actual == normalized_expected:
            task_data.append([task_no, "True", expected_permission, actual_output])
        else:
            task_data.append([task_no, "False", expected_permission, actual_output])
        if status == "False":
            false_counter += 1
            false_tasks.append(task_no)
        else:
            true_counter += 1
            true_tasks.append(task_no)

    except Exception as e:
        task_data.append([task_no, "False", expected_permission, f"Error: {str(e)}"])

check_file_content(file_name="/etc/modprobe.d/disable-cramfs.conf", expected_content="install cramfs /bin/false \nblacklist cramfs", task_no="1.1.1.1")
check_file_content(file_name="/etc/modprobe.d/disable-freevxfs.conf", expected_content="install freevxfs /bin/false \nblacklist freevxfs", task_no="1.1.1.2")
check_file_content(file_name="/etc/modprobe.d/disable-hfs.conf", expected_content="install hfs /bin/false \nblacklist hfs", task_no="1.1.1.3")
check_file_content(file_name="/etc/modprobe.d/disable-hfsplus.conf", expected_content="install hfsplus /bin/false \nblacklist hfsplus", task_no="1.1.1.4")
check_file_content(file_name="/etc/modprobe.d/disable-jffs2.conf", expected_content="install jffs2 /bin/false \nblacklist jffs2", task_no="1.1.1.5")
check_file_content(file_name="/etc/modprobe.d/disable-squashfs.conf", expected_content="install squashfs /bin/false \nblacklist squashfs", task_no="1.1.1.6")
check_file_content(file_name="/etc/modprobe.d/disable-udf.conf", expected_content="install udf /bin/false \nblacklist udf", task_no="1.1.1.7")
check_file_content(file_name="/etc/modprobe.d/disable-usb-storage.conf", expected_content="install usb-storage /bin/false \nblacklist usb-storage", task_no="1.1.1.8")

task_no = "1.2.2"
expected_gpgcheck_output = "gpgcheck=1"
try:
    gpgcheck_found = False

    if os.path.exists("/etc/dnf/dnf.conf"):
        with open("/etc/dnf/dnf.conf", "r") as dnf_conf:
            for line in dnf_conf:
                if line.strip().startswith("gpgcheck="):
                    value = line.strip().split("=")[1]
                    if value == "1":
                        gpgcheck_found = True

    if not gpgcheck_found and os.path.exists("/etc/yum.repos.d/"):
        repo_files = [f for f in os.listdir("/etc/yum.repos.d/") if f.endswith(".repo")]
        for repo_file in repo_files:
            repo_path = os.path.join("/etc/yum.repos.d/", repo_file)
            with open(repo_path, "r") as repo:
                for line in repo:
                    if line.strip().startswith("gpgcheck="):
                        value = line.strip().split("=")[1]
                        if value == "1":
                            gpgcheck_found = True
                            break
            if gpgcheck_found:
                break

    if gpgcheck_found:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_gpgcheck_output, "gpgcheck=1"])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_gpgcheck_output, "No match found"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_gpgcheck_output, f"Error: {str(e)}"])

task_no = "1.2.3"
expected_gpgcheck_output = "repo_gpgcheck=1"
try:
    gpgcheck_found = False

    if os.path.exists("/etc/dnf/dnf.conf"):
        with open("/etc/dnf/dnf.conf", "r") as dnf_conf:
            for line in dnf_conf:
                if line.strip().startswith("repo_gpgcheck="):
                    value = line.strip().split("=")[1]
                    if value == "1":
                        gpgcheck_found = True

    if not gpgcheck_found and os.path.exists("/etc/yum.repos.d/"):
        repo_files = [f for f in os.listdir("/etc/yum.repos.d/") if f.endswith(".repo")]
        for repo_file in repo_files:
            repo_path = os.path.join("/etc/yum.repos.d/", repo_file)
            with open(repo_path, "r") as repo:
                for line in repo:
                    if line.strip().startswith("repo_gpgcheck="):
                        value = line.strip().split("=")[1]
                        if value == "1":
                            gpgcheck_found = True
                            break
            if gpgcheck_found:
                break

    if gpgcheck_found:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_gpgcheck_output, "repo_gpgcheck=1"])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_gpgcheck_output, "No match found"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_gpgcheck_output, f"Error: {str(e)}"])
    
task_no = "1.3.1"
expected_output = "GRUB2_PASSWORD=grub.pbkdf2.sha512"

try:
    find_command = "find /boot -type f -name 'user.cfg' ! -empty"
    process_find = subprocess.run(find_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    l_grub_password_file = process_find.stdout.strip()

    actual_output = ""

    if os.path.isfile(l_grub_password_file):
        grep_command = f"awk -F. '/^\\s*GRUB2_PASSWORD=\\S+/ {{print $1\".\"$2\".\"$3}}' {l_grub_password_file}"
        process_grep = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        actual_output = process_grep.stdout.strip()

    if actual_output.startswith(expected_output.split("=")[0]):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output if actual_output else "No matching line found"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.3.2"
expected_output = "Audit Result: *** PASS ***"

def file_mug_chk(l_file, l_mode, l_user, l_group):
    l_output = ""
    l_output2 = ""
    if os.path.dirname(l_file).startswith("/boot/efi/EFI"):
        l_pmask = 0o0077
    else:
        l_pmask = 0o0177
    l_maxperm = oct(0o0777 & ~l_pmask)[2:]
    if int(l_mode, 8) & l_pmask > 0:
        l_output2 += f"\n - Is mode \"{l_mode}\" and should be mode: \"{l_maxperm}\" or more restrictive"
    else:
        l_output += f"\n - Is correctly mode: \"{l_mode}\" which is mode: \"{l_maxperm}\" or more restrictive"
    if l_user == "root":
        l_output += f"\n - Is correctly owned by user: \"{l_user}\""
    else:
        l_output2 += f"\n - Is owned by user: \"{l_user}\" and should be owned by user: \"root\""
    if l_group == "root":
        l_output += f"\n - Is correctly group-owned by group: \"{l_group}\""
    else:
        l_output2 += f"\n - Is group-owned by group: \"{l_group}\" and should be group-owned by group: \"root\""
    return l_output, l_output2

try:
    command = "find /boot -type f \\( -name 'grub*' -o -name 'user.cfg' \\) -print0"
    process_find = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    files = process_find.stdout.split('\0')

    l_output = ""
    l_output2 = ""

    for l_gfile in files:
        if not l_gfile.strip():
            continue
        stat_command = f"stat -Lc '%n %#a %U %G' {l_gfile}"
        process_stat = subprocess.run(stat_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stat_output = process_stat.stdout.strip()
        if stat_output:
            l_file, l_mode, l_user, l_group = stat_output.split()
            out, out2 = file_mug_chk(l_file, l_mode, l_user, l_group)
            l_output += out
            l_output2 += out2

    if not l_output2:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, "*** PASS ***"])
    else:
        result = f"\n ** FAIL **\n - * Reasons for audit failure * :\n{l_output2}\n"
        if l_output:
            result += f" - * Correctly set * :\n{l_output}\n"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, result])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.4.1"
expected_output = "kernel.randomize_va_space = 2"

try:
    command = "sysctl kernel.randomize_va_space"
    process_sysctl = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process_sysctl.stdout.strip()

    command_check_file = "grep -E '^\\s*kernel.randomize_va_space\\s*=\\s*2\\b' /etc/sysctl.conf /etc/sysctl.d/*"
    process_file_check = subprocess.run(command_check_file, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    file_output = process_file_check.stdout.strip()

    if actual_output == expected_output and file_output:
        task_data.append([task_no, "True", expected_output, actual_output])
        true_counter += 1
        true_tasks.append(task_no)
    else:
        task_data.append([task_no, "False", expected_output, f"{actual_output}\nFile check: {file_output if file_output else 'Not found in files'}"])
        false_counter += 1
        false_tasks.append(task_no)

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.4.2"
expected_output = "kernel.yama.ptrace_scope = 1"

try:
    command = "sysctl kernel.yama.ptrace_scope"
    process_sysctl = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process_sysctl.stdout.strip()

    command_check_file = "grep -E '^\\s*kernel.yama.ptrace_scope\\s*=\\s*1\\b' /etc/sysctl.conf /etc/sysctl.d/*"
    process_file_check = subprocess.run(command_check_file, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    file_output = process_file_check.stdout.strip()

    if actual_output == expected_output and file_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, f"{actual_output}\nFile check: {file_output if file_output else 'Not found in files'}"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.4.3"
expected_output = "ProcessSizeMax=0 ProcessSizeMax=0"

try:
    command = "systemd-analyze cat-config /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* | grep -Pio '^\\s*ProcessSizeMax\\s*=\\s*0\\b'"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip()

    normalized_expected_output = ' '.join(expected_output.split()).strip()
    normalized_actual_output = ' '.join(actual_output.split()).strip()

    if normalized_actual_output == normalized_expected_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output if actual_output else "Not found in files"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])
    
task_no = "1.4.4"
expected_output = "Storage=none Storage=none"

try:
    command = "systemd-analyze cat-config /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* | grep -Pio '^\\s*Storage\\s*=\\s*none\\b'"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip()

    normalized_expected_output = ' '.join(expected_output.split()).strip()
    normalized_actual_output = ' '.join(actual_output.split()).strip()

    if normalized_actual_output == normalized_expected_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output if actual_output else "Not found in files"])

except Exception as e:
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])
    false_counter += 1
    false_tasks.append(task_no)

task_no = "1.5.1.1"
expected_output_prefix = "libselinux-"
try:
    command = "rpm -q libselinux"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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

task_no = "1.5.1.2"
expected_output = ""
try:
    command = "grubby --info=ALL | grep -Po '(selinux|enforcing)=0\\b'"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else ""

    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, ""])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.5.1.3"
expected_output = "SELINUXTYPE=targeted"
try:
    command = "grep -E '^\s*SELINUXTYPE=(targeted|mls)\\b' /etc/selinux/config"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else ""

    if expected_output in actual_output:
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

task_no = "1.5.1.4"
expected_outputs = ["Enforcing", "Permissive"]
try:
    command = "getenforce"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else ""

    if actual_output in expected_outputs:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", " or ".join(expected_outputs), actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", " or ".join(expected_outputs), actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", " or ".join(expected_outputs), f"Error: {str(e)}"])

task_no = "1.5.1.5"
expected_output = "Enforcing"
try:
    command = "getenforce"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else ""

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

task_no = "1.5.1.6"
expected_output = "Nothing (empty output)"
try:
    command = "ps -eZ | grep unconfined_service_t"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else ""

    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, "Nothing (Empty Output)"])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "1.5.1.7"
expected_output_prefix = "package mcstrans"
try:
    command = "rpm -q mcstrans"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else "error"
    
    if actual_output.startswith(expected_output_prefix):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "package mctrans is not installed", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "package mctrans is not installed", actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_prefix}x", f"Error: {str(e)}"])

task_no = "1.5.1.8"
expected_output_prefix = "package setroubleshoot"
try:
    command = "rpm -q setroubleshoot"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip() if process.stdout else "error"
    
    if actual_output.startswith(expected_output_prefix):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "package setroubleshoot is not installed", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "package setroubleshoot is not installed", actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_prefix}x", f"Error: {str(e)}"])

task_no = "1.6.1"
expected_output = ""

try:
    command = "grep -Pi '^\\s*LEGACY\\b' /etc/crypto-policies/config"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip()

    if actual_output == expected_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", actual_output if actual_output else "Lines returned"])
        
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.6.2"
expected_sha1_hash = ""
expected_sha1_in_certs = "sha1_in_certs = 0"
combined_status = "True"

try:
    command1 = "awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\\s*\\-\\s*([^#\\n\\r]+)?SHA1/){print}' /etc/crypto-policies/state/CURRENT.pol"
    process1 = subprocess.run(command1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_sha1_hash = process1.stdout.strip()

    command2 = "grep -Psi -- '^\\s*sha1_in_certs\\s*=\\s*' /etc/crypto-policies/state/CURRENT.pol"
    process2 = subprocess.run(command2, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_sha1_in_certs = process2.stdout.strip()

    if actual_sha1_hash != expected_sha1_hash or expected_sha1_in_certs not in actual_sha1_in_certs:
        combined_status = "False"

    task_data.append([task_no, combined_status, "Both SHA1 hash and sha1_in_certs checks passed", f"{actual_sha1_hash} / {actual_sha1_in_certs}"])
    if combined_status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "SHA1 hash or sha1_in_certs check failed", f"Error: {str(e)}"])

task_no = "1.6.3"
output_check = ""
failure_reason = ""
status = "True"

try:
    cbc_check_command = "grep -Piq -- '^\\h*cipher\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol"
    cbc_for_ssh_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*' /etc/crypto-policies/state/CURRENT.pol"
    no_cbc_for_ssh_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol"

    cbc_output = subprocess.run(cbc_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ssh_cipher_output = subprocess.run(cbc_for_ssh_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if cbc_output.returncode == 0:
        if ssh_cipher_output.returncode == 0:
            no_cbc_output = subprocess.run(no_cbc_for_ssh_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if no_cbc_output.returncode == 0:
                failure_reason = "Cipher Block Chaining (CBC) is enabled for SSH"
                status = "False"
            else:
                output_check = "Cipher Block Chaining (CBC) is disabled for SSH"
        else:
            failure_reason = "Cipher Block Chaining (CBC) is enabled for SSH"
            status = "False"
    else:
        output_check = " - Cipher Block Chaining (CBC) is disabled"

    if not failure_reason:
        result_output = f"{output_check}"
    else:
        result_output = f"{failure_reason}"

    task_data.append([task_no, status, result_output.strip(), ""])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "CBC check passed", f"Error: {str(e)}"])

task_no = "1.6.4"
expected_output = ""
status = "True"
try:
    command = "grep -Pi -- '^\\h*mac\\h*=\\h*([^#\\n\\r]+)?-64\\b' /etc/crypto-policies/state/CURRENT.pol"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    actual_output = process.stdout.strip()

    if actual_output != expected_output:
        status = "False"

    task_data.append([task_no, status, "", actual_output])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    false_counter += 1
    false_tasks.append(task_no)

task_no = "1.7.1"
output_check = ""
failure_reason = ""
status = "True"

try:
    motd_check_command = '''
    for l_file in /etc/motd{,.d/*}; do
        if grep -Psqi -- "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release | cut -d= -f2 | sed -e 's/\\"//g')\b)" "$l_file"; then
            echo "File: \"$l_file\" includes system information"
        fi
    done
    '''

    motd_output = subprocess.run(motd_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if motd_output.returncode == 0:
        if motd_output.stdout:
            actual_output = motd_output.stdout.strip()
            status = "False"
        else:
            actual_output = "No MOTD files include system information"
    else:
        actual_output = "Failed to check MOTD files"

    task_data.append([task_no, status, expected_output, actual_output])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", "Error: " + str(e)])

task_no = "1.7.2"
output_check = ""
failure_reason = ""
status = "True"

try:
    issue_check_command = "grep -E -i '(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue"

    issue_output = subprocess.run(issue_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if issue_output.returncode == 0:
        output_check = issue_output.stdout.decode().strip()
        status = "False"
        failure_reason = r"/etc/issue includes system info"
    else:
        output_check = ""
        status = "True"

    task_data.append([task_no, status, "", output_check])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", "Error: " + str(e)])
    

task_no = "1.7.3"
output_check = ""
failure_reason = ""
status = "True"

try:
    issue_net_check_command = "grep -E -i '(\\v|\\r|\\m|\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))' /etc/issue.net"

    issue_net_output = subprocess.run(issue_net_check_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if issue_net_output.returncode == 0:
        output_check = issue_net_output.stdout.decode().strip()
        status = "False"
        failure_reason = r"/etc/issue.net includes system information"
    else:
        output_check = ""

    task_data.append([task_no, status, "", output_check if output_check else ""])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", "Error: " + str(e)])
    
check_permissions("1.7.4", "-rw-r--r-- 0 0 ", "/etc/motd")
check_permissions("1.7.5", "-rw-r--r-- 0 0 ", "/etc/issue")
check_permissions("1.7.6", "-rw-r--r-- 0 0 ", "/etc/issue.net")

task_no = "1.8.1"
output_check = "package gdm is not installed"
failure_reason = ""
status = "True"

try:
    command = "rpm -q gdm"
    process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    expected_output = "package gdm is not installed"
    actual_output = process.stdout.strip()

    if actual_output == expected_output:
        output_check = expected_output
    else:
        failure_reason = f"{actual_output}"
        status = "False"

    result_output = output_check if status == "True" else failure_reason
    task_data.append([task_no, status, expected_output, result_output.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "package gdm is not installed", f"Error: {str(e)}"])
    
task_no = "1.8.2"
output_check = ""
failure_reason = ""
status = "True"

try:
    check_pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]

    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        check_gdmfile_command = "grep -Prils '^\\h*banner-message-enable\\b' /etc/dconf/db/*.d"
        gdmfile_process = subprocess.run(check_gdmfile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        gdmfile = gdmfile_process.stdout.strip()

        if gdmfile:
            gdmprofile_command = f"awk -F/ '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{gdmfile}\""
            gdmprofile_process = subprocess.run(gdmprofile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            gdmprofile = gdmprofile_process.stdout.strip()

            check_banner_enable_command = f"grep -Pisq '^\\h*banner-message-enable=true\\b' {gdmfile}"
            banner_enable_process = subprocess.run(check_banner_enable_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if banner_enable_process.returncode == 0:
                output_check += f"\n - The \"banner-message-enable\" option is enabled in \"{gdmfile}\""
            else:
                failure_reason += f"\n - The \"banner-message-enable\" option is not enabled"

            check_banner_text_command = f"grep -Pios '^\\h*banner-message-text=.*$' {gdmfile}"
            banner_text_process = subprocess.run(check_banner_text_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            banner_text = banner_text_process.stdout.strip()

            if banner_text:
                output_check += f"\n - The \"banner-message-text\" option is set in \"{gdmfile}\"\n - banner-message-text is set to:\n - \"{banner_text}\""
            else:
                failure_reason += f"\n - The \"banner-message-text\" option is not set"

            check_profile_command = f"grep -Pq '^\\h*system-db:{gdmprofile}' /etc/dconf/profile/{gdmprofile}"
            profile_process = subprocess.run(check_profile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if profile_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" profile doesn't exist"

            check_db_command = f"test -f /etc/dconf/db/{gdmprofile}"
            db_process = subprocess.run(check_db_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if db_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists in the dconf database"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" profile doesn't exist in the dconf database"
        else:
            failure_reason += "\n - The \"banner-message-enable\" option isn't configured"
    else:
        output_check = "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n *** PASS ***\n"

    expected_outputs = [
        f"\n - The \"banner-message-enable\" option is enabled in \"{gdmfile}\"",
        f"\n - The \"banner-message-text\" option is set in \"{gdmfile}\"\n - banner-message-text is set to:\n - \"{banner_text}\"",
        f"\n - The \"{gdmprofile}\" profile exists",
        f"\n - The \"{gdmprofile}\" profile exists in the dconf database"
    ]
    actual_outputs = [
        output_check.strip() if "banner-message-enable" in output_check else failure_reason.strip(),
        banner_text if banner_text else "",
        "The profile exists" if profile_process.returncode == 0 else "The profile doesn't exist",
        "The profile exists in the dconf database" if db_process.returncode == 0 else "The profile doesn't exist in the dconf database"
    ]

    if not failure_reason:
        task_data.append([task_no, status, "\n".join(expected_outputs), "\n".join(actual_outputs)])
    else:
        status = "False"
        task_data.append([task_no, status, "\n".join(expected_outputs), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.3"
output_check = ""
failure_reason = ""
status = "True"

try:
    check_pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]

    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        check_gdmfile_command = "grep -Pril '^\\h*disable-user-list\\h*=\\h*true\\b' /etc/dconf/db"
        gdmfile_process = subprocess.run(check_gdmfile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        gdmfile = gdmfile_process.stdout.strip()

        if gdmfile:
            output_check += f"\n - The \"disable-user-list\" option is enabled in \"{gdmfile}\""
            gdmprofile_command = f"awk -F/ '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{gdmfile}\""
            gdmprofile_process = subprocess.run(gdmprofile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            gdmprofile = gdmprofile_process.stdout.strip()

            check_profile_command = f"grep -Pq '^\\h*system-db:{gdmprofile}' /etc/dconf/profile/{gdmprofile}"
            profile_process = subprocess.run(check_profile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if profile_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" doesn't exist"

            check_db_command = f"test -f /etc/dconf/db/{gdmprofile}"
            db_process = subprocess.run(check_db_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if db_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists in the dconf database"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" profile doesn't exist in the dconf database"
        else:
            failure_reason += "\n - The \"disable-user-list\" option is not enabled"
    else:
        output_check = "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n *** PASS ***\n"

    expected_outputs = [
        f"\n - The \"disable-user-list\" option is enabled in \"{gdmfile}\"",
        f"\n - The \"{gdmprofile}\" profile exists",
        f"\n - The \"{gdmprofile}\" profile exists in the dconf database"
    ]
    actual_outputs = [
        output_check.strip() if "disable-user-list" in output_check else failure_reason.strip(),
        "The profile exists" if profile_process.returncode == 0 else "The profile doesn't exist",
        "The profile exists in the dconf database" if db_process.returncode == 0 else "The profile doesn't exist in the dconf database"
    ]

    if not failure_reason:
        task_data.append([task_no, status, "\n".join(expected_outputs), "\n".join(actual_outputs)])
    else:
        status = "False"
        task_data.append([task_no, status, "\n".join(expected_outputs), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.4"
output_check = ""
failure_reason = ""
status = "True"

try:
    check_pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]
    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        output_check = ""
        failure_reason = ""
        max_idle_delay = 900
        max_lock_delay = 5
        
        kfile_command = "grep -Psril '^\\h*idle-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/"
        kfile_process = subprocess.run(kfile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        kfile = kfile_process.stdout.strip()

        if kfile:
            profile_command = f"awk -F'/' '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{kfile}\""
            profile_process = subprocess.run(profile_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            profile = profile_process.stdout.strip()

            idle_value_command = f"awk -F 'uint32' '/idle-delay/{{print $2}}' \"{kfile}\" | xargs"
            idle_value_process = subprocess.run(idle_value_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            idle_value = idle_value_process.stdout.strip()

            if idle_value:
                if 0 < int(idle_value) <= max_idle_delay:
                    output_check += f"\n - The \"idle-delay\" option is set to \"{idle_value}\" seconds in \"{kfile}\""
                elif idle_value == "0":
                    output_check += f"\n - The \"idle-delay\" option is set to \"{idle_value}\" (disabled) in \"{kfile}\""
                elif int(idle_value) > max_idle_delay:
                    failure_reason += f"\n - The \"idle-delay\" option is set to \"{idle_value}\" seconds (greater than {max_idle_delay}) in \"{kfile}\""
            else:
                failure_reason += f"\n - The \"idle-delay\" option is not set in \"{kfile}\""

            lock_value_command = f"awk -F 'uint32' '/lock-delay/{{print $2}}' \"{kfile}\" | xargs"
            lock_value_process = subprocess.run(lock_value_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            lock_value = lock_value_process.stdout.strip()

            if lock_value:
                if 0 <= int(lock_value) <= max_lock_delay:
                    output_check += f"\n - The \"lock-delay\" option is set to \"{lock_value}\" seconds in \"{kfile}\""
                elif int(lock_value) > max_lock_delay:
                    failure_reason += f"\n - The \"lock-delay\" option is set to \"{lock_value}\" seconds (greater than {max_lock_delay}) in \"{kfile}\""
            else:
                failure_reason += f"\n - The \"lock-delay\" option is not set in \"{kfile}\""

            if subprocess.run(f"grep -Psq '^\\h*system-db:{profile}' /etc/dconf/profile/*", shell=True).returncode == 0:
                output_check += f"\n - The \"{profile}\" profile exists"
            else:
                failure_reason += f"\n - The \"{profile}\" doesn't exist"

            if subprocess.run(f"test -f /etc/dconf/db/{profile}", shell=True).returncode == 0:
                output_check += f"\n - The \"{profile}\" profile exists in the dconf database"
            else:
                failure_reason += f"\n - The \"{profile}\" profile doesn't exist in the dconf database"
        else:
            failure_reason += "\n - The \"idle-delay\" option doesn't exist, remaining tests skipped"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"

    expected_outputs = [
        output_check.strip(),
        "The profile exists" if "The profile exists" in output_check else "The profile doesn't exist",
        "The profile exists in the dconf database" if "The profile exists in the dconf database" in output_check else "The profile doesn't exist in the dconf database"
    ]
    actual_outputs = [
        output_check.strip(),
        "The profile exists" if "The profile exists" in output_check else "The profile doesn't exist",
        "The profile exists in the dconf database" if "The profile exists in the dconf database" in output_check else "The profile doesn't exist in the dconf database"
    ]

    if not failure_reason:
        task_data.append([task_no, status, "\n".join(expected_outputs), "\n".join(actual_outputs)])
    else:
        status = "False"
        task_data.append([task_no, status, "\n".join(expected_outputs), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.5"
output_check = ""
failure_reason = ""
status = "True"
try:
    check_pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]
    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        idle_delay_dir = "/etc/dconf/db/local.d/00-screensaver"
        lock_delay_dir = "/etc/dconf/db/local.d/00-screensaver"
        
        if os.path.exists(idle_delay_dir):
            output_check += "\n - \"idle-delay\" is locked as it is present in the correct directory"
        else:
            failure_reason += "\n - \"idle-delay\" file is not present, so it cannot be considered locked"
        
        if os.path.exists(lock_delay_dir):
            output_check += "\n - \"lock-delay\" is locked as it is present in the correct directory"
        else:
            failure_reason += "\n - \"lock-delay\" file is not present, so it cannot be considered locked"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    
    expected_outputs = [
        output_check.strip(),
        "The idle-delay option is locked" if "idle-delay is locked" in output_check else "The idle-delay option is not locked",
        "The lock-delay option is locked" if "lock-delay is locked" in output_check else "The lock-delay option is not locked"
    ]
    actual_outputs = [
        output_check.strip(),
        "The idle-delay option is locked" if "idle-delay is locked" in output_check else "The idle-delay option is not locked",
        "The lock-delay option is locked" if "lock-delay is locked" in output_check else "The lock-delay option is not locked"
    ]

    if not failure_reason:
        task_data.append([task_no, status, "\n".join(expected_outputs), "\n".join(actual_outputs)])
    else:
        status = "False"
        task_data.append([task_no, status, "\n".join(expected_outputs), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.6"
output_check = ""
failure_reason = ""
status = "True"

try:
    pkg_output = ""
    pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager = subprocess.check_output(pkg_manager_command, shell=True).decode().strip()
    
    packages = ["gdm", "gdm3"]
    for pkg in packages:
        check_pkg_command = pkg_manager + " -q " + pkg
        pkg_check = subprocess.run(check_pkg_command, shell=True)
        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"
    
    if pkg_output:
        output_check += pkg_output
        dconf_dir = "/etc/dconf/db/"
        automount_file = subprocess.run("grep -Prils -- '^\\h*automount\\b' " + dconf_dir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if automount_file:
            output_check += f"\n - \"automount\" is set in: \"{automount_file}\""
        else:
            failure_reason += "\n - \"automount\" is not set"
        automount_open_file = subprocess.run("grep -Prils -- '^\\h*automount-open\\b' " + dconf_dir, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if automount_open_file:
            output_check += f"\n - \"automount-open\" is set in: \"{automount_open_file}\""
        else:
            failure_reason += "\n - \"automount-open\" is not set"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    
    if not failure_reason:
        task_data.append([task_no, "True", output_check.strip(), ""])
    else:
        status = "False"
        task_data.append([task_no, status, output_check.strip(), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)
except Exception as e:
    task_data.append([task_no, "False", "", "Error: " + str(e)])

task_no = "1.8.7"
output_check = ""
failure_reason = ""
status = "True"

try:
    pkg_output = ""
    pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager = subprocess.check_output(pkg_manager_command, shell=True).decode().strip()
    
    packages = ["gdm", "gdm3"]
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True)
        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"
    
    if pkg_output:
        output_check += pkg_output
        
        # Check for "automount" presence
        automount_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/automount\\b' /etc/dconf/db/*.d", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if automount_file:
            output_check += f"\n - \"automount\" is locked in \"{automount_file}\""
        else:
            failure_reason += "\n - \"automount\" is not set so it cannot be locked"
        
        # Check for "automount-open" presence
        automount_open_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/automount-open\\b' /etc/dconf/db/*.d", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if automount_open_file:
            output_check += f"\n - \"automount-open\" is locked in \"{automount_open_file}\""
        else:
            failure_reason += "\n - \"automount-open\" is not set so it cannot be locked"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    
    if not failure_reason:
        task_data.append([task_no, "True", output_check.strip(), ""])
    else:
        task_data.append([task_no, "False", output_check.strip(), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)
except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.8"
output_check = ""
failure_reason = ""
status = "True"

try:
    pkg_output = ""
    pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager = subprocess.check_output(pkg_manager_command, shell=True).decode().strip()
    
    packages = ["gdm", "gdm3"]
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True)
        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"
    
    if pkg_output:
        output_check += pkg_output
        
        # Check for "autorun-never" presence
        autorun_never_file = subprocess.run("grep -Prils '^\\s*autorun-never\\b' /etc/dconf/db/*.d", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if autorun_never_file:
            output_check += f"\n - \"autorun-never\" is set in \"{autorun_never_file}\""
        else:
            failure_reason += "\n - \"autorun-never\" is not set"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    
    if not failure_reason:
        task_data.append([task_no, "True", output_check.strip(), ""])
    else:
        task_data.append([task_no, "False", output_check.strip(), failure_reason.strip()])
    
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)
except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "1.8.9"
output_check = ""
failure_reason = ""
status = "True"

try:
    pkg_output = ""
    pkg_manager_command = "command -v dpkg-query > /dev/null 2>&1 && echo dpkg-query || command -v rpm > /dev/null 2>&1 && echo rpm"
    pkg_manager = subprocess.check_output(pkg_manager_command, shell=True).decode().strip()
    
    packages = ["gdm", "gdm3"]
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True)
        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"
    
    if pkg_output:
        output_check += pkg_output
        
        # Check for "autorun-never" lock
        autorun_never_lock_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/autorun-never\\b' /etc/dconf/db/*.d", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).stdout.strip()
        if autorun_never_lock_file:
            output_check += f"\n - \"autorun-never\" is locked in \"{autorun_never_lock_file}\""
        else:
            failure_reason += "\n - \"autorun-never\" is not set so it cannot be locked"
    else:
        output_check += "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    
    if not failure_reason:
        task_data.append([task_no, "True", output_check.strip(), ""])
    else:
        task_data.append([task_no, "False", output_check.strip(), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)
except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
task_no = "1.8.10"
output_check = ""
failure_reason = ""
status = "True"

try:
    check_command = "grep -Eis '^\\s*Enable\\s*=\\s*true' /etc/gdm/custom.conf"
    try:
        actual_output = subprocess.check_output(check_command, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        actual_output = e.output.strip()
    
    if actual_output:
        failure_reason = "Enable=true is set in /etc/gdm/custom.conf"
        status = "False"
    else:
        output_check = "The Enable setting in /etc/gdm/custom.conf is not set to true, meeting the requirement"
    
    if status == "True":
        task_data.append([task_no, "True", output_check.strip(), ""])
    else:
        task_data.append([task_no, "False", output_check.strip(), failure_reason.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)
except Exception as e:
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


show_results()

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################