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
    excel_file = "CIS_OL9_Hardening_Report.xlsx"
    module_name = "Basic Config"
    with pd.ExcelWriter(excel_file, engine="openpyxl", mode="a" if os.path.exists(excel_file) else "w") as writer:
        df.to_excel(writer, sheet_name=module_name, index=False)

    print(f"Results written to sheet '{module_name}' in {excel_file}")


def normalize_whitespace(content: str) -> str:
    return ' '.join(content.split())


def check_file_content(file_name: str, expected_content: str, task_no: str) -> None:
    global true_counter, false_counter, true_tasks, false_tasks, task_data

    if os.path.exists(file_name):
        with open(file_name, 'r') as file:
            file_content = file.read()
        
        normalized_file_content = normalize_whitespace(file_content)
        normalized_expected_content = normalize_whitespace(expected_content)
        
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
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.2.1.2"
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

task_no = "1.2.1.3"
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

task_no = "1.3.1.1"
expected_output_prefix = "libselinux-"
try:
    command = "rpm -q libselinux"
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

task_no = "1.3.1.2"
expected_output = ""
try:
    command = "grubby --info=ALL | grep -Po '(selinux|enforcing)=0\\b'"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.3.1.3"
expected_output = "SELINUXTYPE=targeted"
try:
    command = "grep -E '^\s*SELINUXTYPE=(targeted|mls)\\b' /etc/selinux/config"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.3.1.4"
expected_outputs = ["Enforcing", "Permissive"]
try:
    command = "getenforce"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.3.1.5"
expected_output = "Enforcing"
try:
    command = "getenforce"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.4.1"
expected_output = "GRUB2_PASSWORD=grub.pbkdf2.sha512"

try:
    find_command = "find /boot -type f -name 'user.cfg' ! -empty"
    process_find = subprocess.run(find_command, shell=True, capture_output=True, text=True)
    l_grub_password_file = process_find.stdout.strip()

    actual_output = ""

    if os.path.isfile(l_grub_password_file):
        grep_command = f"awk -F. '/^\\s*GRUB2_PASSWORD=\\S+/ {{print $1\".\"$2\".\"$3}}' {l_grub_password_file}"
        process_grep = subprocess.run(grep_command, shell=True, capture_output=True, text=True)
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

task_no = "1.4.2"
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
    process_find = subprocess.run(command, shell=True, capture_output=True, text=True)
    files = process_find.stdout.split('\0')

    l_output = ""
    l_output2 = ""

    for l_gfile in files:
        if not l_gfile.strip():
            continue
        stat_command = f"stat -Lc '%n %#a %U %G' {l_gfile}"
        process_stat = subprocess.run(stat_command, shell=True, capture_output=True, text=True)
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

task_no = "1.5.1"
expected_output = "kernel.randomize_va_space = 2"

try:
    command = "sysctl kernel.randomize_va_space"
    process_sysctl = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process_sysctl.stdout.strip()

    command_check_file = "grep -E '^\\s*kernel.randomize_va_space\\s*=\\s*2\\b' /etc/sysctl.conf /etc/sysctl.d/*"
    process_file_check = subprocess.run(command_check_file, shell=True, capture_output=True, text=True)
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

task_no = "1.5.2"
expected_output = "kernel.yama.ptrace_scope = 1"

try:
    command = "sysctl kernel.yama.ptrace_scope"
    process_sysctl = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process_sysctl.stdout.strip()

    command_check_file = "grep -E '^\\s*kernel.yama.ptrace_scope\\s*=\\s*1\\b' /etc/sysctl.conf /etc/sysctl.d/*"
    process_file_check = subprocess.run(command_check_file, shell=True, capture_output=True, text=True)
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

task_no = "1.5.3"
expected_output = "ProcessSizeMax=0 ProcessSizeMax=0"

try:
    command = "systemd-analyze cat-config /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* | grep -Pio '^\\s*ProcessSizeMax\\s*=\\s*0\\b'"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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
    
task_no = "1.5.4"
expected_output = "Storage=none Storage=none"

try:
    command = "systemd-analyze cat-config /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* | grep -Pio '^\\s*Storage\\s*=\\s*none\\b'"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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


task_no = "1.6.1"
expected_output = ""

try:
    command = "grep -Pi '^\\s*LEGACY\\b' /etc/crypto-policies/config"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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
expected_output = ""

try:
    command = "grep -Pi '^\\s*CRYPTO_POLICY\\s*=' /etc/sysconfig/sshd"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()

    if actual_output == expected_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "", actual_output if actual_output else "Output returned"])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "1.6.3"
expected_sha1_hash = ""
expected_sha1_in_certs = "sha1_in_certs = 0"
combined_status = "True"

try:
    command1 = "awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\\s*\\-\\s*([^#\\n\\r]+)?SHA1/){print}' /etc/crypto-policies/state/CURRENT.pol"
    process1 = subprocess.run(command1, shell=True, capture_output=True, text=True)
    actual_sha1_hash = process1.stdout.strip()

    command2 = "grep -Psi -- '^\\s*sha1_in_certs\\s*=\\s*' /etc/crypto-policies/state/CURRENT.pol"
    process2 = subprocess.run(command2, shell=True, capture_output=True, text=True)
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

task_no = "1.6.4"
expected_output = ""
status = "True"
try:
    command = "grep -Pi -- '^\\h*mac\\h*=\\h*([^#\\n\\r]+)?-64\\b' /etc/crypto-policies/state/CURRENT.pol"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
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

task_no = "1.6.5"
output_check = ""
failure_reason = ""
status = "True"

try:
    cbc_check_command = "grep -Piq -- '^\\h*cipher\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol"
    cbc_for_ssh_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*' /etc/crypto-policies/state/CURRENT.pol"
    no_cbc_for_ssh_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol"

    cbc_output = subprocess.run(cbc_check_command, shell=True, capture_output=True)
    ssh_cipher_output = subprocess.run(cbc_for_ssh_check_command, shell=True, capture_output=True)

    if cbc_output.returncode == 0:
        if ssh_cipher_output.returncode == 0:
            no_cbc_output = subprocess.run(no_cbc_for_ssh_check_command, shell=True, capture_output=True)
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

task_no = "1.6.6"
output_check = ""
failure_reason = ""
status = "True"

try:
    chacha20_check_command = "grep -Piq -- '^\\h*cipher\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol"
    ssh_cipher_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*' /etc/crypto-policies/state/CURRENT.pol"
    no_chacha20_for_ssh_check_command = "grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*([^#\\n\\r]+)?\\bchacha20-poly1305\\b' /etc/crypto-policies/state/CURRENT.pol"

    chacha20_output = subprocess.run(chacha20_check_command, shell=True, capture_output=True)
    ssh_cipher_output = subprocess.run(ssh_cipher_check_command, shell=True, capture_output=True)

    if chacha20_output.returncode == 0:
        if ssh_cipher_output.returncode == 0:
            no_chacha20_output = subprocess.run(no_chacha20_for_ssh_check_command, shell=True, capture_output=True)
            if no_chacha20_output.returncode == 0:
                failure_reason = "chacha20-poly1305 is enabled for SSH"
                status = "False"
            else:
                output_check = "chacha20-poly1305 is disabled for SSH"
        else:
            failure_reason = "chacha20-poly1305 is enabled for SSH"
            status = "False"
    else:
        output_check = "chacha20-poly1305 is disabled"

    if not failure_reason:
        result_output = f"{output_check}"
    else:
        result_output = f"{failure_reason}"

    task_data.append([task_no, status, "chacha20-poly1305 is disabled for SSH", result_output.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "chacha20-poly1305 is disabled for SSH", f"Error: {str(e)}"])

task_no = "1.6.7"
output_check = ""
failure_reason = ""
status = "True"

try:
    etm_check_command = "grep -Psi -- '^\\h*etm\\b' /etc/crypto-policies/state/CURRENT.pol"
    etm_output = subprocess.run(etm_check_command, shell=True, capture_output=True, text=True)

    if etm_output.returncode == 0:
        etm_lines = etm_output.stdout.strip().splitlines()
        expected_values = ["etm@libssh = DISABLE_ETM", "etm@openssh-client = DISABLE_ETM", "etm@openssh-server = DISABLE_ETM"]
        if all(any(expected in line for line in etm_lines) for expected in expected_values):
            output_check = "EtM is disabled for SSH."
        else:
            failure_reason = "EtM is not disabled correctly for SSH."
            status = "False"
    else:
        failure_reason = "EtM configuration line not found."
        status = "False"

    if not failure_reason:
        result_output = f"{output_check}"
    else:
        result_output = f"{failure_reason}"

    task_data.append([task_no, status, "EtM is disabled for SSH", result_output.strip()])
    if status == "False":
        false_counter += 1
        false_tasks.append(task_no)
    else:
        true_counter += 1
        true_tasks.append(task_no)

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "EtM is disabled for SSH", f"Error: {str(e)}"])
    
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

    motd_output = subprocess.run(motd_check_command, shell=True, capture_output=True, text=True)

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

    issue_output = subprocess.run(issue_check_command, shell=True, capture_output=True)

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

    issue_net_output = subprocess.run(issue_net_check_command, shell=True, capture_output=True)

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
    process = subprocess.run(command, shell=True, capture_output=True, text=True)

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
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, capture_output=True, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]

    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, capture_output=True, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        check_gdmfile_command = "grep -Prils '^\\h*banner-message-enable\\b' /etc/dconf/db/*.d"
        gdmfile_process = subprocess.run(check_gdmfile_command, shell=True, capture_output=True, text=True)
        gdmfile = gdmfile_process.stdout.strip()

        if gdmfile:
            gdmprofile_command = f"awk -F/ '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{gdmfile}\""
            gdmprofile_process = subprocess.run(gdmprofile_command, shell=True, capture_output=True, text=True)
            gdmprofile = gdmprofile_process.stdout.strip()

            check_banner_enable_command = f"grep -Pisq '^\\h*banner-message-enable=true\\b' {gdmfile}"
            banner_enable_process = subprocess.run(check_banner_enable_command, shell=True, capture_output=True, text=True)

            if banner_enable_process.returncode == 0:
                output_check += f"\n - The \"banner-message-enable\" option is enabled in \"{gdmfile}\""
            else:
                failure_reason += f"\n - The \"banner-message-enable\" option is not enabled"

            check_banner_text_command = f"grep -Pios '^\\h*banner-message-text=.*$' {gdmfile}"
            banner_text_process = subprocess.run(check_banner_text_command, shell=True, capture_output=True, text=True)
            banner_text = banner_text_process.stdout.strip()

            if banner_text:
                output_check += f"\n - The \"banner-message-text\" option is set in \"{gdmfile}\"\n - banner-message-text is set to:\n - \"{banner_text}\""
            else:
                failure_reason += f"\n - The \"banner-message-text\" option is not set"

            check_profile_command = f"grep -Pq '^\\h*system-db:{gdmprofile}' /etc/dconf/profile/{gdmprofile}"
            profile_process = subprocess.run(check_profile_command, shell=True, capture_output=True, text=True)

            if profile_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" profile doesn't exist"

            check_db_command = f"test -f /etc/dconf/db/{gdmprofile}"
            db_process = subprocess.run(check_db_command, shell=True, capture_output=True)

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
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, capture_output=True, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]

    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, capture_output=True, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        check_gdmfile_command = "grep -Pril '^\\h*disable-user-list\\h*=\\h*true\\b' /etc/dconf/db"
        gdmfile_process = subprocess.run(check_gdmfile_command, shell=True, capture_output=True, text=True)
        gdmfile = gdmfile_process.stdout.strip()

        if gdmfile:
            output_check += f"\n - The \"disable-user-list\" option is enabled in \"{gdmfile}\""
            gdmprofile_command = f"awk -F/ '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{gdmfile}\""
            gdmprofile_process = subprocess.run(gdmprofile_command, shell=True, capture_output=True, text=True)
            gdmprofile = gdmprofile_process.stdout.strip()

            check_profile_command = f"grep -Pq '^\\h*system-db:{gdmprofile}' /etc/dconf/profile/{gdmprofile}"
            profile_process = subprocess.run(check_profile_command, shell=True, capture_output=True, text=True)

            if profile_process.returncode == 0:
                output_check += f"\n - The \"{gdmprofile}\" profile exists"
            else:
                failure_reason += f"\n - The \"{gdmprofile}\" doesn't exist"

            check_db_command = f"test -f /etc/dconf/db/{gdmprofile}"
            db_process = subprocess.run(check_db_command, shell=True, capture_output=True)

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
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, capture_output=True, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]
    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, capture_output=True, text=True)

        if pkg_check.returncode == 0:
            pkg_output += f"\n - Package: \"{pkg}\" exists on the system\n - checking configuration"

    if pkg_output:
        output_check = ""
        failure_reason = ""
        max_idle_delay = 900
        max_lock_delay = 5
        
        kfile_command = "grep -Psril '^\\h*idle-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/"
        kfile_process = subprocess.run(kfile_command, shell=True, capture_output=True, text=True)
        kfile = kfile_process.stdout.strip()

        if kfile:
            profile_command = f"awk -F'/' '{{split($(NF-1),a,\".\");print a[1]}}' <<< \"{kfile}\""
            profile_process = subprocess.run(profile_command, shell=True, capture_output=True, text=True)
            profile = profile_process.stdout.strip()

            idle_value_command = f"awk -F 'uint32' '/idle-delay/{{print $2}}' \"{kfile}\" | xargs"
            idle_value_process = subprocess.run(idle_value_command, shell=True, capture_output=True, text=True)
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
            lock_value_process = subprocess.run(lock_value_command, shell=True, capture_output=True, text=True)
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
    pkg_manager_process = subprocess.run(check_pkg_manager_command, shell=True, capture_output=True, text=True)
    pkg_manager = pkg_manager_process.stdout.strip()

    packages = ["gdm", "gdm3"]
    pkg_output = ""
    for pkg in packages:
        check_pkg_command = f"{pkg_manager} -q {pkg}"
        pkg_check = subprocess.run(check_pkg_command, shell=True, capture_output=True, text=True)

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
        automount_file = subprocess.run("grep -Prils -- '^\\h*automount\\b' " + dconf_dir, shell=True, capture_output=True, text=True).stdout.strip()
        if automount_file:
            output_check += f"\n - \"automount\" is set in: \"{automount_file}\""
        else:
            failure_reason += "\n - \"automount\" is not set"
        automount_open_file = subprocess.run("grep -Prils -- '^\\h*automount-open\\b' " + dconf_dir, shell=True, capture_output=True, text=True).stdout.strip()
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
        automount_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/automount\\b' /etc/dconf/db/*.d", shell=True, capture_output=True, text=True).stdout.strip()
        if automount_file:
            output_check += f"\n - \"automount\" is locked in \"{automount_file}\""
        else:
            failure_reason += "\n - \"automount\" is not set so it cannot be locked"
        
        # Check for "automount-open" presence
        automount_open_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/automount-open\\b' /etc/dconf/db/*.d", shell=True, capture_output=True, text=True).stdout.strip()
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
        autorun_never_file = subprocess.run("grep -Prils '^\\s*autorun-never\\b' /etc/dconf/db/*.d", shell=True, capture_output=True, text=True).stdout.strip()
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
        autorun_never_lock_file = subprocess.run("grep -Prils '^\\s*/org/gnome/desktop/media-handling/autorun-never\\b' /etc/dconf/db/*.d", shell=True, capture_output=True, text=True).stdout.strip()
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

task_no = "2.1.1"
expected_output = "package autofs is not installed"
try:
    command = "rpm -q autofs"
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

task_no = "2.1.2"
expected_output = "package avahi is not installed"
try:
    command = "rpm -q avahi"
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

task_no = "2.1.3"
expected_output = "package dhcp-server is not installed"
try:
    command = "rpm -q dhcp-server"
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

task_no = "2.1.4"
expected_output = "package bind is not installed"
try:
    command = "rpm -q bind"
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

task_no = "2.1.5"
expected_output = "package dnsmasq is not installed"
try:
    command = "rpm -q dnsmasq"
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

task_no = "2.1.6"
expected_output = "package samba is not installed"
try:
    command = "rpm -q samba"
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

task_no = "2.1.7"
expected_output = "package vsftpd is not installed"
try:
    command = "rpm -q vsftpd"
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
    
task_no = "2.1.8"
expected_output1 = "package dovecot is not installed"
expected_output2 = "package cyrus-imapd is not installed"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    command = "rpm -q dovecot"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output1 = process.stdout.strip() if process.stdout else "error"
    
    command = "rpm -q cyrus-imapd"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output2 = process.stdout.strip() if process.stdout else "error"
    
    actual_output = f"{actual_output1}\n{actual_output2}"
    
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

task_no = "2.1.9"
expected_output = "package nfs-utils is not installed"
try:
    command = "rpm -q nfs-utils"
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

task_no = "2.1.10"
expected_output = "package ypserv is not installed"
try:
    command = "rpm -q ypserv"
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

task_no = "2.1.11"
expected_output = "package cups is not installed"
try:
    command = "rpm -q cups"
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

task_no = "2.1.12"
expected_output = "package rpcbind is not installed"
try:
    command = "rpm -q rpcbind"
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

task_no = "2.1.13"
expected_output = "package rsync-daemon is not installed"
try:
    command = "rpm -q rsync-daemon"
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

task_no = "2.1.14"
expected_output = "package net-snmp is not installed"
try:
    command = "rpm -q net-snmp"
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

task_no = "2.1.15"
expected_output = "package telnet-server is not installed"
try:
    command = "rpm -q telnet-server"
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
    
task_no = "2.1.16"
expected_output = "package tftp-server is not installed"
try:
    command = "rpm -q tftp-server"
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

task_no = "2.1.17"
expected_output = "package squid is not installed"
try:
    command = "rpm -q squid"
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
    
task_no = "2.1.18"
expected_output1 = "package httpd is not installed"
expected_output2 = "package nginx is not installed"
expected_output = f"{expected_output1}\n{expected_output2}"
try:
    command = "rpm -q httpd"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output1 = process.stdout.strip() if process.stdout else "error"
    
    command = "rpm -q nginx"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output2 = process.stdout.strip() if process.stdout else "error"
    
    actual_output = f"{actual_output1}\n{actual_output2}"
    
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

task_no = "2.1.19"
expected_output = "package xinetd is not installed"
try:
    command = "rpm -q xinetd"
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

task_no = "2.1.20"
expected_output = "package xorg-x11-server-common is not installed"
try:
    command = "rpm -q xorg-x11-server-common"
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

task_no = "2.1.21"
port_list = ["25", "465", "587"]
output = ""
output_failure = ""
actual_output = ""
try:
    command = "postconf -n inet_interfaces"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    inet_interfaces = process.stdout.strip()
    actual_output += f"{inet_interfaces}"

    if inet_interfaces != "inet_interfaces = all":
        for port in port_list:
            command = f"ss -plntu | grep -P -- ':{port}\\b' | grep -Pvq -- '\\h+(127\\.0\\.0\\.1|\\[?::1\\]?):{port}\\b'"
            process = subprocess.run(command, shell=True)
            port_check_output = subprocess.run(f"ss -plntu | grep -P -- ':{port}\\b'", shell=True, capture_output=True, text=True)
            actual_output += f"\nPort {port} check:\n{port_check_output.stdout.strip()}"

            if process.returncode == 0:
                output_failure += f"\nPort \"{port}\" is listening on a non-loopback network interface"
            else:
                output += f"\nPort \"{port}\" is not listening on a non-loopback network interface"
    else:
        output_failure += "\nPostfix is bound to all interfaces"

    if not output_failure:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", output.strip(), actual_output.strip()])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", output.strip(), f"{output_failure.strip()}\n{actual_output.strip()}"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

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

task_no = "6.3.1.1"
expected_output_prefix1 = "audit-"
expected_output_prefix2 = "audit-libs-"

try:
    command1 = "rpm -q audit"
    process1 = subprocess.run(command1, shell=True, capture_output=True, text=True)
    actual_output1 = process1.stdout.strip() if process1.stdout else "Package not installed"
    command2 = "rpm -q audit-libs"
    process2 = subprocess.run(command2, shell=True, capture_output=True, text=True)
    actual_output2 = process2.stdout.strip() if process2.stdout else "Package not installed"
    actual_output = f"{actual_output1}\n{actual_output2}"
    if actual_output1.startswith(expected_output_prefix1) and actual_output2.startswith(expected_output_prefix2):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_prefix1}x\n{expected_output_prefix2}x", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"{expected_output_prefix1}x\n{expected_output_prefix2}x", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_prefix1}x\n{expected_output_prefix2}x", f"Error: {str(e)}"])


task_no = "6.3.1.2"
expected_output_audit = "audit=1"
expected_output_grub = 'GRUB_CMDLINE_LINUX="'
try:
    command_audit = "grubby --info=ALL | grep -Po '\\baudit=1\\b'"
    process_audit = subprocess.run(command_audit, shell=True, capture_output=True, text=True)
    audit_output = process_audit.stdout.strip()
    command_grub = "grep -Psoi -- '^\\h*GRUB_CMDLINE_LINUX=\"([^#\\n\\r]+\\h+)?audit=1\\b' /etc/default/grub"
    process_grub = subprocess.run(command_grub, shell=True, capture_output=True, text=True)
    grub_output = process_grub.stdout.strip()
    if audit_output and grub_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_audit} and {expected_output_grub}", 
                          f"{audit_output}\n{grub_output}"])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"{expected_output_audit} and {expected_output_grub}", 
                          f"Audit Output: {audit_output}\nGrub Output: {grub_output}"])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_audit} and {expected_output_grub}", 
                      f"Error: {str(e)}"])

task_no = "6.3.1.3"
expected_output_backlog = "audit_backlog_limit="
minimum_backlog_size = 8192
actual_output = ""
backlog_valid = False
try:
    command_backlog = "grubby --info=ALL | grep -Po '\\baudit_backlog_limit=\\d+\\b'"
    process_backlog = subprocess.run(command_backlog, shell=True, capture_output=True, text=True)
    backlog_output = process_backlog.stdout.strip()
    if backlog_output:
        backlog_value_match = re.search(r'(\d+)', backlog_output)
        if backlog_value_match:
            backlog_value = int(backlog_value_match.group(1))
            backlog_valid = backlog_value >= minimum_backlog_size
    command_grub = "grep -Psoi -- '^\\h*GRUB_CMDLINE_LINUX=\"([^#\\n\\r]+\\h+)?\\baudit_backlog_limit=\\d+\\b' /etc/default/grub"
    process_grub = subprocess.run(command_grub, shell=True, capture_output=True, text=True)
    grub_output = process_grub.stdout.strip()
    if backlog_valid and grub_output:
        actual_output = f"{backlog_output}\n{grub_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_backlog} >= {minimum_backlog_size}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Backlog Output: {backlog_output}\nGrub Output: {grub_output}"
        task_data.append([task_no, "False", f"{expected_output_backlog} >= {minimum_backlog_size}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_backlog} >= {minimum_backlog_size}", f"Error: {str(e)}"])

task_no = "6.3.1.4"
expected_output_enabled = "enabled"
expected_output_active = "active"
actual_output = ""
try:
    command_enabled = "systemctl is-enabled auditd | grep '^enabled'"
    process_enabled = subprocess.run(command_enabled, shell=True, capture_output=True, text=True)
    enabled_output = process_enabled.stdout.strip()
    command_active = "systemctl is-active auditd | grep '^active'"
    process_active = subprocess.run(command_active, shell=True, capture_output=True, text=True)
    active_output = process_active.stdout.strip()
    if enabled_output == expected_output_enabled and active_output == expected_output_active:
        actual_output = f"{enabled_output}\n{active_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_enabled, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Enabled Output: {enabled_output}\nActive Output: {active_output}"
        task_data.append([task_no, "False", expected_output_enabled, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_enabled, f"Error: {str(e)}"])

task_no = "6.3.2.1"
expected_output = "max_log_file > 7"
actual_output = ""
compliance_status = False

try:
    command = "grep 'max_log_file =' /etc/audit/auditd.conf"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()

    if actual_output:
        file_value = int(actual_output.split('=')[1].strip().split()[0])
        if file_value > 7:
            compliance_status = True
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, f"max_log_file = {file_value}"])
        else:
            compliance_status = False
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, f"max_log_file = {file_value}"])
    else:
        actual_output = "Not found in file"
        compliance_status = False
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    compliance_status = False
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])


task_no = "6.3.2.2"
expected_output_action = "max_log_file_action = keep_logs"
exp = "keep_logs"
actual_output = ""

try:
    command_action = "grep max_log_file_action /etc/audit/auditd.conf"
    process_action = subprocess.run(command_action, shell=True, capture_output=True, text=True)
    actual_output = process_action.stdout.strip()
    if exp in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_action, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_action, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_action, f"Error: {str(e)}"])

task_no = "6.3.2.3"
expected_output_full = "disk_full_action = <halt|single>"
expected_output_error = "disk_error_action = <syslog|single|halt>"
exp_full = ['halt', 'single']
exp_error = ['syslog', 'single', 'halt']
actual_output = ""

try:
    command_full = "grep 'disk_full_action =' /etc/audit/auditd.conf"
    process_full = subprocess.run(command_full, shell=True, capture_output=True, text=True)
    full_action_output = process_full.stdout.strip()
    command_error = "grep 'disk_error_action =' /etc/audit/auditd.conf"
    process_error = subprocess.run(command_error, shell=True, capture_output=True, text=True)
    error_action_output = process_error.stdout.strip()
    full_action_valid = any(x in full_action_output for x in exp_full)
    error_action_valid = any(x in error_action_output for x in exp_error)
    if full_action_valid and error_action_valid:
        actual_output = f"{full_action_output}\n{error_action_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_full} and {expected_output_error}", actual_output])
    else:
        actual_output = f"Disk Full Action Output: {full_action_output or 'Not set correctly'}\nDisk Error Action Output: {error_action_output or 'Not set correctly'}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"{expected_output_full} and {expected_output_error}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_full} and {expected_output_error}", f"Error: {str(e)}"])

task_no = "6.3.2.4"
expected_output_space_left = "space_left_action = <email|exec|single|halt>"
expected_output_admin_space_left = "admin_space_left_action = <single|halt>"
exp_space_left = ['email', 'exec', 'single', 'halt']
exp_admin_space_left = ['single', 'halt']
actual_output = ""

try:
    command_space_left = "grep 'space_left_action =' /etc/audit/auditd.conf"
    process_space_left = subprocess.run(command_space_left, shell=True, capture_output=True, text=True)
    space_left_output = process_space_left.stdout.strip()
    command_admin_space_left = "grep 'admin_space_left_action =' /etc/audit/auditd.conf"
    process_admin_space_left = subprocess.run(command_admin_space_left, shell=True, capture_output=True, text=True)
    admin_space_left_output = process_admin_space_left.stdout.strip()
    space_left_valid = any(x in space_left_output for x in exp_space_left)
    admin_space_left_valid = any(x in admin_space_left_output for x in exp_admin_space_left)
    if space_left_valid and admin_space_left_valid:
        actual_output = f"{space_left_output}\n{admin_space_left_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"{expected_output_space_left} and {expected_output_admin_space_left}", actual_output])
    else:
        actual_output = f"Space Left Action Output: {space_left_output or 'Not set correctly'}\nAdmin Space Left Action Output: {admin_space_left_output or 'Not set correctly'}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"{expected_output_space_left} and {expected_output_admin_space_left}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"{expected_output_space_left} and {expected_output_admin_space_left}", f"Error: {str(e)}"])

task_no = "6.3.3.1"
expected_output = "-w /etc/sudoers -p wa -k scope\n-w /etc/sudoers.d -p wa -k scope"
actual_output = ""
try:
    command_disk = "awk '/^ *-w/ && /\\/etc\\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = "auditctl -l | awk '/^ *-w/ && /\\/etc\\/sudoers/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output.split('\n')):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.2"
expected_output = (
    "-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation\n"
    "-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation"
)
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && "
        "(/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && "
        "(/ -C *euid!=uid/ || / -C *uid!=euid/) && / -S *execve/ && "
        "(/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && "
        "(/ -F *auid!=unset/ || / -F *auid!=-1/ || / -F *auid!=4294967295/) && "
        "(/ -C *euid!=uid/ || / -C *uid!=euid/) && / -S *execve/ && "
        "(/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output.split('\n')):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

import subprocess

task_no = "6.3.3.3"
expected_output = "-w /var/log/sudo.log -p wa -k sudo_log_file"
actual_output = ""
try:
    command = (
        "SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' "
        "-e 's/\"//g' -e 's|/|\\\\/|g'); "
        "[ -n \"${SUDO_LOG_FILE}\" ] && awk \"/^ *-w/ && /${SUDO_LOG_FILE}/ && / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable SUDO_LOG_FILE is unset.\n'"
    )
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {actual_output}"
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.4"
expected_output = (
    "-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change\n"
    "-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change\n"
    "-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change\n"
    "-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change\n"
    "-w /etc/localtime -p wa -k time-change"
)
actual_output = ""

try:
    # Command to check disk audit rules
    command_disk = (
        "awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && "
        "(/adjtimex/ || /settimeofday/ || /clock_settime/) && "
        "(/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules; "
        "awk '/^ *-w/ && /\\/etc\\/localtime/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' "
        "/etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    
    # Command to check running audit rules
    command_running = (
        "auditctl -l | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ && "
        "(/adjtimex/ || /settimeofday/ || /clock_settime/) && "
        "(/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'; "
        "auditctl -l | awk '/^ *-w/ && /\\/etc\\/localtime/ && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    
    actual_output = f"{disk_output}\n{running_output}"
    
    # Validate if all expected lines are present in the actual output
    if all(line in actual_output for line in expected_output.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.5"
expected_output = (
    "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale\n"
    "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale\n"
)
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-a *always,exit/ && /-F *arch=b(32|64)/ && /-S/ && "
        "(/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' "
        "/etc/audit/rules.d/*.rules; "
        "awk '/^ *-w/ && (/etc/issue/ || /etc/issue.net/ || /etc/hosts/ || /etc/sysconfig/network/ "
        "|| /etc/hostname/ || /etc/sysconfig/network-scripts/ || /etc/NetworkManager/) && / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ "
        "&& (/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'; "
        "auditctl -l | awk '/^ *-w/ && (/etc/issue/ || /etc/issue.net/ || /etc/hosts/ || "
        "/etc/sysconfig/network/ || /etc/hostname/ || /etc/sysconfig/network-scripts/ || "
        "/etc/NetworkManager/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.6"
expected_output = "OK: ' found in auditing rules."
actual_output = ""
try:
    command_disk = """
    #!/usr/bin/env bash
    {
        for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
            for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
                grep -qr "${PRIVILEGED}" /etc/audit/rules.d && printf "OK: '${PRIVILEGED}' found in auditing rules.\\n" || printf "Warning: '${PRIVILEGED}' not found in on disk configuration.\\n"
            done
        done
    }
    """
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = """
    #!/usr/bin/env bash
    {
        RUNNING=$(auditctl -l)
        [ -n "${RUNNING}" ] && for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
            for PRIVILEGED in $(find "${PARTITION}" -xdev -perm /6000 -type f); do
                printf -- "${RUNNING}" | grep -q "${PRIVILEGED}" && printf "OK: '${PRIVILEGED}' found in auditing rules.\\n" || printf "Warning: '${PRIVILEGED}' not found in running configuration.\\n"
            done
        done || printf "ERROR: Variable 'RUNNING' is unset.\\n"
    }
    """
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all("OK:" in line for line in actual_output.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Output:\n{actual_output}"
        task_data.append([task_no, "False", "", actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "6.3.3.7"
expected_output = "OK"
actual_output = ""
try:
    command_disk = """
    #!/usr/bin/env bash
    {
        UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
        [ -n "${UID_MIN}" ] && awk "/^ *-a *always,exit/ \
        &&/ -F *arch=b(32|64)/ \
        &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
        &&/ -F *auid>=${UID_MIN}/ \
        &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \
        &&/ -S/ \
        &&/creat/ \
        &&/open/ \
        &&/truncate/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" /etc/audit/rules.d/*.rules \
        || printf "ERROR: Variable 'UID_MIN' is unset.\\n"
    }
    """
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = """
    #!/usr/bin/env bash
    {
        UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
        [ -n "${UID_MIN}" ] && auditctl -l | awk "/^ *-a *always,exit/ \
        &&/ -F *arch=b(32|64)/ \
        &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \
        &&/ -F *auid>=${UID_MIN}/ \
        &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \
        &&/ -S/ \
        &&/creat/ \
        &&/open/ \
        &&/truncate/ \
        &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)" \
        || printf "ERROR: Variable 'UID_MIN' is unset.\\n"
    }
    """
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    expected_rules = [
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access",
        "-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access"
    ]
    if all(rule in actual_output for rule in expected_rules):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Output:\n{actual_output}"
        task_data.append([task_no, "False", "", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.3.3.8"
expected_lines = [
    "-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale",
    "-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale"
]
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-a *always,exit/ && /-F *arch=b(32|64)/ && /-S/ && "
        "(/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' "
        "/etc/audit/rules.d/*.rules; "
        "awk '/^ *-w/ && (/etc/issue/ || /etc/issue.net/ || /etc/hosts/ || /etc/sysconfig/network/ "
        "|| /etc/hostname/ || /etc/sysconfig/network-scripts/ || /etc/NetworkManager/) && / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-a *always,exit/ && / -F *arch=b(32|64)/ && / -S/ "
        "&& (/sethostname/ || /setdomainname/) && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'; "
        "auditctl -l | awk '/^ *-w/ && (/etc/issue/ || /etc/issue.net/ || /etc/hosts/ || "
        "/etc/sysconfig/network/ || /etc/hostname/ || /etc/sysconfig/network-scripts/ || "
        "/etc/NetworkManager/) && / +-p *wa/ && (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_lines):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "\n".join(expected_lines), actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output or 'No output'}\nRunning Output: {running_output or 'No output'}"
        task_data.append([task_no, "False", "\n".join(expected_lines), actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "\n".join(expected_lines), f"Error: {str(e)}"])

task_no = "6.3.3.9"
expected_output = (
    "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod\n"
    "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod\n"
)
try:
    with open("/etc/audit/rules.d/50-perm_mod.rules") as f:
        rules_content = f.read()
    def normalize_content(content):
        lines = content.strip().splitlines()
        normalized_lines = [re.sub(r'\s+', ' ', line).strip() for line in lines]
        return set(normalized_lines)

    expected_lines = normalize_content(expected_output)
    actual_lines = normalize_content(rules_content)

    if expected_lines.issubset(actual_lines):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, rules_content])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, rules_content])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.10"
expected_output = (
    "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts\n"
    "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts"
)
try:
    with open("/etc/audit/rules.d/50-mounts.rules") as f:
        rules_content = f.read()
    expected_lines = normalize_content(expected_output)
    actual_lines = normalize_content(rules_content)
    if expected_lines.issubset(actual_lines):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, rules_content])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, rules_content])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.11"
expected_output = (
    "-w /var/run/utmp -p wa -k session\n"
    "-w /var/log/wtmp -p wa -k session\n"
    "-w /var/log/btmp -p wa -k session"
)
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-w/ "
        "&& (/\\/var\\/run\\/utmp/ || /\\/var\\/log\\/wtmp/ || /\\/var\\/log\\/btmp/) "
        "&& / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-w/ "
        "&& (/\\/var\\/run\\/utmp/ || /\\/var\\/log\\/wtmp/ || /\\/var\\/log\\/btmp/) "
        "&& / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.12"
expected_output = (
    "-w /var/log/lastlog -p wa -k logins\n"
    "-w /var/run/faillock -p wa -k logins"
)
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-w/ "
        "&& (/\\/var\\/log\\/lastlog/ || /\\/var\\/run\\/faillock/) "
        "&& / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-w/ "
        "&& (/\\/var\\/log\\/lastlog/ || /\\/var\\/run\\/faillock/) "
        "&& / +-p *wa/ "
        "&& (/ key= *[!-~]* *$/ || / -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.13"
expected_output = (
    "-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete\n"
    "-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=unset -F key=delete"
)
try:
    with open("/etc/audit/rules.d/50-delete.rules") as f:
        rules_content = f.read()

    expected_lines = normalize_content(expected_output)
    actual_lines = normalize_content(rules_content)

    if expected_lines.issubset(actual_lines):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, rules_content])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, rules_content])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.14"
expected_output_on_disk = (
    "-w /etc/selinux -p wa -k MAC-policy\n"
    "-w /usr/share/selinux -p wa -k MAC-policy"
)
expected_output_running = (
    "-w /etc/selinux -p wa -k MAC-policy\n"
    "-w /usr/share/selinux -p wa -k MAC-policy"
)
actual_output = ""
try:
    command_disk = (
        "awk '/^ *-w/ "
        "&&(/\\/etc\\/selinux/ "
        "||/\\/usr\\/share\\/selinux/) "
        "&&/ +-p *wa/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-w/ "
        "&&(/\\/etc\\/selinux/ "
        "||/\\/usr\\/share\\/selinux/) "
        "&&/ +-p *wa/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if all(line in actual_output for line in expected_output_on_disk.splitlines()) and \
       all(line in actual_output for line in expected_output_running.splitlines()):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output_on_disk, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk, f"Error: {str(e)}"])

task_no = "6.3.3.15"
expected_output_on_disk = (
    "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
)
expected_output_running = (
    "-a always,exit -S all -F p"
)
actual_output = ""
try:
    command_disk = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/chcon/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/chcon/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if (expected_output_on_disk in actual_output) and (expected_output_running in actual_output):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output_on_disk, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk, f"Error: {str(e)}"])

task_no = "6.3.3.16"
expected_output_on_disk = (
    "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
)
expected_output_running = (
    "-a always,exit -S all -F pa"
)
actual_output = ""
try:
    command_disk = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/setfacl/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/setfacl/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if (expected_output_on_disk in actual_output) and (expected_output_running in actual_output):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output_on_disk, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk, f"Error: {str(e)}"])

task_no = "6.3.3.17"
expected_output_on_disk = (
    "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng"
)
expected_output_running = (
    "-a always,exit -S all -F pat"
)
actual_output = ""
try:
    command_disk = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/chacl/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/chacl/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if (expected_output_on_disk in actual_output) and (expected_output_running in actual_output):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output_on_disk, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk, f"Error: {str(e)}"])

task_no = "6.3.3.18"
expected_output_on_disk = (
    "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k usermod"
)
expected_output_running = (
    "-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1 -F key=usermod"
)
actual_output = ""
try:
    command_disk = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/sbin\\/usermod/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/sbin\\/usermod/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}"
    if (expected_output_on_disk in actual_output) and (expected_output_running in actual_output):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}"
        task_data.append([task_no, "False", expected_output_on_disk, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk, f"Error: {str(e)}"])

task_no = "6.3.3.19"
expected_output_on_disk_1 = (
    "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules"
)
expected_output_on_disk_2 = (
    "-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules"
)
expected_output_running_1 = (
    "-a always,exit -F arch=b64 -S create_module,init_module,delete_module,query_module,finit_module -F auid>=1000 -F auid!=-1 -F key=kernel_modules"
)
expected_output_running_2 = (
    "-a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules"
)
actual_output = ""
symlink_output = ""
try:
    command_disk = (
        "awk '/^ *-a *always,exit/ "
        "&&/ -F *arch=b(32|64)/ "
        "&&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) "
        "&&/ -S/ "
        "&&(/init_module/ "
        "||/finit_module/ "
        "||/delete_module/ "
        "||/create_module/ "
        "||/query_module/) "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules; "
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/kmod/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_disk = subprocess.run(command_disk, shell=True, capture_output=True, text=True)
    disk_output = process_disk.stdout.strip()
    command_running = (
        "auditctl -l | awk '/^ *-a *always,exit/ "
        "&&/ -F *arch=b(32|64)/ "
        "&&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) "
        "&&/ -S/ "
        "&&(/init_module/ "
        "||/finit_module/ "
        "||/delete_module/ "
        "||/create_module/ "
        "||/query_module/) "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'; "
        "UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs); "
        "[ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ "
        "&&(/ -F *auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) "
        "&&/ -F *auid>=${UID_MIN}/ "
        "&&/ -F *perm=x/ "
        "&&/ -F *path=\\/usr\\/bin\\/kmod/ "
        "&&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" "
        "|| printf 'ERROR: Variable \"UID_MIN\" is unset.\\n'"
    )
    process_running = subprocess.run(command_running, shell=True, capture_output=True, text=True)
    running_output = process_running.stdout.strip()
    symlink_command = (
        "a_files=(/usr/sbin/lsmod /usr/sbin/rmmod /usr/sbin/insmod /usr/sbin/modinfo /usr/sbin/modprobe /usr/sbin/depmod); "
        "for l_file in \"${a_files[@]}\"; do "
        "if [ \"$(readlink -f \"$l_file\")\" = \"$(readlink -f /bin/kmod)\" ]; then "
        "printf \"OK: \\\"$l_file\\\"\\n\"; "
        "else printf \"Issue with symlink for file: \\\"$l_file\\\"\\n\"; "
        "fi; done"
    )
    process_symlink = subprocess.run(symlink_command, shell=True, capture_output=True, text=True)
    symlink_output = process_symlink.stdout.strip()
    actual_output = f"{disk_output}\n{running_output}\n{symlink_output}"
    if (expected_output_on_disk_1 in actual_output) and (expected_output_on_disk_2 in actual_output) and \
       (expected_output_running_1 in actual_output) and (expected_output_running_2 in actual_output):
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_on_disk_1, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        actual_output = f"Disk Output: {disk_output}\nRunning Output: {running_output}\nSymlink Output: {symlink_output}"
        task_data.append([task_no, "False", expected_output_on_disk_1, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_on_disk_1, f"Error: {str(e)}"])

task_no = "6.3.3.20"
expected_output = "-e 2"
try:
    with open("/etc/audit/rules.d//99-finalize.rules") as f:
        rules_content = f.read()
    if "-e 2" in rules_content.splitlines():
        actual_output = "-e 2"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = rules_content.strip()
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])

except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output, f"Error: {str(e)}"])

task_no = "6.3.3.21"
expected_output = "/usr/sbin/augenrules: No change"
actual_output = ""
try:
    command = "augenrules --check"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
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

task_no = "6.3.4.1"
expected_output_pass = "** PASS **"
expected_output_fail = "** FAIL **"
actual_output = ""
try:
    script = """
    #!/usr/bin/env bash
    {
        l_perm_mask="0027"
        if [ -e "/etc/audit/auditd.conf" ]; then
            l_audit_log_directory="$(dirname "$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
            if [ -d "$l_audit_log_directory" ]; then
                l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
                l_directory_mode="$(stat -Lc '%#a' "$l_audit_log_directory")"
                if [ $(( $l_directory_mode & $l_perm_mask )) -gt 0 ]; then
                    echo -e "** FAIL **\\n - Directory: \\"$l_audit_log_directory\\" is mode: \\"$l_directory_mode\\"\\n (should be mode: \\"$l_maxperm\\" or more restrictive)\\n"
                else
                    echo -e "** PASS **\\n - Directory: \\"$l_audit_log_directory\\" is mode: \\"$l_directory_mode\\"\\n (should be mode: \\"$l_maxperm\\" or more restrictive)\\n"
                fi
            else
                echo -e "** FAIL **\\n - Log file directory not set in \\"/etc/audit/auditd.conf\\" please set log file directory"
            fi
        else
            echo -e "** FAIL **\\n - File: \\"/etc/audit/auditd.conf\\" not found\\n - ** Verify auditd is installed **"
        fi
    }
    """
    process = subprocess.run(script, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output_pass in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    elif expected_output_fail in actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.2"
expected_output_pass = "** PASS **"
expected_output_fail = "** FAIL **"
actual_output = ""
try:
    script = """
    #!/usr/bin/env bash
    {
        l_output="" l_output2=""
        l_perm_mask="0177"
        if [ -e "/etc/audit/auditd.conf" ]; then
            l_audit_log_directory="$(dirname "$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
            if [ -d "$l_audit_log_directory" ]; then
                l_maxperm="$(printf '%o' $(( 0777 & ~$l_perm_mask )) )"
                while IFS= read -r -d $'\\0' l_file; do
                    while IFS=: read -r l_file_mode l_hr_file_mode; do
                        l_output2="$l_output2\\n - File: \\"$l_file\\" is mode: \\"$l_file_mode\\"\\n (should be mode: \\"$l_maxperm\\" or more restrictive)\\n"
                    done <<< "$(stat -Lc '%#a:%A' "$l_file")"
                done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -perm /"$l_perm_mask" -print0)
            else
                l_output2="$l_output2\\n - Log file directory not set in \\"/etc/audit/auditd.conf\\" please set log file directory"
            fi
        else
            l_output2="$l_output2\\n - File: \\"/etc/audit/auditd.conf\\" not found.\\n - ** Verify auditd is installed **"
        fi
        if [ -z "$l_output2" ]; then
            l_output="$l_output\\n - All files in \\"$l_audit_log_directory\\" are mode: \\"$l_maxperm\\" or more restrictive"
            echo -e "** PASS **\\n - * Correctly configured * :$l_output"
        else
            echo -e "** FAIL **\\n - * Reasons for audit failure * :$l_output2\\n"
        fi
    }
    """
    process = subprocess.run(script, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output_pass in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    elif expected_output_fail in actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.3"
expected_output_pass = "** PASS **"
expected_output_fail = "** FAIL **"
actual_output = ""

try:
    script = """
    #!/usr/bin/env bash
    {
        l_output="" l_output2=""
        if [ -e "/etc/audit/auditd.conf" ]; then
            l_audit_log_directory="$(dirname "$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
            if [ -d "$l_audit_log_directory" ]; then
                while IFS= read -r -d $'\\0' l_file; do
                    l_file_owner="$(stat -c '%U' "$l_file")"
                    if [ "$l_file_owner" != "root" ]; then
                        l_output2="$l_output2\\n - File: \\"$l_file\\" is owned by: \\"$l_file_owner\\" (should be owned by: \\"root\\")\\n"
                    fi
                done < <(find "$l_audit_log_directory" -maxdepth 1 -type f -print0)
            else
                l_output2="$l_output2\\n - Log file directory not set in \\"/etc/audit/auditd.conf\\" please set log file directory"
            fi
        else
            l_output2="$l_output2\\n - File: \\"/etc/audit/auditd.conf\\" not found.\\n - ** Verify auditd is installed **"
        fi
        if [ -z "$l_output2" ]; then
            l_output="$l_output\\n - All files in \\"$l_audit_log_directory\\" are owned by: \\"root\\""
            echo -e "** PASS **\\n - * Correctly configured * :$l_output"
        else
            echo -e "** FAIL **\\n - * Reasons for audit failure * :$l_output2\\n"
        fi
    }
    """
    process = subprocess.run(script, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output_pass in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    elif expected_output_fail in actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

import subprocess

task_no = "6.3.4.4"
expected_output_pass = "** PASS **"
expected_output_fail = "** FAIL **"
actual_output = ""

try:
    script = """
    #!/usr/bin/env bash
    {
        l_output="" l_output2=""
        if [ -e "/etc/audit/auditd.conf" ]; then
            l_audit_log_directory="$(dirname "$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)")"
            l_audit_log_group="$(awk -F= '/^\\s*log_group\\s*/{print $2}' /etc/audit/auditd.conf | xargs)"
            if grep -Pq -- '^\\h*(root|adm)\\h*$' <<< "$l_audit_log_group"; then
                l_output="$l_output\\n - Log file group correctly set to: \\"$l_audit_log_group\\" in \\"/etc/audit/auditd.conf\\""
            else
                l_output2="$l_output2\\n - Log file group is set to: \\"$l_audit_log_group\\" in \\"/etc/audit/auditd.conf\\"\\n (should be set to group: \\"root or adm\\")\\n"
            fi
            if [ -d "$l_audit_log_directory" ]; then
                while IFS= read -r -d $'\\0' l_file; do
                    l_output2="$l_output2\\n - File: \\"$l_file\\" is group owned by group: \\"$(stat -Lc '%G' "$l_file")\\"\\n (should be group owned by group: \\"root or adm\\")\\n"
                done < <(find "$l_audit_log_directory" -maxdepth 1 -type f \\( ! -group root -a ! -group adm \\) -print0)
            else
                l_output2="$l_output2\\n - Log file directory not set in \\"/etc/audit/auditd.conf\\" please set log file directory"
            fi
        else
            l_output2="$l_output2\\n - File: \\"/etc/audit/auditd.conf\\" not found.\\n - ** Verify auditd is installed **"
        fi
        if [ -z "$l_output2" ]; then
            l_output="$l_output\\n - All files in \\"$l_audit_log_directory\\" are group owned by group: \\"root or adm\\"\\n"
            echo -e "** PASS **\\n - * Correctly configured * :$l_output"
        else
            echo -e "** FAIL **\\n - * Reasons for audit failure * :$l_output2\\n"
            [ -n "$l_output" ] && echo -e " - * Correctly configured * :\\n$l_output\\n"
        fi
    }
    """
    process = subprocess.run(script, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output_pass in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    elif expected_output_fail in actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.5"
expected_output_pass = "** PASS **"
expected_output_fail = "** FAIL **"
actual_output = ""

try:
    script = """
    #!/usr/bin/env bash
    {
        l_output="" l_output2="" l_perm_mask="0137"
        l_maxperm="$(printf '%o' $((0777 & ~$l_perm_mask)))"
        while IFS= read -r -d $'\\0' l_fname; do
            l_mode=$(stat -Lc '%#a' "$l_fname")
            if [ $(( "$l_mode" & "$l_perm_mask" )) -gt 0 ]; then
                l_output2="$l_output2\\n - file: \\"$l_fname\\" is mode: \\"$l_mode\\" (should be mode: \\"$l_maxperm\\" or more restrictive)"
            fi
        done < <(find /etc/audit/ -type f \\( -name "*.conf" -o -name '*.rules' \\) -print0)
        if [ -z "$l_output2" ]; then
            echo -e "** PASS **\\n - All audit configuration files are mode: \\"$l_maxperm\\" or more restrictive"
        else
            echo -e "** FAIL **\\n$l_output2"
        fi
    }
    """
    process = subprocess.run(script, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if expected_output_pass in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    elif expected_output_fail in actual_output:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.6"
expected_output_pass = "Nothing should be returned"
actual_output = ""
try:
    command = "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.7"
expected_output_pass = "Nothing should be returned"
actual_output = ""
try:
    command = "find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.8"
expected_output_pass = "All audit tools are correctly configured"
actual_output = ""
try:
    l_perm_mask = "0022"
    l_maxperm = oct(0o777 & ~int(l_perm_mask, 8))[2:]
    audit_tools = ["/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/augenrules"]
    l_output = ""
    l_output2 = ""
    for audit_tool in audit_tools:
        command = f"stat -Lc '%#a' {audit_tool}"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        l_mode = process.stdout.strip()
        if int(l_mode) & int(l_perm_mask, 8) > 0:
            l_output2 += f"\n - Audit tool \"{audit_tool}\" is mode: \"{l_mode}\" and should be mode: \"{l_maxperm}\" or more restrictive"
        else:
            l_output += f"\n - Audit tool \"{audit_tool}\" is correctly configured to mode: \"{l_mode}\""
    if l_output2 == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, l_output2])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])
    
task_no = "6.3.4.9"
expected_output_pass = "Nothing should be returned"
actual_output = ""
try:
    command = 'stat -Lc "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk \'$2 != "root" {print}\''
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "6.3.4.10"
expected_output_pass = "Nothing should be returned"
actual_output = ""
try:
    command = 'stat -Lc "%n %G" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules | awk \'$2 != "root" {print}\''
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == "":
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "7.1.1"
expected_output_pass = "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/passwd:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/passwd:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/passwd:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.2"
expected_output_pass = "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/passwd-"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/passwd-:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/passwd-:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/passwd-:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.3"
expected_output_pass = "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/group:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/group:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/group:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.4"
expected_output_pass = "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group-"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/group-:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/group-:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/group-:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.5"
expected_output_pass = "Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/gshadow:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/gshadow:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/shadow:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.6"
expected_output_pass = "Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shadow-"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/shadow-:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/shadow-:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/shadow-:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.7"
expected_output_pass = "Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/gshadow:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/gshadow:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/gshadow:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.8"
expected_output_pass = "Access: (0/----------) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/gshadow-"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/gshadow-:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/gshadow-:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/gshadow-:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.9"
expected_output_pass = "Access: (0644/-rw-r--r--) Uid: ( 0/ root) Gid: ( 0/ root)"
actual_output = ""
try:
    command = "stat -Lc 'Access: (%#a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/shells"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", f"/etc/shells:\n{expected_output_pass}", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", f"/etc/shells:\n{expected_output_pass}", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", f"/etc/shells:\n{expected_output_pass}", f"Error: {str(e)}"])

task_no = "7.1.11"
expected_output_pass = "No world writable files exist on the local filesystem.\nSticky bit is set on world writable directories on the local filesystem."
expected_output_fail = "There are \"{count}\" World writable files on the system.\nThere are \"{count}\" World writable directories without the sticky bit on the system."
actual_output = ""
try:
    command = """#!/usr/bin/env bash
{
 l_output="" l_output2=""
 l_smask='01000'
 a_file=(); a_dir=()
 a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")
 while IFS= read -r l_mount; do
 while IFS= read -r l_file; do
 if [ -e "$l_file" ]; then
 [ -f "$l_file" ] && a_file+=("$l_file")
 if [ -d "$l_file" ]; then
 l_mode="$(stat -Lc '%#a' "$l_file")"
 [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=("$l_file")
 fi
 fi
 done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 2> /dev/null)
 done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')
 if ! (( ${#a_file[@]} > 0 )); then
 l_output="$l_output\n - No world writable files exist on the local filesystem."
 else
 l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_file[@]}")\" World writable files on the system.\n - The following is a list of World writable files:\n$(printf '%s\n' "${a_file[@]}")\n - end of list\n"
 fi
 if ! (( ${#a_dir[@]} > 0 )); then
 l_output="$l_output\n - Sticky bit is set on world writable directories on the local filesystem."
 else
 l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_dir[@]}")\" World writable directories without the sticky bit on the system.\n - The following is a list of World writable directories without the sticky bit:\n$(printf '%s\n' "${a_dir[@]}")\n - end of list\n"
 fi
 unset a_path; unset a_arr; unset a_file; unset a_dir
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2"
 [ -n "$l_output" ] && echo -e "- * Correctly configured *:\n$l_output\n"
 fi
}"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if "PASS" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "7.1.12"
expected_output_pass = "No files or directories without a owner exist on the local filesystem.\nNo files or directories without a group exist on the local filesystem."
expected_output_fail = "There are \"{count}\" unowned files or directories on the system.\nThere are \"{count}\" ungrouped files or directories on the system."
actual_output = ""
try:
    command = """#!/usr/bin/env bash
{
 l_output="" l_output2=""
 a_nouser=(); a_nogroup=()
 a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")
 while IFS= read -r l_mount; do
 while IFS= read -r l_file; do
 if [ -e "$l_file" ]; then
 while IFS=: read -r l_user l_group; do
 [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file")
 [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file")
 done < <(stat -Lc '%U:%G' "$l_file")
 fi
 done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) 2> /dev/null)
 done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')
 if ! (( ${#a_nouser[@]} > 0 )); then
 l_output="$l_output\n - No files or directories without a owner exist on the local filesystem."
 else
 l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nouser[@]}")\" unowned files or directories on the system.\n - The following is a list of unowned files and/or directories:\n$(printf '%s\n' "${a_nouser[@]}")\n - end of list"
 fi
 if ! (( ${#a_nogroup[@]} > 0 )); then
 l_output="$l_output\n - No files or directories without a group exist on the local filesystem."
 else
 l_output2="$l_output2\n - There are \"$(printf '%s' "${#a_nogroup[@]}")\" ungrouped files or directories on the system.\n - The following is a list of ungrouped files and/or directories:\n$(printf '%s\n' "${a_nogroup[@]}")\n - end of list"
 fi
 unset a_path; unset a_arr; unset a_nouser; unset a_nogroup
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2"
 [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output\n"
 fi
}"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if "PASS" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "7.2.1"
expected_output_pass = ""
actual_output = ""
try:
    command = "awk -F: '($2 != \"x\" ) { print \"User: \\\"\" $1 \"\\\" is not set to shadowed passwords \"}' /etc/passwd"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No users found without shadowed passwords.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No users found without shadowed passwords..", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No users found without shadowed passwords..", f"Error: {str(e)}"])

task_no = "7.2.2"
expected_output_pass = ""
actual_output = ""
try:
    command = "awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No users found without passwords.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No users found without passwords.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No users found without passwords.", f"Error: {str(e)}"])
    
task_no = "7.2.3"
expected_output_pass = ""
actual_output = ""
try:
    command = """#!/usr/bin/env bash
    {
        a_passwd_group_gid=($(awk -F: '{print $4}' /etc/passwd | sort -u))
        a_group_gid=($(awk -F: '{print $3}' /etc/group | sort -u))
        a_passwd_group_diff=($(printf '%s\n' "${a_group_gid[@]}" "${a_passwd_group_gid[@]}" | sort | uniq -u))
        
        for l_gid in "${a_passwd_group_diff[@]}"; do
            awk -F: '($4 == "'"$l_gid"'") {print " - User: \"" $1 "\" has GID: \"" $4 "\" which does not exist in /etc/group" }' /etc/passwd
        done
    }"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "All GIDs in /etc/passwd exist in /etc/group.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "All GIDs in /etc/passwd exist in /etc/group.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "All GIDs in /etc/passwd exist in /etc/group.", f"Error: {str(e)}"])

task_no = "7.2.4"
expected_output_pass = ""
actual_output = ""
try:
    command = """#!/usr/bin/env bash
    {
        while read -r l_count l_uid; do
            if [ "$l_count" -gt 1 ]; then
                echo -e "Duplicate UID: \"$l_uid\" Users: \"$(awk -F: '($3 == n) {print $1 }' n=$l_uid /etc/passwd | xargs)\""
            fi
        done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)
    }"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No duplicate UIDs found in /etc/passwd.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No duplicate UIDs found in /etc/passwd.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No duplicate UIDs found in /etc/passwd.", f"Error: {str(e)}"])

task_no = "7.2.5"
expected_output_pass = ""
actual_output = ""
try:
    command = """#!/usr/bin/env bash
    {
        while read -r l_count l_gid; do
            if [ "$l_count" -gt 1 ]; then
                echo -e "Duplicate GID: \"$l_gid\" Groups: \"$(awk -F: '($3 == n) {print $1 }' n=$l_gid /etc/group | xargs)\""
            fi
        done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)
    }"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No duplicate GIDs found in /etc/group.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No duplicate GIDs found in /etc/group.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No duplicate GIDs found in /etc/group.", f"Error: {str(e)}"])

task_no = "7.2.6"
expected_output_pass = ""
actual_output = ""
try:
    command = """#!/usr/bin/env bash
    {
        while read -r l_count l_user; do
            if [ "$l_count" -gt 1 ]; then
                echo -e "Duplicate User: \"$l_user\" Users: \"$(awk -F: '($1 == n) {print $1 }' n=$l_user /etc/passwd | xargs)\""
            fi
        done < <(cut -f1 -d":" /etc/group | sort -n | uniq -c)
    }"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No duplicate users found in /etc/group.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No duplicate users found in /etc/group.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No duplicate users found in /etc/group.", f"Error: {str(e)}"])

task_no = "7.2.7"
expected_output_pass = ""
actual_output = ""
try:
    command = """#!/usr/bin/env bash
    {
        while read -r l_count l_group; do
            if [ "$l_count" -gt 1 ]; then
                echo -e "Duplicate Group: \"$l_group\" Groups: \"$(awk -F: '($1 == n) { print $1 }' n=$l_group /etc/group | xargs)\""
            fi
        done < <(cut -f1 -d":" /etc/group | sort -n | uniq -c)
    }"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()    
    if actual_output == expected_output_pass:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", "No duplicate groups found in /etc/group.", actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", "No duplicate groups found in /etc/group.", actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "No duplicate groups found in /etc/group.", f"Error: {str(e)}"])

task_no = "7.2.8"
expected_output_pass = "All local interactive users: - home directories exist - own their home directory - home directories are mode: \"750\" or more restrictive"
expected_output_fail = "There are issues with user home directories."
actual_output = ""
try:
    command = """#!/usr/bin/env bash
{
 l_output="" l_output2="" l_heout2="" l_hoout2="" l_haout2=""
 l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
 unset a_uarr && a_uarr=()
 while read -r l_epu l_eph; do
     a_uarr+=("$l_epu $l_eph")
 done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"
 l_asize="${#a_uarr[@]}"
 [ "$l_asize " -gt "10000" ] && echo -e "\n ** INFO **\n - \"$l_asize\" Local interactive users found on the system\n - This may be a long running check\n"
 while read -r l_user l_home; do
     if [ -d "$l_home" ]; then
         l_mask='0027'
         l_max="$(printf '%o' $(( 0777 & ~$l_mask)) )"
         while read -r l_own l_mode; do
             [ "$l_user" != "$l_own" ] && l_hoout2="$l_hoout2\n - User: \"$l_user\" Home \"$l_home\" is owned by: \"$l_own\""
             if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
                 l_haout2="$l_haout2\n - User: \"$l_user\" Home \"$l_home\" is mode: \"$l_mode\" should be mode: \"$l_max\" or more restrictive"
             fi
         done <<< "$(stat -Lc '%U %#a' "$l_home")"
     else
         l_heout2="$l_heout2\n - User: \"$l_user\" Home \"$l_home\" Doesn't exist"
     fi
 done <<< "$(printf '%s\n' "${a_uarr[@]}")"
 [ -z "$l_heout2" ] && l_output="$l_output\n - home directories exist" || l_output2="$l_output2$l_heout2"
 [ -z "$l_hoout2" ] && l_output="$l_output\n - own their home directory" || l_output2="$l_output2$l_hoout2"
 [ -z "$l_haout2" ] && l_output="$l_output\n - home directories are mode: \"$l_max\" or more restrictive" || l_output2="$l_output2$l_haout2"
 [ -n "$l_output" ] && l_output=" - All local interactive users:$l_output"
 if [ -z "$l_output2" ]; then
     echo -e "\n- Audit Result:\n ** PASS **\n - * Correctly configured *:\n$l_output"
 else
     echo -e "\n- Audit Result:\n ** FAIL **\n - * Reasons for audit failure *:\n$l_output2"
     [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output"
 fi
}"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if "PASS" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

task_no = "7.2.9"
expected_output_pass = "All local interactive user dot files are correctly configured."
expected_output_fail = "There are issues with local interactive user dot files."
actual_output = ""

try:
    command = """#!/usr/bin/env bash
{
 a_output2=(); a_output3=()
 l_maxsize="1000"
 l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
 a_user_and_home=()
 while read -r l_local_user l_local_user_home; do
     [[ -n "$l_local_user" && -n "$l_local_user_home" ]] && a_user_and_home+=("$l_local_user:$l_local_user_home")
 done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"
 l_asize="${#a_user_and_home[@]}"
 [ "${#a_user_and_home[@]}" -gt "$l_maxsize" ] && printf '%s\n' "" " ** INFO **" " - \"$l_asize\" Local interactive users found on the system" " - This may be a long running check" ""
 file_access_chk()
 {
     a_access_out=()
     l_max="$(printf '%o' $(( 0777 & ~$l_mask)) )"
     if [ $(( $l_mode & $l_mask )) -gt 0 ]; then
         a_access_out+=(" - File: \"$l_hdfile\" is mode: \"$l_mode\" and should be mode: \"$l_max\" or more restrictive")
     fi
     if [[ ! "$l_owner" =~ ($l_user) ]]; then
         a_access_out+=(" - File: \"$l_hdfile\" owned by: \"$l_owner\" and should be owned by \"${l_user//|/ or }\"")
     fi
     if [[ ! "$l_gowner" =~ ($l_group) ]]; then
         a_access_out+=(" - File: \"$l_hdfile\" group owned by: \"$l_gowner\" and should be group owned by \"${l_group//|/ or }\"")
     fi
 }
 while IFS=: read -r l_user l_home; do
     a_dot_file=(); a_netrc=(); a_netrc_warn=(); a_bhout=(); a_hdirout=()
     if [ -d "$l_home" ]; then
         l_group="$(id -gn "$l_user" | xargs)"; l_group="${l_group// /|}"
         while IFS= read -r l_hdfile; do
             while read -r l_mode l_owner l_gowner; do
                 case "$(basename "$l_hdfile")" in
                     .forward | .rhost )
                         a_dot_file+=(" - File: \"$l_hdfile\" exists") ;;
                     .netrc )
                         l_mask='0177'; file_access_chk
                         if [ "${#a_access_out[@]}" -gt 0 ]; then
                             a_netrc+=("${a_access_out[@]}")
                         else
                             a_netrc_warn+=(" - File: \"$l_hdfile\" exists")
                         fi ;;
                     .bash_history )
                         l_mask='0177'; file_access_chk
                         [ "${#a_access_out[@]}" -gt 0 ] && a_bhout+=("${a_access_out[@]}") ;;
                     * )
                         l_mask='0133'; file_access_chk
                         [ "${#a_access_out[@]}" -gt 0 ] && a_hdirout+=("${a_access_out[@]}") ;;
                 esac
             done < <(stat -Lc '%#a %U %G' "$l_hdfile")
         done < <(find "$l_home" -xdev -type f -name '.*')
     fi
     if [[ "${#a_dot_file[@]}" -gt 0 || "${#a_netrc[@]}" -gt 0 || "${#a_bhout[@]}" -gt 0 || "${#a_hdirout[@]}" -gt 0 ]]; then
         a_output2+=(" - User: \"$l_user\" Home Directory: \"$l_home\""
         "${a_dot_file[@]}" "${a_netrc[@]}" "${a_bhout[@]}" "${a_hdirout[@]}")
     fi
     [ "${#a_netrc_warn[@]}" -gt 0 ] && a_output3+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_netrc_warn[@]}")
 done <<< "$(printf '%s\n' "${a_user_and_home[@]}")"
 if [ "${#a_output2[@]}" -le 0 ]; then
     [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' " ** WARNING **" "${a_output3[@]}"
     printf '%s\n' "- Audit Result:" " ** PASS **"
 else
     printf '%s\n' "- Audit Result:" " ** FAIL **" " - * Reasons for audit failure * :" "${a_output2[@]}" ""
     [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' " ** WARNING **" "${a_output3[@]}"
 fi
}"""
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    actual_output = process.stdout.strip()
    if "PASS" in actual_output:
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output_pass, actual_output])
    else:
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output_pass, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", expected_output_pass, f"Error: {str(e)}"])

show_results()