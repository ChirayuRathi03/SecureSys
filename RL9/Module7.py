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


### Written By: 
###     1. Aditi Jamsandekar
###     2. Chirayu Rathi
###     3. Siddhi Jani
############################