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
    module_name = os.path.splitext(os.path.basename(__file__))[0]
    with pd.ExcelWriter(excel_file, engine="openpyxl", mode="a" if os.path.exists(excel_file) else "w") as writer:
        df.to_excel(writer, sheet_name=module_name, index=False)

    print(f"Results written to sheet '{module_name}' in {excel_file}")


def normalize_whitespace(content: str) -> str:
    return ' '.join(content.split())


task_no = "6.1.1"
expected_output_prefix = "aide-"
try:
    command = "rpm -q aide"
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
    
task_no = "6.1.2"
output = []
actual_output = []
expected_output = "aidecheck.service and aidecheck.timer are enabled, and aidecheck.timer is running"
try:
    service_enabled = subprocess.run("systemctl is-enabled aidecheck.service", shell=True, capture_output=True, text=True).stdout.strip()
    timer_enabled = subprocess.run("systemctl is-enabled aidecheck.timer", shell=True, capture_output=True, text=True).stdout.strip()
    timer_status = subprocess.run("systemctl status aidecheck.timer", shell=True, capture_output=True, text=True).stdout.strip()
    if service_enabled == "enabled" and timer_enabled == "enabled" and "Active: active (waiting)" in timer_status:
        output.append(" - aidecheck.service and aidecheck.timer are enabled and aidecheck.timer is running")
        actual_output = ""
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = []
        if service_enabled != "enabled":
            actual_output.append(" - aidecheck.service is not enabled")
        if timer_enabled != "enabled":
            actual_output.append(" - aidecheck.timer is not enabled")
        if "Active: active (waiting)" not in timer_status:
            actual_output.append(" - aidecheck.timer is not running correctly")
        actual_output = "\n".join(actual_output)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.1.3"
output = []
actual_output = []
expected_output = "AIDE is configured to use cryptographic mechanisms for audit tools with options: p, i, n, u, g, s, b, acl, xattrs, sha512"
audit_tools = ["auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules"]
required_options = ["p", "i", "n", "u", "g", "s", "b", "acl", "xattrs", "sha512"]
try:
    config_file = subprocess.run("whereis aide.conf | awk '{print $2}'", shell=True, capture_output=True, text=True).stdout.strip()
    if config_file:
        config_content = subprocess.run(f"cat {config_file}", shell=True, capture_output=True, text=True).stdout.strip()
        missing_files = []
        missing_options = []
        for tool in audit_tools:
            if tool in config_content:
                for option in required_options:
                    if option not in config_content:
                        missing_options.append(f" - Option '{option}' missing for tool '{tool}' in AIDE config.")
            else:
                missing_files.append(f" - Audit tool file '{tool}' not found in AIDE config.")
        if not missing_files and not missing_options:
            output.append(f" - AIDE is properly configured with all required options for audit tools.")
            actual_output = ""
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
        else:
            actual_output = "\n".join(missing_files + missing_options)
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
    else:
        actual_output = " - AIDE configuration file not found. Verify if AIDE is installed."
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.1.1"
output = []
actual_output = []
expected_output = "systemd-journald is enabled (static) and active."
try:
    is_enabled_output = subprocess.run("systemctl is-enabled systemd-journald.service", shell=True, capture_output=True, text=True).stdout.strip()
    is_active_output = subprocess.run("systemctl is-active systemd-journald.service", shell=True, capture_output=True, text=True).stdout.strip()
    if is_enabled_output == "static" and is_active_output == "active":
        actual_output = f"enabled = {is_enabled_output}, active = {is_active_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"enabled = {is_enabled_output}, active = {is_active_output}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.1.2"
output = []
actual_output = []
expected_output = "Permissions of /etc/tmpfiles.d/systemd.conf or /usr/lib/tmpfiles.d/systemd.conf are set correctly."
try:
    file_path = ""
    if os.path.isfile("/etc/tmpfiles.d/systemd.conf"):
        file_path = "/etc/tmpfiles.d/systemd.conf"
    elif os.path.isfile("/usr/lib/tmpfiles.d/systemd.conf"):
        file_path = "/usr/lib/tmpfiles.d/systemd.conf"
    if file_path:
        higher_permissions_found = False
        with open(file_path, 'r') as f:
            for line in f:
                if re.search(r'^\s*[a-z]+\s+[^\s]+\s+0*([6-7][4-7][1-7]|7[0-7][0-7])\s+', line):
                    higher_permissions_found = True
                    break        
        if higher_permissions_found:
            actual_output = f" - permissions other than 0640 found in {file_path}"
            false_counter += 1
            false_tasks.append(task_no)
            task_data.append([task_no, "False", expected_output, actual_output])
        else:
            actual_output = f"{file_path} exists and has correct permissions set."
            true_counter += 1
            true_tasks.append(task_no)
            task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = " - Neither /etc/tmpfiles.d/systemd.conf nor /usr/lib/tmpfiles.d/systemd.conf exists."
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.1.3"
output = []
actual_output = []
expected_output = "Logs are rotated according to site policy with specified values for SystemMaxUse, SystemKeepFree, RuntimeMaxUse, RuntimeKeepFree, MaxFileSec."
try:
    config_output = subprocess.run("systemd-analyze cat-config systemd/journald.conf | grep -E '(SystemMaxUse|SystemKeepFree|RuntimeMaxUse|RuntimeKeepFree|MaxFileSec)'", shell=True, capture_output=True, text=True).stdout.strip()
    if config_output:
        actual_output = f"Log rotation settings:\n{config_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = " - No log rotation settings found. Ensure they are configured."
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.1.4"
output = []
actual_output = []
expected_output = "Only one logging system is in use: either rsyslog or systemd-journald."
try:
    l_output = ""
    l_output2 = ""    
    if subprocess.run("systemctl is-active --quiet rsyslog", shell=True).returncode == 0:
        l_output = "\n - rsyslog is in use\n- follow the recommendations in Configure rsyslog subsection only"
    elif subprocess.run("systemctl is-active --quiet systemd-journald", shell=True).returncode == 0:
        l_output = "\n - journald is in use\n- follow the recommendations in Configure journald subsection only"
    else:
        l_output2 = "\n - unable to determine system logging\nConfigure only ONE system logging: rsyslog OR journald"
    if not l_output2:
        actual_output = f"{l_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Reason(s) for failure:\n{l_output2}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.2.1.1"
expected_output_prefix = "systemd-journal-remote-"
try:
    command = "rpm -q systemd-journal-remote"
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

task_no = "6.2.2.1.2"
output = []
actual_output = []
expected_output = "systemd-journal-upload authentication is configured correctly with specified certificate locations and URL."
try:
    config_output = subprocess.run(
        "grep -P '^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=' /etc/systemd/journal-upload.conf",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if config_output:
        actual_output = f"{config_output}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "No authentication configuration found in /etc/systemd/journal-upload.conf"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.2.1.3"
output = []
actual_output = []
expected_output = "systemd-journal-upload is enabled and active."
try:
    enabled_status = subprocess.run(
        "systemctl is-enabled systemd-journal-upload.service",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    active_status = subprocess.run(
        "systemctl is-active systemd-journal-upload.service",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if enabled_status == "enabled" and active_status == "active":
        actual_output = "systemd-journal-upload is enabled and active.\n"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "systemd-journal-upload status:\n  Enabled: {}\n  Active: {}".format(enabled_status, active_status)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.2.1.4"
output = []
actual_output = []
expected_output = "systemd-journal-remote.socket and systemd-journal-remote.service are not enabled or active."
try:
    enabled_status = subprocess.run(
        "systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^enabled'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    active_status = subprocess.run(
        "systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^active'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if not enabled_status and not active_status:
        actual_output = "systemd-journal-remote.socket and systemd-journal-remote.service are not enabled or active.\n"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "systemd-journal-remote.socket and/or systemd-journal-remote.service status:\n  Enabled: {}\n  Active: {}".format(enabled_status, active_status)
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.2.2"
output = []
actual_output = []
expected_output = "ForwardToSyslog=no"
try:
    forward_to_syslog_status = subprocess.run(
        "systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E '^ForwardToSyslog=no'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if forward_to_syslog_status:
        actual_output = "ForwardToSyslog=no"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"ForwardToSyslog is not set to no.\n{forward_to_syslog_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.2.3"
output = []
actual_output = []
expected_output = "Compress=yes"
try:
    compress_status = subprocess.run(
        "systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E '^Compress=yes'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if compress_status:
        actual_output = "Compress=yes"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Compress is not set to yes.\n{compress_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])
    
task_no = "6.2.2.4"
output = []
actual_output = []
expected_output = "Storage=persistent"
try:
    storage_status = subprocess.run(
        "systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E '^Storage=persistent'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if storage_status:
        actual_output = "Storage=persistent"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Storage is not set to persistent.\n{storage_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.1"
expected_output_prefix = "rsyslog-"
try:
    command = "rpm -q rsyslog"
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

task_no = "6.2.3.2"
output = []
actual_output = []
expected_output = "rsyslog.service is enabled and active."
try:
    rsyslog_enabled = subprocess.run(
        "systemctl is-enabled rsyslog",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    rsyslog_active = subprocess.run(
        "systemctl is-active rsyslog.service",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if rsyslog_enabled == "enabled" and rsyslog_active == "active":
        actual_output = "rsyslog.service is enabled and active.\n"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"rsyslog.service status: enabled={rsyslog_enabled}, active={rsyslog_active}."
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.3"
output = []
actual_output = []
expected_output = "ForwardToSyslog=yes"
try:
    forward_to_syslog_status = subprocess.run(
        "systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E '^ForwardToSyslog=yes'",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()    
    if forward_to_syslog_status:
        actual_output = "ForwardToSyslog=yes"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"ForwardToSyslog is not set to yes.\n{forward_to_syslog_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.4"
output = []
actual_output = []
expected_output = "$FileCreateMode 0640."
try:
    file_create_mode_status = subprocess.run(
        "grep -Ps '^\\h*\\$FileCreateMode\\h+0[0,2,4,6][0,2,4]0\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()    
    if file_create_mode_status:
        actual_output = "$FileCreateMode 0640\n"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"$FileCreateMode is not set to 0640 or more restrictive.\n{file_create_mode_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.5"
output = []
actual_output = []
expected_output = "Logs are being recorded in /var/log/maillog."
try:
    mail_log_status = subprocess.run(
        "ls -l /var/log/maillog",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if mail_log_status:
        actual_output = f"{mail_log_status}\n"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "No logs are being recorded in /var/log/maillog.\n"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.6"
output = []
actual_output = []
expected_output = "@@<FQDN or IP of remote loghost>"
try:
    central_host_status = subprocess.run(
        "grep '^*.*[^I][^I]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if central_host_status:
        actual_output = f"{central_host_status}"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = "No logs are configured to be sent to a central host."
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.3.7"
output = []
actual_output = []
expected_output = "The system is not configured to accept incoming logs"
try:
    module_load_status = subprocess.run(
        "grep -Psi -- '^\h*module\\(load=\"?imtcp\"?\\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    input_type_status = subprocess.run(
        "grep -Psi -- '^\h*input\\(type=\"?imtcp\"?\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf",
        shell=True,
        capture_output=True,
        text=True
    ).stdout.strip()
    if not module_load_status and not input_type_status:
        actual_output = "No configuration found for accepting incoming logs."
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Configuration found that allows incoming logs.\n{module_load_status}; {input_type_status}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.4.1"
output = []
actual_output = []
expected_output = "/etc/logrotate.conf and /etc/logrotate.d/* should be reviewed for log rotation."
try:
    logrotate_conf = ""
    l_output = ""

    if subprocess.run("test -f /etc/logrotate.conf", shell=True).returncode == 0:
        logrotate_conf = "/etc/logrotate.conf"
    elif subprocess.run("compgen -G '/etc/logrotate.d/*.conf'", shell=True).returncode == 0:
        logrotate_conf = "/etc/logrotate.d/*.conf"
    elif subprocess.run("systemctl is-active --quiet systemd-journal-upload.service", shell=True).returncode == 0:
        actual_output = "- journald is in use on the system\n- recommendation is NA"
    else:
        actual_output = "- logrotate is not configured"
        l_output += "\n- rsyslog is in use and logrotate is not configured"

    if not l_output:
        actual_output = f"{logrotate_conf} and verify logs are rotated according to site policy."
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"Reason(s) for failure:\n{l_output}"
        false_counter += 1
        false_tasks.append(task_no)
        task_data.append([task_no, "False", expected_output, actual_output])
except Exception as e:
    false_counter += 1
    false_tasks.append(task_no)
    task_data.append([task_no, "False", "", f"Error: {str(e)}"])

task_no = "6.2.4.1"
output = []
actual_output = ""
expected_output = "All files in \"/var/log/\" have appropriate permissions and ownership."
l_output2 = []
try:
    l_uidmin = subprocess.run("awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs", shell=True, capture_output=True, text=True).stdout.strip()
    def file_test_chk(l_fname, l_mode, l_user, l_uid, l_group, l_auser, l_agroup, output_var, perm_mask, maxperm):
        if (int(l_mode, 8) & int(perm_mask, 8)) > 0:
            output_var.append(f"\n - Mode: \"{l_mode}\" should be \"{maxperm}\" or more restrictive")
        if not re.match(l_auser, l_user):
            output_var.append(f"\n - Owned by: \"{l_user}\" and should be owned by \"{l_auser.replace('|', ' or ')}\"")
        if not re.match(l_agroup, l_group):
            output_var.append(f"\n - Group owned by: \"{l_group}\" and should be group owned by \"{l_agroup.replace('|', ' or ')}\"")
    a_file = []
    for l_file in subprocess.run("find -L /var/log -type f -print0", shell=True, capture_output=True, text=True).stdout.split('\0'):
        if l_file:
            file_stats = subprocess.run(f"stat -Lc '%n^%#a^%U^%u^%G^%g' \"{l_file}\"", shell=True, capture_output=True, text=True).stdout.strip()
            a_file.append(file_stats)
    for l_entry in a_file:
        l_fname, l_mode, l_user, l_uid, l_group, l_gid = l_entry.split('^')
        l_bname = os.path.basename(l_fname)
        perm_mask = ''
        maxperm = ''
        if l_bname in ["lastlog", "lastlog.*", "wtmp", "wtmp.*", "wtmp-*", "btmp", "btmp.*", "btmp-*", "README"]:
            perm_mask = '0113'
            maxperm = oct(0o777 & ~int(perm_mask, 8))
            l_auser = "root"
            l_agroup = "(root|utmp)"
        elif l_bname in ["secure", "auth.log", "syslog", "messages"]:
            perm_mask = '0137'
            maxperm = oct(0o777 & ~int(perm_mask, 8))
            l_auser = "(root|syslog)"
            l_agroup = "(root|adm)"
        elif l_bname.lower() in ["sssd", "gdm", "gdm3"]:
            perm_mask = '0117'
            maxperm = oct(0o777 & ~int(perm_mask, 8))
            l_auser = "(root|SSSD)"
            l_agroup = "(root|SSSD|gdm|gdm3)"
        elif l_bname in ["*.journal", "*.journal~"]:
            perm_mask = '0137'
            maxperm = oct(0o777 & ~int(perm_mask, 8))
            l_auser = "root"
            l_agroup = "(root|systemd-journal)"
        else:
            perm_mask = '0137'
            maxperm = oct(0o777 & ~int(perm_mask, 8))
            l_auser = "(root|syslog)"
            l_agroup = "(root|adm)"        
        if perm_mask:
            file_test_chk(l_fname, l_mode, l_user, l_uid, l_group, l_auser, l_agroup, l_output2, perm_mask, maxperm)
    if not l_output2:
        actual_output = "All files in \"/var/log/\" have appropriate permissions and ownership"
        true_counter += 1
        true_tasks.append(task_no)
        task_data.append([task_no, "True", expected_output, actual_output])
    else:
        actual_output = f"{''.join(l_output2)}"
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

show_results()

### Written By: 
###     1. Aditi Jamsandekar
###     2. Chirayu Rathi
###     3. Siddhi Jani
############################
