#!/usr/bin/env bash

# Task 6.1.1: Ensure AIDE is installed
dnf install aide -y
#aide --init
#mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# Task 6.1.2: Ensure filesystem integrity is regularly checked:
#crontab -u root -e
#0 5 * * * /usr/sbin/aide --check

#cat <<EOF > /etc/systemd/system/aidecheck.service
#[Unit]
#Description=Aide Check

#[Service]
#Type=simple
#ExecStart=/usr/sbin/aide --check

#[Install]
#WantedBy=multi-user.target
#EOF

#cat <<EOF > /etc/systemd/system/aidecheck.timer
#[Unit]
#Description=Aide check every day at 5AM

#[Timer]
#OnCalendar=*-*-* 05:00:00
#Unit=aidecheck.service

#[Install]
#WantedBy=multi-user.target
#EOF

chown root:root /etc/systemd/system/aidecheck.*
chmod 0644 /etc/systemd/system/aidecheck.*

systemctl daemon-reload
systemctl enable aidecheck.service
systemctl --now enable aidecheck.timer

# Task 6.1.3: Ensure cryptographic mechanisms are used to protect the integrity of audit tools
AUDIT_PATH=$(readlink -f /sbin/auditctl)

AUDIT_DIR=$(dirname "$AUDIT_PATH")

AIDE_RULES="$AUDIT_DIR/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
$AUDIT_DIR/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
$AUDIT_DIR/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
$AUDIT_DIR/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
$AUDIT_DIR/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
$AUDIT_DIR/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512"

if grep -q '@@x_include' /etc/aide.conf; then
    echo "Warning: /etc/aide.conf includes an @@x_include statement. Ensure the executable files are owned by the current user and are not group or world-writable."
else
    echo -e "\n# Audit Tools\n$AIDE_RULES" >> /etc/aide.conf
    echo "/etc/aide.conf updated with audit tools paths."
fi

# Task 6.2.1.1: Ensure journald service is enabled and active
systemctl unmask systemd-journald.service
systemctl start systemd-journald.service

# Task 6.2.1.2: Ensure journald log file access is configured (Manual)
file_path=""

if [ -f /etc/tmpfiles.d/systemd.conf ]; then
  file_path="/etc/tmpfiles.d/systemd.conf"
elif [ -f /usr/lib/tmpfiles.d/systemd.conf ]; then
  cp /usr/lib/tmpfiles.d/systemd.conf /etc/tmpfiles.d/systemd.conf
  file_path="/etc/tmpfiles.d/systemd.conf"
fi

if [ -n "$file_path" ]; then
  sed -i 's/^\(\s*[a-z]\+\s\+[^\s]\+\s\+\)0*\([6-7][4-7][1-7]\|7[0-7][0-7]\)\s\+/\10640 /g' "$file_path"
  chmod 0640 "$file_path"
fi

# Task 6.2.1.3: Ensure journald log file rotation is configured (Manual)
file_path="/etc/systemd/journald.conf"
config="[Journal]\nSystemMaxUse=1G\nSystemKeepFree=500M\nRuntimeMaxUse=200M\nRuntimeKeepFree=50M\nMaxFileSec=1month"

if grep -q '^\[Journal\]' "$file_path"; then
  sed -i '/^\[Journal\]/a\'"$config"'' "$file_path"
else
  echo -e "$config" >> "$file_path"
fi

systemctl restart systemd-journald

# Task 6.2.1.4: Ensure only one logging system is in use
rsyslog_status=$(systemctl is-active --quiet rsyslog && echo "active" || echo "inactive")
journald_status=$(systemctl is-active --quiet systemd-journald && echo "active" || echo "inactive")

if [ "$rsyslog_status" = "active" ] && [ "$journald_status" = "active" ]; then
  systemctl stop systemd-journald
  systemctl disable systemd-journald
  rm -f /etc/systemd/journald.conf
  echo "Both rsyslog and systemd-journald are active. Disabled systemd-journald."
elif [ "$rsyslog_status" = "active" ] && [ "$journald_status" = "inactive" ]; then
  systemctl stop systemd-journald
  systemctl disable systemd-journald
  rm -f /etc/systemd/journald.conf
  systemctl restart rsyslog
  echo "rsyslog is active and systemd-journald is inactive."
elif [ "$rsyslog_status" = "inactive" ] && [ "$journald_status" = "active" ]; then
  systemctl stop rsyslog
  systemctl disable rsyslog
  rm -f /etc/rsyslog.conf
  systemctl restart systemd-journald
  echo "systemd-journald is active and rsyslog is inactive."
else
  echo "Neither rsyslog nor systemd-journald is active. Ensure that one logging system is configured."
fi

# Task 6.2.2.1.1: Ensure systemd-journal-remote is installed
dnf install systemd-journal-remote -y

# Task 6.2.2.1.2: Ensure systemd-journal-upload authentication is configured (Manual)
config_file="/etc/systemd/journal-upload.conf"
backup_file="/etc/systemd/journal-upload.conf.bak"

read -p "Enter the URL of the log server: " log_server_url

if [ ! -f "$config_file" ]; then
  touch "$config_file"
fi

cp "$config_file" "$backup_file"
sed -i '/^\[Upload\]/d' "$config_file"
cat <<EOL >> "$config_file"
[Upload]
URL=$log_server_url
ServerKeyFile=/etc/ssl/private/journal-upload.pem
ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
TrustedCertificateFile=/etc/ssl/ca/trusted.pem
EOL

systemctl restart systemd-journal-upload

# Task 6.2.2.1.3: Ensure systemd-journal-upload is enabled and active
systemctl unmask systemd-journal-upload.service
systemctl --now enable systemd-journal-upload.service

# Task 6.2.2.1.4: Ensure systemd-journal-remote service is not in use 
systemctl stop systemd-journal-remote.socket systemd-journal-remote.service
systemctl mask systemd-journal-remote.socket systemd-journal-remote.service

# Task 6.2.2.2: Ensure journald ForwardToSyslog is disabled
config_dir="/etc/systemd/journald.conf.d"
config_file="$config_dir/60-journald.conf"

if [ ! -d "$config_dir" ]; then
  mkdir -p "$config_dir"
fi

if grep -Pqs '^\s*\[Journal\]' "$config_file"; then
  sed -i '/^\s*ForwardToSyslog\s*=.*/d' "$config_file"
fi

if ! grep -Pqs '^\s*ForwardToSyslog\s*=' "$config_file"; then
  echo -e "[Journal]\nForwardToSyslog=no" >> "$config_file"
else
  sed -i '/^\s*\[Journal\]/a ForwardToSyslog=no' "$config_file"
fi

systemctl reload-or-restart systemd-journald

# Task 6.2.2.3: Ensure journald Compress is configured
config_dir="/etc/systemd/journald.conf.d"
config_file="$config_dir/60-journald.conf"

if [ ! -d "$config_dir" ]; then
  mkdir -p "$config_dir"
fi

if grep -Pqs '^\s*\[Journal\]' "$config_file"; then
  sed -i '/^\s*Compress\s*=.*/d' "$config_file"
fi

if ! grep -Pqs '^\s*Compress\s*=' "$config_file"; then
  echo -e "[Journal]\nCompress=yes" >> "$config_file"
else
  sed -i '/^\s*\[Journal\]/a Compress=yes' "$config_file"
fi

systemctl reload-or-restart systemd-journald

# Task 6.2.2.4: Ensure journald Storage is configured
config_dir="/etc/systemd/journald.conf.d"
config_file="$config_dir/60-journald.conf"

if [ ! -d "$config_dir" ]; then
  mkdir -p "$config_dir"
fi

if grep -Pqs '^\s*\[Journal\]' "$config_file"; then
  sed -i '/^\s*Storage\s*=.*/d' "$config_file"
fi

if ! grep -Pqs '^\s*Storage\s*=' "$config_file"; then
  echo -e "[Journal]\nStorage=persistent" >> "$config_file"
else
  sed -i '/^\s*\[Journal\]/a Storage=persistent' "$config_file"
fi

systemctl reload-or-restart systemd-journald

# Task 6.2.3.1: Ensure rsyslog is installed
dnf install rsyslog -y

# Task 6.2.3.2: Ensure rsyslog service is enabled and active
if systemctl is-active --quiet rsyslog; then
  echo "rsyslog is being used for logging."
  systemctl unmask rsyslog.service
  systemctl enable rsyslog.service
  systemctl start rsyslog.service
else
  echo "rsyslog is not being used for logging."
fi

# Task 6.2.3.3: Ensure journald is configured to send logs to rsyslog
if systemctl is-active --quiet rsyslog; then
  config_dir="/etc/systemd/journald.conf.d"
  config_file="$config_dir/60-journald.conf"

  if [ ! -d "$config_dir" ]; then
    mkdir -p "$config_dir"
  fi

  if grep -Pqs '^\s*\[Journal\]' "$config_file"; then
    sed -i '/^\s*ForwardToSyslog\s*=.*/d' "$config_file"
  fi

  if ! grep -Pqs '^\s*ForwardToSyslog\s*=' "$config_file"; then
    echo -e "[Journal]\nForwardToSyslog=yes" >> "$config_file"
  else
    sed -i '/^\s*\[Journal\]/a ForwardToSyslog=yes' "$config_file"
  fi

  systemctl reload-or-restart systemd-journald.service
else
  echo "rsyslog is not the preferred method for capturing logs."
fi

# Task 6.2.3.4: Ensure rsyslog log file creation mode is configured
config_file="/etc/rsyslog.conf"
mode="0640"
if [ ! -f "$config_file" ]; then
  touch "$config_file"
fi
if grep -Pqs '^\s*\$FileCreateMode\s*=' "$config_file"; then
  sed -i 's/^\s*\$FileCreateMode\s*=.*/\$FileCreateMode '"$mode"'/' "$config_file"
else
  echo -e "\n\$FileCreateMode $mode" >> "$config_file"
fi

# Check for dedicated .conf files in /etc/rsyslog.d/
for file in "$config_dir"*.conf; do
  if [ -f "$file" ]; then
    if grep -Pqs '^\s*\$FileCreateMode\s*=' "$file"; then
      sed -i 's/^\s*\$FileCreateMode\s*=.*/$FileCreateMode '"$mode"'/' "$file"
    else
      echo -e "\n$FileCreateMode $mode" >> "$file"
    fi
  fi
done

systemctl restart rsyslog

# Task 6.2.3.5: Ensure rsyslog logging is configured (Manual)
CONFIG_SETTINGS=(
  "*.emerg :omusrmsg:*"
  "auth,authpriv.* /var/log/secure"
  "mail.* -/var/log/mail"
  "mail.info -/var/log/mail.info"
  "mail.warning -/var/log/mail.warn"
  "mail.err /var/log/mail.err"
  "cron.* /var/log/cron"
  "*.=warning;*.=err -/var/log/warn"
  "*.crit /var/log/warn"
  "*.*;mail.none;news.none -/var/log/messages"
  "local0,local1.* -/var/log/localmessages"
  "local2,local3.* -/var/log/localmessages"
  "local4,local5.* -/var/log/localmessages"
  "local6,local7.* -/var/log/localmessages"
)

update_config_file() {
  local file=$1
  local setting
  local temp_file=$(mktemp)

  cp "$file" "$temp_file"

  for setting in "${CONFIG_SETTINGS[@]}"; do
    if grep -q "^${setting%% *}" "$temp_file"; then
      sed -i "s|^${setting%% *}.*|${setting}|g" "$temp_file"
    else
      echo "$setting" >> "$temp_file"
    fi
  done

  mv "$temp_file" "$file"
}

if [ -f /etc/rsyslog.conf ]; then
  update_config_file "/etc/rsyslog.conf"
fi

if [ -d /etc/rsyslog.d ]; then
  for conf_file in /etc/rsyslog.d/*.conf; do
    if [ -f "$conf_file" ]; then
      update_config_file "$conf_file"
    fi
  done
fi

systemctl restart rsyslog

# Task 6.2.3.6: Ensure rsyslog is configured to send logs to a remote log host
read -p "Enter the remote loghost (FQDN or IP): " remote_loghost

if systemctl is-active --quiet rsyslog; then

  [ ! -d /etc/rsyslog.d ] && mkdir /etc/rsyslog.d

  grep -Pq '^.*action\(\s*target="' /etc/rsyslog.conf /etc/rsyslog.d/*.conf && \
    sed -i "/^.*action(type=\"omfwd\"/d" /etc/rsyslog.conf /etc/rsyslog.d/*.conf

  printf '%s\n' "*.* action(type=\"omfwd\" target=\"$remote_loghost\" port=\"514\" protocol=\"tcp\" action.resumeRetryCount=\"100\" queue.type=\"LinkedList\" queue.size=\"1000\")" >> /etc/rsyslog.conf

  systemctl reload-or-restart rsyslog
fi

# Task 6.2.3.7: Ensure rsyslog is not configured to receive logs from a remote client
patterns=(
    "module(load=\"imtcp\")"
    "input(type=\"imtcp\" port=\"514\")"
    "\$ModLoad imtcp"
    "\$InputTCPServerRun"
)

if systemctl is-active --quiet rsyslog; then

    for pattern in "${patterns[@]}"; do
        grep -Rl "$pattern" /etc/rsyslog.conf /etc/rsyslog.d/ | while read -r file; do
            sed -i "/$pattern/d" "$file"
        done
    done

    systemctl restart rsyslog

else
    echo "rsyslog is not active. No changes were made."
fi

# Task 6.2.3.8: Ensure rsyslog logrotate is configured (Manual)
logrotate_conf="/etc/logrotate.conf"
logrotate_dir="/etc/logrotate.d"
logrotate_file="$logrotate_dir/rsyslog"

mkdir -p "$logrotate_dir"

cat <<EOF > "$logrotate_file"
/var/log/rsyslog/*.log {
    weekly
    rotate 4
    compress
    missingok
    notifempty
    postrotate
        /usr/bin/systemctl reload rsyslog.service >/dev/null || true
    endscript
}
EOF

logrotate -f /etc/logrotate.conf

# Task 6.2.4.1: Ensure access to all logfiles has been configured
log_min_uid="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"
result=""

check_file() {
    local file="$1"
    local mode="$2"
    local user="$3"
    local group="$4"

    local fixed=""
    local required_perm
    local correct_user="root"
    local correct_group="root"

    if [ $((mode & perm_mask)) -gt 0 ]; then
        fixed="$fixed\n - Mode: \"$mode\" should be \"$max_perm\" or more restrictive\n - Removing excess permissions"
        chmod "$required_perm" "$file"
    fi

    if [[ ! "$user" =~ $allowed_user ]]; then
        fixed="$fixed\n - Owned by: \"$user\" and should be owned by \"${allowed_user//|/ or }\"\n - Changing ownership to: \"$correct_user\""
        chown "$correct_user" "$file"
    fi

    if [[ ! "$group" =~ $allowed_group ]]; then
        fixed="$fixed\n - Group owned by: \"$group\" and should be group owned by \"${allowed_group//|/ or }\"\n - Changing group ownership to: \"$correct_group\""
        chgrp "$correct_group" "$file"
    fi

    [ -n "$fixed" ] && result="$result\n - File: \"$file\" is:$fixed\n"
}

files=()

while IFS= read -r -d $'\0' file; do
    [ -e "$file" ] && files+=("$(stat -Lc '%n^%#a^%U^%u^%G^%g' "$file")")
done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)

while IFS="^" read -r file mode user uid group gid; do
    basename="$(basename "$file")"

    case "$basename" in
        lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
            perm_mask='0113'
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            required_perm="ug-x,o-wx"
            allowed_user="root"
            allowed_group="(root|utmp)"
            check_file "$file" "$mode" "$user" "$group"
            ;;
        secure | auth.log | syslog | messages)
            perm_mask='0137'
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            required_perm="u-x,g-wx,o-rwx"
            allowed_user="(root|syslog)"
            allowed_group="(root|adm)"
            check_file "$file" "$mode" "$user" "$group"
            ;;
        SSSD | sssd)
            perm_mask='0117'
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            required_perm="ug-x,o-rwx"
            allowed_user="(root|SSSD)"
            allowed_group="(root|SSSD)"
            check_file "$file" "$mode" "$user" "$group"
            ;;
        gdm | gdm3)
            perm_mask='0117'
            required_perm="ug-x,o-rwx"
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            allowed_user="root"
            allowed_group="(root|gdm|gdm3)"
            check_file "$file" "$mode" "$user" "$group"
            ;;
        *.journal | *.journal~)
            perm_mask='0137'
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            required_perm="u-x,g-wx,o-rwx"
            allowed_user="root"
            allowed_group="(root|systemd-journal)"
            check_file "$file" "$mode" "$user" "$group"
            ;;
        *)
            perm_mask='0137'
            max_perm="$(printf '%o' $((0777 & ~$perm_mask)))"
            required_perm="u-x,g-wx,o-rwx"
            allowed_user="(root|syslog)"
            allowed_group="(root|adm)"
            if [ "$uid" -lt "$log_min_uid" ] && [ -z "$(awk -v grp="$group" -F: '$1==grp {print $4}' /etc/group)" ]; then
                if [[ ! "$user" =~ $allowed_user ]]; then
                    allowed_user="(root|syslog|$user)"
                fi
                if [[ ! "$group" =~ $allowed_group ]]; then
                    if ! awk -F: '$4=="'"$gid"'" {print $3}' /etc/passwd | awk -v min_uid="$log_min_uid" '$1 >= min_uid {exit 1}'; then
                        allowed_group="(root|adm|$group)"
                    fi
                fi
            fi
            check_file "$file" "$mode" "$user" "$group"
            ;;
    esac
done <<< "$(printf '%s\n' "${files[@]}")"

if [ -z "$result" ]; then
    echo -e "- All files in \"/var/log/\" have appropriate permissions and ownership\n - No changes required\n"
else
    echo -e "\n$result"
fi

# Task 6.3.1.1: Ensure auditd packages are installed
dnf install audit audit-libs -y

# Task 6.3.1.2: Ensure auditing for processes that start prior to auditd is enabled
grubby --update-kernel ALL --args 'audit=1'

grub_file="/etc/default/grub"
search_term="GRUB_CMDLINE_LINUX="

# Backup the grub file before editing
cp "$grub_file" "${grub_file}.bak"

if grep -q "^$search_term" "$grub_file"; then
    # If GRUB_CMDLINE_LINUX exists, check and add 'audit=1' if missing
    sed -i "/^$search_term/ s/\"\$/ audit=1\"/" "$grub_file"
else
    # If GRUB_CMDLINE_LINUX does not exist, add it
    echo 'GRUB_CMDLINE_LINUX="audit=1"' >> "$grub_file"
fi

grub2-mkconfig -o /boot/grub2/grub.cfg

# Task 6.3.1.3: Ensure audit_backlog_limit is sufficient
read -rp "Enter the audit_backlog_limit size (e.g., 8192): " backlog_size

grubby --update-kernel ALL --args "audit_backlog_limit=${backlog_size}"

# Backup the grub file before editing again
cp "$grub_file" "${grub_file}.bak2"

if grep -q "^$search_term" "$grub_file"; then
    # If GRUB_CMDLINE_LINUX exists, check and add 'audit_backlog_limit' if missing
    sed -i "/^$search_term/ s/\"\$/ audit_backlog_limit=${backlog_size}\"/" "$grub_file"
else
    # If GRUB_CMDLINE_LINUX does not exist, add it
    echo "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=${backlog_size}\"" >> "$grub_file"
fi

grub2-mkconfig -o /boot/grub2/grub.cfg

# Task 6.3.1.4: Ensure auditd service is enabled and active
systemctl unmask auditd
systemctl enable auditd
systemctl start auditd

# Task 6.3.2.1: Ensure audit log storage size is configured
read -rp "Enter the max_log_file size: " log_file_size

auditd_conf="/etc/audit/auditd.conf"
temp_file=$(mktemp)
if grep -q "^max_log_file" "$auditd_conf"; then
    awk -v key="max_log_file" -v value="$log_file_size" \
    '{ if ($0 ~ "^"key) $0 = key " = " value; print }' \
    "$auditd_conf" > "$temp_file" && mv "$temp_file" "$auditd_conf"
else
    echo "max_log_file = $log_file_size" >> "$auditd_conf"
fi
[ -f "$temp_file" ] && rm "$temp_file"
echo "Configuration updated successfully."

# Task 6.3.2.2: Ensure audit logs are not automatically deleted 
auditd_conf="/etc/audit/auditd.conf"
temp_file=$(mktemp)
if grep -q "^max_log_file_action" "$auditd_conf"; then
    echo "Updating existing max_log_file_action setting in $auditd_conf"
    awk -v key="max_log_file_action" -v value="keep_logs" \
    '{ if ($0 ~ "^"key) $0 = key " = " value; print }' \
    "$auditd_conf" > "$temp_file" && mv "$temp_file" "$auditd_conf"
else
    echo "Appending max_log_file_action = keep_logs to $auditd_conf"
    echo "max_log_file_action = keep_logs" >> "$auditd_conf"
fi
[ -f "$temp_file" ] && rm "$temp_file"
#systemctl restart auditd

# Task 6.3.2.3: Ensure system is disabled when audit logs are full
auditd_conf="/etc/audit/auditd.conf"
if grep -q '^disk_full_action' "$auditd_conf"; then
    sed -i 's/^disk_full_action\s*=.*/disk_full_action = halt/' "$auditd_conf"
else
    echo 'disk_full_action = halt' >> "$auditd_conf"
fi
if grep -q '^disk_error_action' "$auditd_conf"; then
    sed -i 's/^disk_error_action\s*=.*/disk_error_action = halt/' "$auditd_conf"
else
    echo 'disk_error_action = halt' >> "$auditd_conf"
fi

# Commands to set both parameters to 'single':
# sed -i 's/^disk_full_action.*/disk_full_action = single/' /etc/audit/auditd.conf
# sed -i 's/^disk_error_action.*/disk_error_action = single/' /etc/audit/auditd.conf
# replace these with the 'halt' lines above.

# Difference between the 2:
#    single: The system will be switched to single-user mode for manual intervention if the disk is full or if there is a disk error.
#    halt: The system will be halted or powered off if the disk is full or if there is a disk error.

# Task 6.3.2.4: Ensure system warns when audit logs are low on space
auditd_conf="/etc/audit/auditd.conf"
if grep -q '^space_left_action' "$auditd_conf"; then
    sed -i 's/^space_left_action\s*=.*/space_left_action = email/' "$auditd_conf"
else
    echo 'space_left_action = email' >> "$auditd_conf"
fi
if grep -q '^admin_space_left_action' "$auditd_conf"; then
    sed -i 's/^admin_space_left_action\s*=.*/admin_space_left_action = single/' "$auditd_conf"
else
    echo 'admin_space_left_action = single' >> "$auditd_conf"
fi

# Commands to set space_left_action to 'exec' or 'halt':
# sed -i 's/^space_left_action.*/space_left_action = exec/' /etc/audit/auditd.conf
# sed -i 's/^space_left_action.*/space_left_action = halt/' /etc/audit/auditd.conf

# Commands to set admin_space_left_action to 'halt':
# sed -i 's/^admin_space_left_action.*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# Difference between options:
# space_left_action = email: Sends an email notification when space is running low. Requires an MTA.
# space_left_action = exec: Executes a command when space is running low.
# space_left_action = single: Switches to single-user mode when space is running low.
# space_left_action = halt: Halts or powers off the system when space is running low.

# admin_space_left_action = single: Switches to single-user mode when space is critically low.
# admin_space_left_action = halt: Halts or powers off the system when space is critically low.

# Task 6.3.3.1: Ensure changes to system administration scope (sudoers) is collected
RULE_FILE="/etc/audit/rules.d/50-scope.rules"

if ! grep -q '/etc/sudoers' "$RULE_FILE"; then
    printf '%s\n' "-w /etc/sudoers -p wa -k scope" > "$RULE_FILE"
fi

if ! grep -q '/etc/sudoers.d' "$RULE_FILE"; then
    printf '%s\n' "-w /etc/sudoers.d -p wa -k scope" > "$RULE_FILE"
fi

augenrules --load

# Task 6.3.3.2: Ensure actions as another user are always logged
RULE_FILE="/etc/audit/rules.d/50-user_emulation.rules"

if ! grep -q 'user_emulation' "$RULE_FILE"; then
    printf "
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
" > "$RULE_FILE"
fi

augenrules --load

# Task 6.3.3.3: Ensure events that modify the sudo log file are collected
RULE_FILE="/etc/audit/rules.d/50-sudo.rules"
SUDO_LOG_FILE=$(grep -r 'logfile' /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g')

if [ -n "${SUDO_LOG_FILE}" ]; then
    if ! grep -q "${SUDO_LOG_FILE}" "$RULE_FILE"; then
        echo "-w ${SUDO_LOG_FILE} -p wa -k sudo_log_file" >> "$RULE_FILE"
    fi
else
    echo "ERROR: Variable 'SUDO_LOG_FILE' is unset."
fi

augenrules --load

# Task 6.3.3.4: Ensure events that modify date and time information are collected
RULE_FILE="/etc/audit/rules.d/50-time-change.rules"

# Ensure time-change related rules are in place
cat << EOF > "$RULE_FILE"
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
EOF

augenrules --load


# Task 6.3.3.5: Ensure events that modify the system's network environment are collected
RULE_FILE="/etc/audit/rules.d/50-system_locale.rules"

printf "
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/NetworkManager -p wa -k system-locale
" > "$RULE_FILE"

augenrules --load

# Task 6.3.3.6: Ensure use of privileged commands are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
AUDIT_RULE_FILE="/etc/audit/rules.d/50-privileged.rules"
NEW_DATA=()

for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv "noexec|nosuid" | awk '{print $1}'); do
    readarray -t DATA < <(find "${PARTITION}" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }')
    for ENTRY in "${DATA[@]}"; do
        NEW_DATA+=("${ENTRY}")
    done
done

readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
printf '%s\n' "${COMBINED_DATA[@]}" | sort -u > "${AUDIT_RULE_FILE}"

augenrules --load

# Task 6.3.3.7: Ensure unsuccessful file access attempts are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-access.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.8: Ensure events that modify user/group information are collected
RULE_FILE="/etc/audit/rules.d/50-identity.rules"

printf "
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/nsswitch.conf -p wa -k identity
-w /etc/pam.conf -p wa -k identity
-w /etc/pam.d -p wa -k identity
" > "$RULE_FILE"

augenrules --load

# Task 6.3.3.9: Ensure discretionary access control permission modification events are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-perm_mod.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.10: Ensure successful file system mounts are collected 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-mounts.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.11: Ensure session initiation information is collected
RULE_FILE="/etc/audit/rules.d/50-session.rules"

printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" > "$RULE_FILE"

augenrules --load

# Task 6.3.3.12: Ensure login and logout events are collected
RULE_FILE="/etc/audit/rules.d/50-login.rules"

printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" > "$RULE_FILE"

augenrules --load

# Task 6.3.3.13: Ensure file deletion events by users are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-delete.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.14: Ensure events that modify the system's Mandatory Access Controls are collected
RULE_FILE="/etc/audit/rules.d/50-MAC-policy.rules"

printf "
-w /etc/selinux -p wa -k MAC-policy
-w /usr/share/selinux -p wa -k MAC-policy
" > "$RULE_FILE"

augenrules --load

# Task 6.3.3.15: Ensure successful and unsuccessful attempts to use the chcon command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.16: Ensure successful and unsuccessful attempts to use the setfacl command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.17: Ensure successful and unsuccessful attempts to use the chacl command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.18: Ensure successful and unsuccessful attempts to use the usermod command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-usermod.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.19: Ensure kernel module loading unloading and modification is collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-kernel_modules.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
" > "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

# Task 6.3.3.20: Ensure the audit configuration is immutable
printf '\n-e 2' > /etc/audit/rules.d/99-finalize.rules
augenrules --load

# Task 6.3.3.21: Ensure the running and on disk configuration is the same (manual)

# Task 6.3.4.1: Ensure the audit log file directory mode is configured 
log_dir=$(dirname "$(awk -F= '/^\s*log_file\s*/{print $2}' /etc/audit/auditd.conf | xargs)")
if [ -d "$log_dir" ]; then
    chmod g-w,o-rwx "$log_dir"
else
    echo "Error: Directory '$log_dir' not found."
fi

# Task 6.3.4.2: Ensure audit log files mode is configured
log_dir=$(dirname "$(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs)")
if [ -d "$log_dir" ]; then
    find "$log_dir" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
else
    echo "Error: Log directory '$log_dir' not found."
fi

# Task 6.3.4.3: Ensure audit log files owner is configured
[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +

# Task 6.3.4.4: Ensure audit log files group owner is configured
read -p "Enter the name of the group to set for audit logs: " GROUP_NAME
find "$(dirname "$(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs)")" -type f \( ! -group "$GROUP_NAME" -a ! -group root \) -exec chgrp "$GROUP_NAME" {} +
chgrp "$GROUP_NAME" /var/log/audit/
if grep -q '^\s*log_group\s*=' /etc/audit/auditd.conf; then
    sed -ri "s/^\s*log_group\s*=\s*\S+/log_group = $GROUP_NAME/" /etc/audit/auditd.conf
else
    echo "log_group = $GROUP_NAME" >> /etc/audit/auditd.conf
fi
#systemctl restart auditd

# Task 6.3.4.5: Ensure audit configuration files mode is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +

# Task 6.3.4.6: Ensure audit configuration files owner is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +

# Task 6.3.4.7: Ensure audit configuration files group owner is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +

# Task 6.3.4.8: Ensure audit tools mode is configured
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# Task 6.3.4.9: Ensure audit tools owner is configured
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# Task 6.3.4.10: Ensure audit tools group owner is configured
chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

### Written By: 
###     1. Aditi Jamsandekar
###     2. Siddhi Jani
###     3. Chirayu Rathi
############################
