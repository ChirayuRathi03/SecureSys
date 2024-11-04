#!/usr/bin/env bash

# Task 5.1.1 Ensure permissions on /etc/ssh/sshd_config are configured
{
  chmod u-x,og-rwx /etc/ssh/sshd_config
  chown root:root /etc/ssh/sshd_config
  while IFS= read -r -d $'\0' l_file; do
    if [ -e "$l_file" ]; then
      chmod u-x,og-rwx "$l_file"
      chown root:root "$l_file"
    fi
  done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
}

# Task 5.1.2: Ensure permissions on SSH private host key files are configured
ssh_group_name="$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)"

fix_file_permissions() {
  file_mode=$1
  file_owner=$2
  file_group=$3
  file=$4

  output=""
  pmask="0177"
  [ "$file_group" = "$ssh_group_name" ] && pmask="0137"
  maxperm=$(printf '%o' $((0777 & ~$pmask)))

  # Fix mode if necessary
  if [ $((file_mode & pmask)) -gt 0 ]; then
    output="$output\n - Mode: \"$file_mode\" should be \"$maxperm\" (more restrictive)"
    chmod "u-x,g-wx,o-rwx" "$file"
  fi

  # Fix owner if necessary
  if [ "$file_owner" != "root" ]; then
    output="$output\n - Owner: \"$file_owner\" should be \"root\""
    chown root "$file"
  fi

  # Fix group if necessary
  if [[ ! "$file_group" =~ ($ssh_group_name|root) ]]; then
    new_group="${ssh_group_name:-root}"
    output="$output\n - Group: \"$file_group\" should be \"$new_group\""
    chgrp "$new_group" "$file"
  fi

  echo -e "$output"
}

output=""
while IFS= read -r -d $'\0' file; do
  if ssh-keygen -lf "$file" &>/dev/null && file "$file" | grep -Piq '\bopenssh\h+([^#\n\r]+\h+)?private\h+key\b'; then
    file_info=$(stat -Lc '%#a:%U:%G' "$file")
    output+=$(fix_file_permissions ${file_info//:/ } "$file")
  fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

if [ -z "$output" ]; then
  echo -e "\n- No access changes required\n"
else
  echo -e "\n- Remediation results:\n$output\n"
fi

# Task 5.1.3 Ensure permissions on SSH public host key files are configured
output=""
output2=""
pmask="0133"
maxperm=$(printf '%o' $((0777 & ~$pmask)))

fix_file_permissions() {
    while IFS=: read -r file_mode file_owner file_group; do
        out2=""

        # Check and update file mode
        if [ $((file_mode & pmask)) -gt 0 ]; then
            out2+="\n - Mode: \"$file_mode\" should be \"$maxperm\" or more restrictive"
            chmod u-x,go-wx "$file"
        fi

        # Check and update file ownership
        if [ "$file_owner" != "root" ]; then
            out2+="\n - Owned by: \"$file_owner\" should be \"root\""
            chown root "$file"
        fi

        # Check and update file group
        if [ "$file_group" != "root" ]; then
            out2+="\n - Group: \"$file_group\" should be \"root\""
            chgrp root "$file"
        fi

        # Append results to output variables
        if [ -n "$out2" ]; then
            output2+="\n - File: \"$file\"$out2"
        else
            output+="\n - File: \"$file\"\n - Correct: mode: \"$file_mode\", owner: \"$file_owner\", and group: \"$file_group\""
        fi
    done < <(stat -Lc '%#a:%U:%G' "$file")
}

while IFS= read -r -d $'\0' file; do
    if ssh-keygen -lf "$file" &>/dev/null && file "$file" | grep -Piq '\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b'; then
        fix_file_permissions "$file"
    fi
done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

if [ -z "$output2" ]; then
    echo -e "\n- No access changes required\n"
else
    echo -e "\n- Remediation results:\n$output2\n"
fi

# Variables
CRYPTO_POLICY="DEFAULT"
CRYPTO_SUBPOLICY1="NO-SHA1"
CRYPTO_SUBPOLICY2="NO-WEAKMAC"
CRYPTO_SUBPOLICY3="NOSSHCHACHA20"
CRYPTO_SUBPOLICY4="NO-SSHWEAKCIPHERS"
SSHD_CONFIG="/etc/ssh/sshd_config"

# Task 5.1.4: Ensure sshd Ciphers are configured
SUBPOLICY_FILE="/etc/crypto-policies/policies/modules/NO-SSHWEAKCIPHERS.pmod"
echo "Creating or updating the subpolicy file: $SUBPOLICY_FILE"
cat <<EOF > "$SUBPOLICY_FILE"
# This is a subpolicy to disable weak ciphers for the SSH protocol
cipher@SSH = -3DES-CBC -AES-128-CBC -AES-192-CBC -AES-256-CBC -CHACHA20-POLY1305
EOF

echo "Updating system-wide cryptographic policy"
update-crypto-policies --set "${CRYPTO_POLICY}:${CRYPTO_SUBPOLICY1}:${CRYPTO_SUBPOLICY2}:${CRYPTO_SUBPOLICY3}:${CRYPTO_SUBPOLICY4}"

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

CIPHERS_LINE="Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com"
if ! grep -q "$CIPHERS_LINE" "$SSHD_CONFIG"; then
    echo "Manual configuration detected. Modifying $SSHD_CONFIG"
    if grep -q "^Ciphers" "$SSHD_CONFIG"; then
        sed -i "s/^Ciphers.*/$CIPHERS_LINE/" "$SSHD_CONFIG"
    else
        echo "$CIPHERS_LINE" >> "$SSHD_CONFIG"
    fi
fi

# Task 5.1.5: Ensure sshd KexAlgorithms is configured
SUBPOLICY_FILE="/etc/crypto-policies/policies/modules/NO-SHA1.pmod"
echo "Creating or updating the subpolicy file: $SUBPOLICY_FILE"
cat <<EOF > "$SUBPOLICY_FILE"
# This is a subpolicy dropping the SHA1 hash and signature support
hash = -SHA1
sign = -*-SHA1
sha1_in_certs = 0
EOF

echo "Updating system-wide cryptographic policy"
update-crypto-policies --set "${CRYPTO_POLICY}:${CRYPTO_SUBPOLICY1}:${CRYPTO_SUBPOLICY2}:${CRYPTO_SUBPOLICY3}:${CRYPTO_SUBPOLICY4}"

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

KEX_ALGORITHMS_LINE="KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"
if ! grep -q "$KEX_ALGORITHMS_LINE" "$SSHD_CONFIG"; then
    echo "Manual configuration detected. Modifying $SSHD_CONFIG"
    if grep -q "^KexAlgorithms" "$SSHD_CONFIG"; then
        sed -i "s/^KexAlgorithms.*/$KEX_ALGORITHMS_LINE/" "$SSHD_CONFIG"
    else
        echo "$KEX_ALGORITHMS_LINE" >> "$SSHD_CONFIG"
    fi
fi

# Task 5.1.6: Ensure sshd MACs are configured
SUBPOLICY_FILE="/etc/crypto-policies/policies/modules/NO-SSHWEAKMACS.pmod"
echo "Creating or updating the subpolicy file: $SUBPOLICY_FILE"
cat <<EOF > "$SUBPOLICY_FILE"
# This is a subpolicy to disable weak MACs for the SSH protocol
mac@SSH = -HMAC-MD5* -UMAC-64* -UMAC-128*
EOF

echo "Updating system-wide cryptographic policy"
update-crypto-policies --set "${CRYPTO_POLICY}:${CRYPTO_SUBPOLICY1}:${CRYPTO_SUBPOLICY2}:${CRYPTO_SUBPOLICY3}:${CRYPTO_SUBPOLICY4}"

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

MACS_LINE="MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"
if ! grep -q "$MACS_LINE" "$SSHD_CONFIG"; then
    echo "Manual configuration detected. Modifying $SSHD_CONFIG"
    if grep -q "^MACs" "$SSHD_CONFIG"; then
        sed -i "s/^MACs.*/$MACS_LINE/" "$SSHD_CONFIG"
    else
        echo "$MACS_LINE" >> "$SSHD_CONFIG"
    fi
fi


# Task 5.1.7: Ensure sshd access is configured
prompt_for_input() {
    local prompt_message="$1"
    read -p "$prompt_message: " input_value
    echo "$input_value"
}

user_exists() {
    id "$1" &>/dev/null
}

group_exists() {
    getent group "$1" &>/dev/null
}

USER_LIST=$(prompt_for_input "Enter the list of allowed users (separated by spaces)")
GROUP_LIST=$(prompt_for_input "Enter the list of allowed groups (separated by spaces)")

VALID_USERS=""
VALID_GROUPS=""

# Validate each user
for user in $USER_LIST; do
    if user_exists "$user"; then
        VALID_USERS="$VALID_USERS $user"
    else
        echo "Warning: User '$user' does not exist."
    fi
done

# Validate each group
for group in $GROUP_LIST; do
    if group_exists "$group"; then
        VALID_GROUPS="$VALID_GROUPS $group"
    else
        echo "Warning: Group '$group' does not exist."
    fi
done

SSHD_CONFIG="/etc/ssh/sshd_config"
INCLUDE_LINE="Include /etc/ssh/sshd_config.d/*.conf"

# Function to add or update a parameter in the sshd_config file
add_or_update_sshd_config() {
    local param="$1"
    local value="$2"
    
    if grep -q "^$param" "$SSHD_CONFIG"; then
        sed -i "s/^$param.*/$param $value/" "$SSHD_CONFIG"
    else
        # Insert above any Include or Match statements
        awk -v param="$param" -v value="$value" '
            !added && /^Include/ || /^Match/ {
                print param, value;
                added = 1
            }
            { print }
        ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp" && mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
    fi
}

# Ensure AllowUsers or AllowGroups is set before Include or Match statements
if [ -n "$VALID_USERS" ]; then
    add_or_update_sshd_config "AllowUsers" "$VALID_USERS"
fi

if [ -n "$VALID_GROUPS" ]; then
    add_or_update_sshd_config "AllowGroups" "$VALID_GROUPS"
fi

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

# Task 5.1.8: Ensure sshd Banner is configured
SSHD_CONFIG="/etc/ssh/sshd_config"
BANNER_FILE="/etc/issue.net"
BANNER_CONTENT="Authorized users only. All activity may be monitored and reported."

add_or_update_banner() {
    local param="Banner"
    local value="$BANNER_FILE"
    
    if grep -q "^$param" "$SSHD_CONFIG"; then
        sed -i "s|^$param.*|$param $value|" "$SSHD_CONFIG"
    else
        # Insert above any Include or Match statements
        awk -v param="$param" -v value="$value" '
            !added && /^Include/ || /^Match/ {
                print param, value;
                added = 1
            }
            { print }
        ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp" && mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
    fi
}

update_banner_file() {
    printf '%s\n' "$BANNER_CONTENT" > "$BANNER_FILE"
}

clean_banner_file() {
    sed -i 's/\\[mrsv]//g' "$BANNER_FILE"
}

add_or_update_banner
update_banner_file
clean_banner_file

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

# Task 5.1.9: Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured
SSHD_CONFIG="/etc/ssh/sshd_config"
CLIENT_ALIVE_INTERVAL="15"
CLIENT_ALIVE_COUNT_MAX="3"

add_or_update_sshd_config() {
    local param="$1"
    local value="$2"
    
    # Check if the parameter is already present
    if grep -q "^$param" "$SSHD_CONFIG"; then
        # Update existing parameter
        sed -i "s|^$param.*|$param $value|" "$SSHD_CONFIG"
    else
        # Insert above any Include or Match statements
        sed -i "/^Include\|^Match/i $param $value" "$SSHD_CONFIG"
    fi
}

add_or_update_sshd_config "ClientAliveInterval" "$CLIENT_ALIVE_INTERVAL"
add_or_update_sshd_config "ClientAliveCountMax" "$CLIENT_ALIVE_COUNT_MAX"

echo "Reloading or restarting the OpenSSH server"
systemctl reload-or-restart sshd

# Task 5.1.10: Ensure sshd DisableForwarding is enabled
sed -i '/^DisableForwarding/d' /etc/ssh/sshd_config
sed -i '/^Include/i DisableForwarding yes' /etc/ssh/sshd_config
# This means that users will not be able to forward X11 graphical applications or forward ports through the SSH connection.

# Task 5.1.11: Ensure sshd GSSAPIAuthentication is disabled
sed -i '/^GSSAPIAuthentication/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i GSSAPIAuthentication no' /etc/ssh/sshd_config
# This means that users will not be able to use GSSAPI authentication. (Generic Security Services Application Program Interface)

# Task 5.1.12: Ensure sshd HostbasedAuthentication is disabled
sed -i '/^HostbasedAuthentication/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i HostbasedAuthentication no' /etc/ssh/sshd_config
# This means that users will not be able to use host-based authentication. Host-based authentication allows SSH to verify the
# identity of the connecting host based on its IP address or hostname and an associated key.

# Task 5.1.13: Ensure sshd IgnoreRhosts is enabled
sed -i '/^IgnoreRhosts/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i IgnoreRhosts yes' /etc/ssh/sshd_config
# This means that SSH will ignore the Rhosts file, which is used for host-based authentication.

# Task 5.1.14: Ensure sshd LoginGraceTime is configured
sed -i '/^LoginGraceTime/d' /etc/ssh/sshd_config
sed -i '/^Include/i LoginGraceTime 60' /etc/ssh/sshd_config
# This means that users will have 60 seconds to log in after connecting to the SSH server.

# Task 5.1.15: Ensure sshd LogLevel is configured
sed -i '/^LogLevel/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i LogLevel VERBOSE' /etc/ssh/sshd_config
# sed -i '/^Include\|^Match/i LogLevel INFO' /etc/ssh/sshd_config
# VERBOSE provides a more detailed diagnosis compared to INFO. It consists of all messages from INFO.
# INFO is a good default for most environments, but VERBOSE is more useful for troubleshooting.

# Task 5.1.16: Ensure sshd MaxAuthTries is configured
sed -i '/^MaxAuthTries/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i MaxAuthTries 4' /etc/ssh/sshd_config
# This means that users will have 4 attempts to authenticate before the SSH server will lock them out.

# Task 5.1.17: Ensure sshd MaxStartups is configured
sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
sed -i '/^Include/i MaxStartups 10:30:60' /etc/ssh/sshd_config
# Here:
#   10: Number of unauthenticated connections before we start dropping
#   30: Percentage chance of dropping once we reach 10 (increases linearly for more than 10)
#   60: Maximum number of connections at which we start dropping everything

# Task 5.1.18: Ensure sshd MaxSessions is configured 
sed -i '/^MaxSessions/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i MaxSessions 10' /etc/ssh/sshd_config
# This means that users will be able to open up to 10 SSH sessions at a time.

# Task 5.1.19: Ensure sshd PermitEmptyPasswords is disabled
sed -i '/^PermitEmptyPasswords/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i PermitEmptyPasswords no' /etc/ssh/sshd_config
# This means that users will not be able to log in with an empty password.

# Task 5.1.20: Ensure sshd PermitRootLogin is disabled
sed -i '/^PermitRootLogin/d' /etc/ssh/sshd_config
sed -i '/^Include\|^Match/i PermitRootLogin no' /etc/ssh/sshd_config
# This means that the root user will not be able to log in via SSH.

# Task 5.1.21: Ensure sshd PermitUserEnvironment is disabled 
sed -i '/^PermitUserEnvironment/d' /etc/ssh/sshd_config
sed -i '/^Include/i PermitUserEnvironment no' /etc/ssh/sshd_config
# This means that users will not be able to set environment variables when logging in via SSH.

# Task 5.1.22: Ensure sshd UsePAM is enabled
sed -i '/^UsePAM/d' /etc/ssh/sshd_config
sed -i '/^Include/i UsePAM yes' /etc/ssh/sshd_config
# This means that PAM (Pluggable Authentication Modules) will be used for authentication.

# Task 5.2.1: Ensure sudo is installed
dnf install sudo -y

# Task 5.2.2: Ensure sudo commands use pty
edit_sudoers_file() {
    local file="$1"

    cp "$file" "$file.bak"

    # Add Defaults use_pty if not present
    if ! grep -q "^Defaults use_pty" "$file"; then
        echo "Defaults use_pty" >> "$file"
    fi

    # Remove any occurrences of !use_pty
    sed -i '/^Defaults\s*!\s*use_pty/d' "$file"
}

# Edit the main sudoers file
echo "Editing /etc/sudoers"
if visudo -c -f /etc/sudoers >/dev/null 2>&1; then
    edit_sudoers_file /etc/sudoers
else
    echo "/etc/sudoers has syntax errors. Aborting."
fi

# Edit files in /etc/sudoers.d/
echo "Editing files in /etc/sudoers.d/"
for sudoers_file in /etc/sudoers.d/*; do
    if [ -f "$sudoers_file" ]; then
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            edit_sudoers_file "$sudoers_file"
        else
            echo "$sudoers_file has syntax errors. Skipping."
        fi
    fi
done

# Task 5.2.3: Ensure sudo log file exists
edit_sudoers_file() {
    local file="$1"
    local log_file_path="$2"

    cp "$file" "$file.bak"

    # Add Defaults logfile="<PATH TO CUSTOM LOG FILE>" if not present
    if ! grep -q "^Defaults logfile=" "$file"; then
        echo "Defaults logfile=\"$log_file_path\"" >> "$file"
    fi
}

LOG_FILE_PATH="/var/log/sudo.log"

# Edit the main sudoers file
echo "Editing /etc/sudoers"
if visudo -c -f /etc/sudoers >/dev/null 2>&1; then
    edit_sudoers_file /etc/sudoers "$LOG_FILE_PATH"
else
    echo "/etc/sudoers has syntax errors. Aborting."
fi

# Edit files in /etc/sudoers.d/
echo "Editing files in /etc/sudoers.d/"
for sudoers_file in /etc/sudoers.d/*; do
    if [ -f "$sudoers_file" ]; then
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            edit_sudoers_file "$sudoers_file" "$LOG_FILE_PATH"
        else
            echo "$sudoers_file has syntax errors. Skipping."
        fi
    fi
done

# Task 5.2.4: Ensure users must provide password for escalation
remove_nopasswd_lines() {
    local file="$1"

    cp "$file" "$file.bak"

    # Remove lines containing NOPASSWD
    sed -i '/NOPASSWD/d' "$file"
}

# Edit the main sudoers file
echo "Editing /etc/sudoers"
if visudo -c -f /etc/sudoers >/dev/null 2>&1; then
    remove_nopasswd_lines /etc/sudoers
else
    echo "/etc/sudoers has syntax errors. Aborting."
fi

# Edit files in /etc/sudoers.d/
echo "Editing files in /etc/sudoers.d/"
for sudoers_file in /etc/sudoers.d/*; do
    if [ -f "$sudoers_file" ]; then
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            remove_nopasswd_lines "$sudoers_file"
        else
            echo "$sudoers_file has syntax errors. Skipping."
        fi
    fi
done

# Task 5.2.5: Ensure re-authentication for privilege escalation is not disabled globally
remove_noauthenticate_lines() {
    local file="$1"

    cp "$file" "$file.bak"

    # Remove lines containing !authenticate
    sed -i '/!authenticate/d' "$file"
}

# Edit the main sudoers file
echo "Editing /etc/sudoers"
if visudo -c -f /etc/sudoers >/dev/null 2>&1; then
    remove_noauthenticate_lines /etc/sudoers
else
    echo "/etc/sudoers has syntax errors. Aborting."
fi

# Edit files in /etc/sudoers.d/
echo "Editing files in /etc/sudoers.d/"
for sudoers_file in /etc/sudoers.d/*; do
    if [ -f "$sudoers_file" ]; then
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            remove_noauthenticate_lines "$sudoers_file"
        else
            echo "$sudoers_file has syntax errors. Skipping."
        fi
    fi
done

# Task 5.2.6: Ensure sudo authentication timeout is configured correctly
set_timestamp_timeout() {
    local file="$1"

    # Make a backup of the file
    cp "$file" "$file.bak"

    # Ensure timestamp_timeout is set to 15 minutes
    sed -i -E 's/^Defaults\s+(.*timestamp_timeout=[0-9]+)?(.*)$/Defaults \1timestamp_timeout=15 \2/' "$file"

    # Remove any existing timestamp_timeout entries if they're not set to 15
    sed -i '/^Defaults\s*timestamp_timeout=[0-9]\+/d' "$file"

    # Add the timestamp_timeout setting at the end if not present
    if ! grep -q '^Defaults.*timestamp_timeout=15' "$file"; then
        echo "Defaults timestamp_timeout=15" >> "$file"
    fi
}

# Edit the main sudoers file
echo "Editing /etc/sudoers"
if visudo -c -f /etc/sudoers >/dev/null 2>&1; then
    set_timestamp_timeout /etc/sudoers
else
    echo "/etc/sudoers has syntax errors. Aborting."
fi

# Edit files in /etc/sudoers.d/
echo "Editing files in /etc/sudoers.d/"
for sudoers_file in /etc/sudoers.d/*; do
    if [ -f "$sudoers_file" ]; then
        if visudo -c -f "$sudoers_file" >/dev/null 2>&1; then
            set_timestamp_timeout "$sudoers_file"
        else
            echo "$sudoers_file has syntax errors. Skipping."
        fi
    fi
done

# Task 5.2.7: Ensure access to the su command is restricted
GROUP_NAME="root"
# Change group name if it doesnt match company policy.

# Create the empty group
if ! getent group "$GROUP_NAME" > /dev/null; then
    echo "Creating group $GROUP_NAME"
    groupadd "$GROUP_NAME"
else
    echo "Group $GROUP_NAME already exists"
fi

PAM_SU_FILE="/etc/pam.d/su"

# Add the PAM configuration line if not present
if ! grep -q "auth required pam_wheel.so use_uid group=$GROUP_NAME" "$PAM_SU_FILE"; then
    echo "Updating $PAM_SU_FILE"
    echo "auth required pam_wheel.so use_uid group=$GROUP_NAME" >> "$PAM_SU_FILE"
else
    echo "The PAM configuration line is already present in $PAM_SU_FILE"
fi

# Task 5.3.1.1: Ensure latest version of pam is installed
dnf upgrade pam -y

# Task 5.3.1.2: Ensure latest version of authselect is installed
dnf install authselect -y
dnf upgrade authselect -y

# Task 5.3.1.3: Ensure latest version of libpwquality is installed 
dnf install libpwquality -y
dnf upgrade libpwquality -y

# Task 5.3.2: Configure authselect
authselect create-profile custom-profile -b sssd

# Task 5.3.2.1: Ensure active authselect profile includes pam modules
authselect select custom/custom-profile --backup=PAM_CONFIG_BACKUP --force

# Task 5.3.2.2: Ensure pam_faillock module is enabled
l_module_name="faillock"

l_pam_profile=$(head -1 /etc/authselect/authselect.conf)

if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
    l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
    l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

check_pam_faillock() {
    grep -P -- "\bpam_$l_module_name\.so\b" "$l_pam_profile_path"/{password,system}-auth
}

output=$(check_pam_faillock)

if [[ -z "$output" ]]; then
    echo "pam_faillock.so lines not found in the authselect profile templates."
    echo "Refer to the Recommendation 'Ensure active authselect profile includes pam modules' to update the authselect profile template files."
elif grep -q '{include if "with-faillock"}' <<< "$output"; then
    echo "pam_faillock.so lines found with 'include if \"with-faillock\"'."
    echo "Enabling the 'with-faillock' feature and applying changes..."
    authselect enable-feature with-faillock
elif ! grep -q '{include if "with-faillock"}' <<< "$output"; then
    echo "pam_faillock.so lines found without 'include if \"with-faillock\"'."
    echo "Applying authselect changes..."
    authselect apply-changes
fi

# Task 5.3.2.3: Ensure pam_pwquality module is enabled
l_module_name="pwquality"

l_pam_profile=$(head -1 /etc/authselect/authselect.conf)

if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
    l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
    l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

check_pam_pwquality() {
    grep -P -- "\bpam_$l_module_name\.so\b" "$l_pam_profile_path"/{password,system}-auth
}

output=$(check_pam_pwquality)

if [[ -z "$output" ]]; then
    echo "pam_pwquality.so lines not found in the authselect profile templates."
    echo "Refer to the Recommendation 'Ensure active authselect profile includes pam modules' to update the authselect profile template files."
elif grep -q '{include if "with-pwquality"}' <<< "$output"; then
    echo "pam_pwquality.so lines found with 'include if \"with-pwquality\"'."
    echo "Enabling the 'with-pwquality' feature and applying changes..."
    authselect enable-feature with-pwquality
else
    echo "pam_pwquality.so lines found without 'include if \"with-pwquality\"'."
    echo "Applying authselect changes..."
    authselect apply-changes
fi

# Task 5.3.2.4: Ensure pam_pwhistory module is enabled
l_module_name="pwhistory"

l_pam_profile=$(head -1 /etc/authselect/authselect.conf)

if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
    l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
    l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

check_pam_pwhistory() {
    grep -P -- "\bpam_$l_module_name\.so\b" "$l_pam_profile_path"/{password,system}-auth
}

output=$(check_pam_pwhistory)

if [[ -z "$output" ]]; then
    echo "pam_pwhistory.so lines not found in the authselect profile templates."
    echo "Refer to the Recommendation 'Ensure active authselect profile includes pam modules' to update the authselect profile template files."
elif grep -q '{include if "with-pwhistory"}' <<< "$output"; then
    echo "pam_pwhistory.so lines found with 'include if \"with-pwhistory\"'."
    echo "Enabling the 'with-pwhistory' feature and applying changes..."
    authselect enable-feature with-pwhistory
else
    echo "pam_pwhistory.so lines found without 'include if \"with-pwhistory\"'."
    echo "Applying authselect changes..."
    authselect apply-changes
fi

# Task 5.3.2.5: Ensure pam_unix module is enabled
l_module_name="unix"

l_pam_profile=$(head -1 /etc/authselect/authselect.conf)

if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
    l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
    l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

check_pam_unix() {
    grep -P -- "\bpam_$l_module_name\.so\b" "$l_pam_profile_path"/{password,system}-auth
}

output=$(check_pam_unix)

if [[ -z "$output" ]]; then
    echo "pam_unix.so lines not found in the authselect profile templates."
    echo "Refer to the Recommendation 'Ensure active authselect profile includes pam modules' to update the authselect profile template files."
else
    echo "pam_unix.so lines found in the authselect profile templates."
    echo "No further action required if the arguments match your security requirements."
fi

# Task 5.3.3.1.1: Ensure password failed attempts lockout is configured
{
 for l_pam_file in system-auth password-auth; do
 l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
 sed -ri 's/(^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so.*)(\s+deny\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
 done
 authselect apply-changes
}
echo "deny=3" >> /etc/security/faillock.conf


# Task 5.3.3.1.2: Ensure password unlock time is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep -oP 'custom/\S+')/$l_pam_file"    
    if [[ -f "$l_authselect_file" ]]; then
        sed -ri 's/(^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so.*)(\s+unlock_time\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    else
        echo "File $l_authselect_file does not exist. Skipping..."
    fi
done
echo "unlock_time=900" >> /etc/security/faillock.conf

authselect apply-changes

# Task 5.3.3.1.3: Ensure password failed attempts lockout includes root account
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep -oP 'custom/\S+')/$l_pam_file"
        if [[ -f "$l_authselect_file" ]]; then
        sed -ri 's/(^\s*auth\s+(.*)\s+pam_faillock\.so.*)(\s+even_deny_root)(.*$)/\1\4/' "$l_authselect_file"
        sed -ri 's/(^\s*auth\s+(.*)\s+pam_faillock\.so.*)(\s+root_unlock_time\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    else
        echo "File $l_authselect_file does not exist. Skipping..."
    fi
done

echo "even_deny_root" >> /etc/security/faillock.conf
echo "root_unlock_time=60" >> /etc/security/faillock.conf

authselect apply-changes

# Task 5.3.3.2.1: Ensure password number of changed characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+difok\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

printf '\n%s' "difok = 2" >> /etc/security/pwquality.conf.d/50-pwdifok.conf

authselect apply-changes

# Task 5.3.3.2.2: Ensure password length is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+minlen\s*=\s*[0-9]+)(.*$)/\1\4/' "$l_authselect_file"
done

printf '\n%s' "minlen = 14" >> /etc/security/pwquality.conf.d/50-pwlength.conf

authselect apply-changes

# Task 5.3.3.2.3: Ensure password complexity is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+minclass\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+dcredit\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+ucredit\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+lcredit\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+ocredit\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

printf '%s\n' "dcredit = -1" "ucredit = -1" "ocredit = -1" "lcredit = -1" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf

authselect apply-changes

# Task 5.3.3.2.4: Ensure password same consecutive characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+maxrepeat\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

printf '\n%s' "maxrepeat = 3" >> /etc/security/pwquality.conf.d/50-pwrepeat.conf

authselect apply-changes

# Task 5.3.3.2.5: Ensure password maximum sequential characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+maxsequence\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

printf '\n%s' "maxsequence = 3" >> /etc/security/pwquality.conf.d/50-pwmaxsequence.conf

authselect apply-changes

# Task 5.3.3.2.6: Ensure password dictionary check is enabled
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+dictcheck\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

sed -ri 's/^\s*dictcheck\s*=/# &/' /etc/security/pwquality.conf/etc/security/pwquality.conf.d/*.conf

authselect apply-changes

# Task 5.3.3.2.7: Ensure password quality is enforced for the root user
printf '\n%s\n' "enforce_for_root" >> /etc/security/pwquality.conf.d/50-pwroot.conf

# Task 5.3.3.3.1: Ensure password history remember is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so.*)(\s+remember\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

echo "remember=24" >> /etc/security/pwhistory.conf

authselect apply-changes

# Task 5.3.3.3.2: Ensure password history is enforced for the root user 
echo "enforce_for_root" >> /etc/security/pwhistory.conf

# Task 5.3.3.3.3: Ensure pam_pwhistory includes use_authtok
l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
    l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
    l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi

grep -P -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' "$l_pam_profile_path"/{password,system}-auth

if [ $? -ne 0 ]; then
    for l_authselect_file in "$l_pam_profile_path"/password-auth "$l_pam_profile_path"/system-auth; do
        if grep -Pq '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' "$l_authselect_file"; then
            echo "- \"use_authtok\" is already set"
        else
            echo "- \"use_authtok\" is not set. Updating template"
            sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so\s+.*)$/& use_authtok/g' "$l_authselect_file"
        fi
    done
fi

authselect apply-changes

# Task 5.3.3.4.1: Ensure pam_unix does not include nullok
l_module_name="unix"
l_profile_name="$(head -1 /etc/authselect/authselect.conf)"
if [[ ! "$l_profile_name" =~ ^custom\/ ]]; then
  echo " - Follow Recommendation \"Ensure custom authselect profile is used\" and then return to this Recommendation"
else
  grep -P -- "\bpam_$l_module_name\.so\b" /etc/authselect/$l_profile_name/{password,system}-auth
fi

for l_pam_file in system-auth password-auth; do
  l_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
  sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+.*)(nullok)(\s*.*)$/\1\2\4/g' $l_file
done

authselect enable-feature without-nullok

authselect apply-changes

# Task 5.3.3.4.2: Ensure pam_unix does not include remember
l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
grep -P -- '^\h*password\h+([^#\n\r]+\h+)pam_unix\.so\b' "$l_pam_profile_path"/{password,system}-auth

l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
for l_authselect_file in "$l_pam_profile_path"/password-auth "$l_pam_profile_path"/system-auth; do
  sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+.*)(remember=[1-9][0-9]*)(\s*.*)$/\1\4/g' "$l_authselect_file"
done

authselect apply-changes

# Task 5.3.3.4.3 Ensure pam_unix includes a strong password hashing algorithm
l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
grep -P -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' "$l_pam_profile_path"/{password,system}-auth

l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
for l_authselect_file in "$l_pam_profile_path"/password-auth "$l_pam_profile_path"/system-auth; do
  if grep -Pq '^\h*password\h+()\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' "$l_authselect_file"; then
    echo "- A strong password hashing algorithm is correctly set"
  elif grep -Pq '^\h*password\h+()\h+pam_unix\.so\h+([^#\n\r]+\h+)?(md5|bigcrypt|sha256|blowfish)\b' "$l_authselect_file"; then
    echo "- A weak password hashing algorithm is set, updating to \"sha512\""
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+.*)(md5|bigcrypt|sha256|blowfish)(\s*.*)$/\1\4 sha512/g' "$l_authselect_file"
  else
    echo "No password hashing algorithm is set, updating to \"sha512\""
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+.*)$/& sha512/g' "$l_authselect_file"
  fi
done

authselect apply-changes

# Task 5.3.3.4.4: Ensure pam_unix includes use_authtok
l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
grep -P -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' "$l_pam_profile_path"/{password,system}-auth

l_pam_profile="$(head -1 /etc/authselect/authselect.conf)"
if grep -Pq -- '^custom\/' <<< "$l_pam_profile"; then
  l_pam_profile_path="/etc/authselect/$l_pam_profile"
else
  l_pam_profile_path="/usr/share/authselect/default/$l_pam_profile"
fi
for l_authselect_file in "$l_pam_profile_path"/password-auth "$l_pam_profile_path"/system-auth; do
  if grep -Pq '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?use_authtok\b' "$l_authselect_file"; then
    echo "- \"use_authtok\" is already set"
  else
    echo "- \"use_authtok\" is not set. Updating template"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+.*)$/& use_authtok/g' "$l_authselect_file"
  fi
done

authselect apply-changes

# Task 5.4.1.1: Ensure password expiration is configured
sed -ri 's/^PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS 365/' /etc/login.defs

#Task 5.4.1.2: Ensure minimum password days is configured
sed -ri 's/^PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS 1/' /etc/login.defs

# Task 5.4.1.3: Ensure password expiration warning days is configured
sed -ri 's/^PASS_WARN_AGE\s+.*/PASS_WARN_AGE 7/' /etc/login.defs
awk -F: '($2~/^\$.+\$/) {if($6 < 7)system ("chage --warndays 7 " $1)}' /etc/shadow

# Task 5.4.1.4: Ensure strong password hashing algorithm is configured
sed -ri 's/^ENCRYPT_METHOD\s+.*/ENCRYPT_METHOD YESCRYPT/' /etc/login.defs

# Task 5.4.1.5: Ensure inactive password lock is configured
#useradd -D -f 45
#awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)system ("chage --inactive 45 " $1)}' /etc/shadow

# Task 5.4.1.6: Ensure all users last password change date is in the past
while IFS= read -r l_user; do
    l_change=$(date -d "$(chage --list $l_user | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s)
    if [[ "$l_change" -gt "$(date +%s)" ]]; then
        echo "User: \"$l_user\" last password change was \"$(chage --list $l_user | grep '^Last password change' | cut -d: -f2)\""
        #usermod -L "$l_user"
        #chage -d 0 "$l_user"
    fi
done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)

# Task 5.4.2.1: Ensure root is the only UID 0 account
usermod -u 0 root

# Task 5.4.2.2: Ensure root is the only GID 0 account
usermod -g 0 root
groupmod -g 0 root

# Task 5.4.2.3: Ensure group root is the only GID 0 group
groupmod -g 0 root

# Task 5.4.2.4: Ensure root account access is controlled
#passwd root
#usermod -L root

# Task 5.4.2.5: Ensure root path integrity
root_path="/root/.bash_profile"

# Define a list of allowed directories for the PATH variable
allowed_dirs=("/usr/local/sbin" "/usr/local/bin" "/usr/sbin" "/usr/bin" "/sbin" "/bin")

check_and_correct_path() {
    local path=$1

    for dir in $(echo "$path" | tr ':' '\n'); do
        if [[ ! -d "$dir" ]]; then
            echo "Directory $dir is not valid. Please remove it from PATH."
        elif [[ ! -x "$dir" ]]; then
            echo "Directory $dir is not executable. Correcting permissions."
            chmod 755 "$dir"
        elif [[ ! "$(stat -c "%U" "$dir")" == "root" ]]; then
            echo "Directory $dir is not owned by root. Correcting ownership."
            chown root:root "$dir"
        fi
    done

    if echo "$path" | grep -q "^\." ; then
        echo "PATH contains the current working directory (.). Please remove it."
    fi

    if [[ "$path" == *":" ]]; then
        echo "PATH contains a trailing colon. Removing it."
        path=$(echo "$path" | sed 's/:$//')
    fi

    export PATH=$(printf "%s:" "${allowed_dirs[@]}")

    echo "Updating PATH in $root_path"
    sed -i "s|^PATH=.*|PATH=\"$PATH\"|" "$root_path"
}

current_path=$(grep '^PATH=' "$root_path" | cut -d'=' -f2-)
check_and_correct_path "$current_path"

# Task 5.4.2.6: Ensure root user umask is configured
files=("/root/.bash_profile" "/root/.bashrc")

update_umask() {
    local file=$1

    cp "$file" "$file.bak"

    # Check if the file contains a umask setting
    if grep -E '^umask\s+' "$file" > /dev/null; then
        echo "Updating umask in $file"

        # Comment out or update umask settings
        sed -i '/^umask\s\+/s/^/#/' "$file"  # Comment out existing umask settings
        echo "umask 0027" >> "$file"         # Append new umask setting
    fi
}

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        update_umask "$file"
    else
        echo "File $file not found"
    fi
done

# Task 5.4.2.7: Ensure system accounts do not have a valid login shell
valid_shells="^($( awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"

min_uid=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

awk -v pat="$valid_shells" -F: \
'($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ && ($3 < '"$min_uid"' || $3 == 65534) && $(NF) ~ pat) \
{system("usermod -s '"$(command -v nologin)"' " $1)}' /etc/passwd

# Task 5.4.2.8: Ensure accounts without a valid login shell are locked 
valid_shells="^($( awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"

while IFS= read -r user; do
    passwd -S "$user" | awk '$2 !~ /^L/ {system("usermod -L " $1)}'
done < <(awk -v pat="$valid_shells" -F: '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)

# Task 5.4.3.1: Ensure nologin is not listed in /etc/shells
sed -i '/nologin/d' /etc/shells

# Task 5.4.3.2: Ensure default user shell timeout is configured
for file in /etc/bashrc /etc/profile /etc/profile.d/*.sh; do
    if grep -q 'TMOUT=' "$file"; then
        sed -i '/TMOUT=/d' "$file"
    fi
done

printf '%s\n' "# Set TMOUT to 900 seconds" "typeset -xr TMOUT=900" > /etc/profile.d/50-tmout.sh

# Task 5.4.3.3: Ensure default user umask is configured
file_umask_chk() {
    if grep -Psiq -- '^\s*umask\s+(0?[0-7][2-7]7|u(=[rwx]{0,3}),g=([rx]{0,2}),o=)(\s*#.*)?$' "$l_file"; then
        l_out="$l_out\n - umask is set correctly in \"$l_file\""
    elif grep -Psiq -- '^\s*umask\s+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b)|([0-7][01][0-7]\b|[0-7][0-7][0-6]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' "$l_file"; then
        l_output2="$l_output2\n - \"$l_file\""
    fi
}

l_output=""
l_output2=""
l_out=""

while IFS= read -r -d $'\0' l_file; do
    file_umask_chk
done < <(find /etc/profile.d/ -type f -name '*.sh' -print0)

for l_file in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/pam.d/postlogin /etc/login.defs /etc/default/login; do
    file_umask_chk
done

if [ -z "$l_output2" ]; then
    echo -e " - No files contain a UMASK that is not restrictive enough\nNo UMASK updates required to existing files"
else
    echo -e "\n - UMASK is not restrictive enough in the following file(s):$l_output2\n\n- Remediation Procedure:\n - Update these files and comment out the UMASK line\n or update umask to be \"0027\" or more restrictive"
fi

if [ -n "$l_output" ]; then
    echo -e "$l_output"
else
    echo -e " - Configure UMASK in a file in the \"/etc/profile.d/\" directory ending in \".sh\"\n\n Example Command:\n\n# printf '%s\\n' \"umask 027\" > /etc/profile.d/50-systemwide_umask.sh\n"
fi

### Written By: 
###     1. Aditi Jamsandekar
###     2. Siddhi Jani
###     3. Chirayu Rathi
############################
