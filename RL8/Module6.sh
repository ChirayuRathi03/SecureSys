#!/usr/bin/env bash

# Task 6.1.1: Ensure permissions on /etc/passwd are configured
chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd

# Task 6.1.2: Ensure permissions on /etc/passwd- are configured
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/passwd-

# Task 6.1.3: Ensure permissions on /etc/group are configured
chmod u-x,go-wx /etc/group
chown root:root /etc/group

# Task 6.1.4: Ensure permissions on /etc/group- are configured
chmod u-x,go-wx /etc/group-
chown root:root /etc/group-

# Task 6.1.5: Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chmod 0000 /etc/shadow

# Task 6.1.6: Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chmod 0000 /etc/shadow-

# Task 6.1.7: Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow
chmod 0000 /etc/gshadow

# Task 6.1.8: Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chmod 0000 /etc/gshadow-

# Task 6.1.9: Ensure permissions on /etc/shells are configured
chmod u-x,go-wx /etc/shells
chown root:root /etc/shells

# Task 6.1.10: Ensure permissions on /etc/security/opasswd are configured
[ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
[ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd
[ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
[ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old

echo "10"

# Task 6.1.11: Ensure world writable files and directories are secured
sticky_bit_mask='01000'
exclude_paths=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

while IFS= read -r mount_point; do
    while IFS= read -r -d $'\0' file; do
        if [ -e "$file" ]; then
            mode="$(stat -Lc '%#a' "$file")"
            if [ -f "$file" ]; then
                chmod o-w "$file"
            fi
            if [ -d "$file" ]; then
                if [ ! $(( mode & sticky_bit_mask )) -gt 0 ]; then
                    chmod a+t "$file"
                fi
            fi
        fi
    done < <(find "$mount_point" -xdev \( "${exclude_paths[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2> /dev/null)
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')

# Task 6.1.12: Ensure no files or directories without an owner and a group exist
exclude_paths=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")

while IFS= read -r mount_point; do
    find "$mount_point" -xdev \( "${exclude_paths[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
        if [ -e "$file" ]; then
            echo "Fixing ownership for: $file"
            chown root:root "$file"
        fi
    done
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

# Task 6.1.13: Ensure SUID and SGID files are reviewed (Manual)

# Task 6.2.1: Ensure accounts in /etc/passwd use shadowed passwords
pwconv

# Task 6.2.2: Ensure /etc/shadow password fields are not empty
lock_empty_password_accounts() {
    excluded_users="root bin daemon sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve systemd-timesync messagebus syslog _apt"

    empty_password_users=$(awk -F: '($2 == "" && $3 >= 1000) { print $1 }' /etc/shadow | grep -Ev "^($excluded_users)$")

    if [ -n "$empty_password_users" ]; then
        echo "The following user accounts have an empty password and will be locked:"
        echo "$empty_password_users"

        for user in $empty_password_users; do
            passwd -l "$user"
            echo "Account $user has been locked."

            if who | grep -qw "$user"; then
                echo "User $user is currently logged in. Investigate further to determine if they should be forced off."
            fi
        done
    else
        echo "All non-system accounts have passwords set. No empty password fields found in /etc/shadow."
    fi
}

lock_empty_password_accounts

# Task 6.2.3: Ensure all groups in /etc/passwd exist in /etc/group
create_missing_groups() {
    passwd_group_gids=($(awk -F: '{print $4}' /etc/passwd | sort -u))

    group_gids=($(awk -F: '{print $3}' /etc/group | sort -u))

    missing_gids=($(comm -23 <(printf "%s\n" "${passwd_group_gids[@]}" | sort) <(printf "%s\n" "${group_gids[@]}" | sort)))

    if [ ${#missing_gids[@]} -eq 0 ]; then
        echo "All groups in /etc/passwd exist in /etc/group. No action needed."
    else
        echo "The following GIDs are missing in /etc/group and will be created:"
        for gid in "${missing_gids[@]}"; do
            users=$(awk -F: '($4 == '"$gid"') {print $1}' /etc/passwd | xargs)
            
            group_name=$(awk -F: '($4 == '"$gid"') {print $1}' /etc/passwd | head -n 1)
            groupadd -g "$gid" "$group_name"
            echo "Group \"$group_name\" with GID \"$gid\" created for user(s): $users"
        done
    fi
}

create_missing_groups

# Task 6.2.4: Ensure no duplicate UIDs exist
while read -r count uid; do
    if [ "$count" -gt 1 ]; then
        users=($(awk -F: '($3 == '"$uid"') {print $1}' /etc/passwd))
        base_user=${users[0]}
        for ((i=1; i<${#users[@]}; i++)); do
            usermod -u "$(id -u "$base_user")" "${users[$i]}"
        done
    fi
done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

# Task 6.2.5 Ensure no duplicate GIDs exist
while read -r count gid; do
    if [ "$count" -gt 1 ]; then
        groups=($(awk -F: -v gid="$gid" '($3 == gid) {print $1}' /etc/group))
        base_group=${groups[0]}
        base_gid=$(grep "^${base_group}:" /etc/group | cut -d: -f3)
        
        for ((i=1; i<${#groups[@]}; i++)); do
            new_gid=$(awk -F: '{print $3}' /etc/group | sort -n | awk '{if (NR>1 && $1!=last+1) {print last+1} last=$1}' | head -n 1)
            if [ -z "$new_gid" ]; then
                new_gid=$(($(awk -F: '{print $3}' /etc/group | sort -n | tail -n 1) + 1))
            fi
            
            groupmod -g "$new_gid" "${groups[$i]}"
            
            find / -group "$gid" -exec chgrp "$new_gid" {} +
        done
    fi
done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

# Task 6.2.6: Ensure no duplicate user names exist
while read -r count user; do
    if [ "$count" -gt 1 ]; then
        uids=($(awk -F: -v user="$user" '($1 == user) {print $3}' /etc/passwd))
        
        base_uid=${uids[0]}
        base_user=$(grep "^${base_uid}:" /etc/passwd | cut -d: -f1)
        
        for ((i=1; i<${#uids[@]}; i++)); do
            new_user=$(grep "^${uids[$i]}:" /etc/passwd | cut -d: -f1)
            
            new_user=$(echo "$new_user" | awk '{print $0 "_dup"}')
            
            usermod -l "$new_user" "${uids[$i]}"
            
            find / -user "${uids[$i]}" -exec chown "$new_user" {} +
        done
    fi
done < <(cut -f1 -d":" /etc/passwd | sort | uniq -c)

# Task 6.2.7: Ensure no duplicate group names exist
while read -r count group; do
    if [ "$count" -gt 1 ]; then
        gids=($(awk -F: -v group="$group" '($1 == group) {print $3}' /etc/group))
        
        base_gid=${gids[0]}
        base_group=$(grep "^${base_gid}:" /etc/group | cut -d: -f1)
        
        for ((i=1; i<${#gids[@]}; i++)); do
            new_group=$(grep "^${gids[$i]}:" /etc/group | cut -d: -f1)
            
            new_group=$(echo "$new_group" | awk '{print $0 "_dup"}')
            
            groupmod -n "$new_group" "${gids[$i]}"
            
            find / -group "${gids[$i]}" -exec chgrp "$new_group" {} +
        done
    fi
done < <(cut -f1 -d":" /etc/group | sort | uniq -c)

echo "20"

# Task 6.2.8: Ensure local interactive user home directories are configured
output=""
valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
unset user_array && user_array=()

while read -r username home_dir; do
  user_array+=("$username $home_dir")
done <<< "$(awk -v pattern="$valid_shells" -F: '$(NF) ~ pattern { print $1 " " $(NF-1) }' /etc/passwd)"

total_users="${#user_array[@]}"
[ "$total_users" -gt "10000" ] && echo -e "\n ** INFO **\n - \"$total_users\" Local interactive users found on the system\n - This may be a long running process\n"

while read -r user home_dir; do
  if [ -d "$home_dir" ]; then
    permission_mask='0027'
    max_permissions="$(printf '%o' $((0777 & ~permission_mask)))"
    while read -r owner mode; do
      if [ "$user" != "$owner" ]; then
        output="$output\n - User: \"$user\" Home \"$home_dir\" is owned by: \"$owner\"\n - changing ownership to: \"$user\"\n"
        chown "$user" "$home_dir"
      fi
      if [ $((mode & permission_mask)) -gt 0 ]; then
        output="$output\n - User: \"$user\" Home \"$home_dir\" is mode: \"$mode\" should be mode: \"$max_permissions\" or more restrictive\n - removing excess permissions\n"
        chmod g-w,o-rwx "$home_dir"
      fi
    done <<< "$(stat -Lc '%U %#a' "$home_dir")"
  else
    output="$output\n - User: \"$user\" Home \"$home_dir\" Doesn't exist\n - Please create a home in accordance with local site policy"
  fi
done <<< "$(printf '%s\n' "${user_array[@]}")"

if [ -z "$output" ]; then
  echo -e " - No modification needed to local interactive users' home directories"
else
  echo -e "\n$output"
fi

# Task 6.2.9: Ensure local interactive user dot files access is configured
output2=()
output3=()
max_users="1000"
valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
user_home=()

while read -r user home; do
  [[ -n "$user" && -n "$home" ]] && user_home+=("$user:$home")
done <<< "$(awk -v pattern="$valid_shells" -F: '$(NF) ~ pattern { print $1 " " $(NF-1) }' /etc/passwd)"

num_users="${#user_home[@]}"
[ "${#user_home[@]}" -gt "$max_users" ] && printf '%s\n' "" " ** INFO **" \
  " - \"$num_users\" Local interactive users found on the system" \
  " - This may be a long running check" ""

fix_file_access() {
  local access_output=()
  max_mode="$(printf '%o' $((0777 & ~mask)))"
  
  if [ $((mode & mask)) -gt 0 ]; then
    printf '%s\n' "" " - File: \"$file\" is mode: \"$mode\" and should be mode: \"$max_mode\" or more restrictive" \
      " Updating file: \"$file\" to be mode: \"$max_mode\" or more restrictive"
    chmod "$change" "$file"
  fi
  
  if [[ ! "$owner" =~ ($user) ]]; then
    printf '%s\n' "" " - File: \"$file\" owned by: \"$owner\" and should be owned by \"$user\"" \
      " Updating file: \"$file\" to be owned by \"$user\""
    chown "$user" "$file"
  fi
  
  if [[ ! "$group_owner" =~ ($group) ]]; then
    printf '%s\n' "" " - File: \"$file\" group owned by: \"$group_owner\" and should be group owned by \"$group\"" \
      " Updating file: \"$file\" to be group owned by \"$group\""
    chgrp "$group" "$file"
  fi
}

while IFS=: read -r user home; do
  dot_files=()
  netrc_files=()
  netrc_warning=()
  
  if [ -d "$home" ]; then
    group="$(id -gn "$user" | xargs)"
    group="${group// /|}"
    
    while IFS= read -r -d $'\0' file; do
      while read -r mode owner group_owner; do
        case "$(basename "$file")" in
          .forward | .rhost )
            dot_files+=(" - File: \"$file\" exists" "Please review and manually delete this file") ;;
          .netrc )
            mask='0177'; change="u-x,go-rwx"; fix_file_access
            netrc_warning+=(" - File: \"$file\" exists") ;;
          .bash_history )
            mask='0177'; change="u-x,go-rwx"; fix_file_access ;;
          * )
            mask='0133'; change="u-x,go-wx"; fix_file_access ;;
        esac
      done < <(stat -Lc '%#a %U %G' "$file")
    done < <(find "$home" -xdev -type f -name '.*' -print0)
  fi
  
  [ "${#dot_files[@]}" -gt 0 ] && output2+=(" - User: \"$user\" Home Directory: \"$home\"" "${dot_files[@]}")
  [ "${#netrc_warning[@]}" -gt 0 ] && output3+=(" - User: \"$user\" Home Directory: \"$home\"" "${netrc_warning[@]}")
done <<< "$(printf '%s\n' "${user_home[@]}")"

[ "${#output3[@]}" -gt 0 ] && printf '%s\n' "" " ** WARNING **" "${output3[@]}" ""
[ "${#output2[@]}" -gt 0 ] && printf '%s\n' "" "${output2[@]}"

echo "done"

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################