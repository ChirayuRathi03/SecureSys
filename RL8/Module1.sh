#!/usr/bin/env bash

f_module_setup_filesystems() {
  local mod_name="$1"
  local config_file="$2"

  echo "Processing filesystem module: \"$mod_name\""

  # Remove the module if loaded
  if lsmod | grep "$mod_name" &> /dev/null; then
    echo "Removing loaded kernel module: \"$mod_name\""
    modprobe -r "$mod_name" 2>/dev/null
    rmmod "$mod_name" 2>/dev/null
  fi

  # Create configuration file if it doesn't exist and add commands to  disable the module
  touch "$config_file"
  if ! grep -q "install $mod_name /bin/false" "$config_file" 2>/dev/null; then
    echo "install $mod_name /bin/false" >> "$config_file"
  fi

  if ! grep -q "blacklist $mod_name" "$config_file" 2>/dev/null; then
    echo "blacklist $mod_name" >> "$config_file"
  fi

  echo "Module \"$mod_name\" setup complete."
}

f_module_setup_drivers() {
  local mod_name="$1"
  local config_file="$2"

  echo "Processing driver module: \"$mod_name\""

  # Remove the module if loaded
  if lsmod | grep "$mod_name" &> /dev/null; then
    echo "Removing loaded kernel module: \"$mod_name\""
    modprobe -r "$mod_name" 2>/dev/null
    rmmod "$mod_name" 2>/dev/null
  fi

  # Create configuration file if it doesn't exist and add commands to  disable the module
  touch "$config_file"
  if ! grep -q "install $mod_name /bin/false" "$config_file" 2>/dev/null; then
    echo "install $mod_name /bin/false" >> "$config_file"
  fi

  if ! grep -q "blacklist $mod_name" "$config_file" 2>/dev/null; then
    echo "blacklist $mod_name" >> "$config_file"
  fi

  echo "Module \"$mod_name\" setup complete."
}

# Task 1.1.1.1: Ensure "cramfs" kernel module is not available
f_module_setup_filesystems "cramfs" "/etc/modprobe.d/disable-cramfs.conf"

# Task 1.1.1.2: Ensure "freevxfs" kernel module is not available
f_module_setup_filesystems "freevxfs" "/etc/modprobe.d/disable-freevxfs.conf"

# Task 1.1.1.3: Ensure "hfs" kernel module is not available
f_module_setup_filesystems "hfs" "/etc/modprobe.d/disable-hfs.conf"

# Task 1.1.1.4: Ensure "hfsplus" kernel module is not available
f_module_setup_filesystems "hfsplus" "/etc/modprobe.d/disable-hfsplus.conf"

# Task 1.1.1.5: Ensure "jffs2" kernel module is not available
f_module_setup_filesystems "jffs2" "/etc/modprobe.d/disable-jffs2.conf"

# Task 1.1.1.6: Ensure "squashfs" kernel module is not available
f_module_setup_filesystems "squashfs" "/etc/modprobe.d/disable-squashfs.conf"

# Task 1.1.1.7: Ensure "udf" kernel module is not available
f_module_setup_drivers "udf" "/etc/modprobe.d/disable-udf.conf"

# Task 1.1.1.8: Ensure "usb-storage" kernel module is not available
f_module_setup_drivers "usb-storage" "/etc/modprobe.d/disable-usb-storage.conf"

# Task 1.2.2: Ensure gpgcheck is globally activated
sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' {} \;

# Task 1.2.3: Ensure repo_gpgcheck is globally activated
DNF_CONF="/etc/dnf/dnf.conf"
SETTING="repo_gpgcheck=1"

if grep -q "^repo_gpgcheck=" "$DNF_CONF"; then
  # Update if it exists
  sed -i "s/^repo_gpgcheck=.*/$SETTING/" "$DNF_CONF"
else
  # add if it doesnt exist
  sed -i "/^\[main\]/a $SETTING" "$DNF_CONF"
fi

echo "Set $SETTING in $DNF_CONF"

# Task 1.2.4: Ensure package manager repositories are configured (Manual)

# Task 1.2.5: Ensure updates, patches, and additional security software are installed
dnf update

# Task 1.3.1: Ensure bootloader password is set
grub2-setpassword

# Task 1.3.2: Ensure permissions on bootloader are configured
configure_system() {
  if [ -d /boot/efi ]; then
    if mountpoint -q /boot/efi; then
      cp /etc/fstab /etc/fstab.bak

      if grep -q '^/boot/efi' /etc/fstab; then
        sed -i 's|^/boot/efi.*|/boot/efi vfat defaults,umask=0027,fmask=0077,uid=0,gid=0 0 0|' /etc/fstab
      else
        echo '/boot/efi vfat defaults,umask=0027,fmask=0077,uid=0,gid=0 0 0' >> /etc/fstab
      fi
    else
      grep '/boot/efi' /etc/fstab || echo "No entry found for /boot/efi in /etc/fstab."
    fi
  fi

  if [ -d /boot/grub2 ]; then
    [ -f /boot/grub2/grub.cfg ] && chown root:root /boot/grub2/grub.cfg && chmod u-x,go-rwx /boot/grub2/grub.cfg
    [ -f /boot/grub2/grubenv ] && chown root:root /boot/grub2/grubenv && chmod u-x,go-rwx /boot/grub2/grubenv
    [ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg && chmod u-x,go-rwx /boot/grub2/user.cfg
  fi

  if [ ! -d /boot/efi ] && [ ! -d /boot/grub2 ]; then
    echo "Neither /boot/efi nor /boot/grub2 directories found. Unable to determine system type."
  fi
}

configure_system

# Task 1.4.1: Ensure address space layout randomization is enabled
printf "
kernel.randomize_va_space = 2
" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.randomize_va_space=2

# Task 1.4.2: Ensure ptrace_scope is restricted
printf "
kernel.yama.ptrace_scope = 1
" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.yama.ptrace_scope=1

# Task 1.4.3: Ensure core dump backtraces are disabled
{
  [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir /etc/systemd/coredump.conf.d/
  if grep -Psq -- '^\h*\[Coredump\]' /etc/systemd/coredump.conf.d/60-coredump.conf; then
    printf '%s\n' "ProcessSizeMax=0" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  else
    printf '%s\n' "[Coredump]" "ProcessSizeMax=0" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  fi
}

# Task 1.4.4: Ensure core dump storage is disabled
{
  [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir /etc/systemd/coredump.conf.d/
  if grep -Psq -- '^\h*\[Coredump\]' /etc/systemd/coredump.conf.d/60-coredump.conf; then
    printf '%s\n' "Storage=none" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  else
    printf '%s\n' "[Coredump]" "Storage=none" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  fi
}

# Task 1.5.1.1: Ensure SELinux is installed
dnf install libselinux -y

# Task 1.5.1.2: Ensure SELinux is not disabled in bootloader configuration
grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
grep -Psrq 'kernelopts=.*\b(selinux|enforcing)=0\b' /boot/grub2 /boot/efi
if [ $? -eq 0 ]; then
  grub2-mkconfig -o "$(grep -Prl 'kernelopts=.*\b(selinux|enforcing)=0\b' /boot/grub2 /boot/efi)"
fi

# Task 1.5.1.3: Ensure SELinux policy is configured
SELINUXTYPE=targeted

# Task 1.5.1.4: Ensure the SELinux mode is not disabled
# For 'enforcing' mode
setenforce 1 
SELINUX=enforcing

# For 'permissive' mode
#setenforce 0
#SELINUX=permissive
# Difference between the 2: Enforcing blocks and logs unauthorized actions whereas Permissive allows unauthorized actions but logs them.

# Task 1.5.1.5: Ensure the SELinux mode is enforcing
setenforce 1 
SELINUX=enforcing

# Task 1.5.1.6: Ensure no unconfined services exist (Manual)

# Task 1.5.1.7: Ensure the MCS Translation Service (mcstrans) is not installed
dnf remove mcstrans -y

# Task 1.5.1.8: Ensure the SETroubleshoot is not installed
dnf remove setroubleshoot -y

# Task 1.6.1: Ensure system wide crypto policy is not set to legacy
update-crypto-policies --set DEFAULT
update-crypto-policies
# If FIPS is required
#fips-mode-setup --enable

# Task 1.6.2: Ensure system wide crypto policy disables sha1 hash and signature support
printf '%s\n' "hash = -SHA1" "sign = -*-SHA1" "sha1_in_certs = 0" >> /etc/crypto-policies/policies/modules/NO-SHA1.pmod
update-crypto-policies --set DEFAULT:NO-SHA1

# Task 1.6.3: Ensure system wide crypto policy disables cbc for ssh
printf '%s\n' "cipher@SSH = -*-CBC" >> /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC

# Task 1.6.4: Ensure system wide crypto policy disables macs less than 128 bits
printf '%s\n' "mac = -*-64" >> /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-SSHCBC:NO-WEAKMAC

# Task 1.7.1: Ensure message of the day is configured properly
{
  a_files=()
  for l_file in /etc/motd{,.d/*}; do
    if grep -Psqi -- "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release | cut -d= -f2 | sed -e 's/"//g')\b)" "$l_file"; then
      echo -e "\n - File: \"$l_file\" includes system information. Edit this file to remove these entries"
    else
      a_files+=("$l_file")
    fi
  done
  if [ "${#a_files[@]}" -gt 0 ]; then
    echo -e "\n- ** Please review the following files and verify their contents follow local site policy **\n"
    printf '%s\n' "${a_files[@]}"
  fi
}

# Task 1.7.2: Ensure local login warning banner is configured properly
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue 
# Edit this message based on company policies.

# Task 1.7.3: Ensure remote login warning banner is configured properly
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net
# Edit this message based on company policies.

# Task 1.7.4: Ensure access to /etc/motd is configured
chown root:root $(readlink -e /etc/motd)
chmod u-x,go-wx $(readlink -e /etc/motd)

# Task 1.7.5: Ensure access to /etc/issue is configured
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)

# Task 1.7.6: Ensure access to /etc/issue.net is configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

# Task 1.8.1: Ensure GNOME Display Manager is removed
#dnf remove gdm

# Task 1.8.2: Ensure GDM login banner is configured
l_pkgoutput=""
if command -v dpkg-query > /dev/null 2>&1; then
  l_pq="dpkg-query -W"
elif command -v rpm > /dev/null 2>&1; then
  l_pq="rpm -q"
fi

l_pcl="gdm gdm3"
for l_pn in $l_pcl; do
  if $l_pq "$l_pn" > /dev/null 2>&1; then
    l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
  fi
done

if [ -n "$l_pkgoutput" ]; then
  l_gdmprofile="gdm"
  l_bmessage="'Authorized uses only. All activity may be monitored and reported'"

  # Ensure dconf profile exists
  if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
    echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfiledb:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
  fi

  # Ensure dconf database directory exists
  [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ] && mkdir /etc/dconf/db/$l_gdmprofile.d/

  l_kfile="/etc/dconf/db/$l_gdmprofile.d/01-banner-message"

  # Create or update keyfile
  if ! grep -Pq '^\[org/gnome/login-screen\]' "$l_kfile" || ! grep -Pq 'banner-message-enable=true' "$l_kfile"; then
    echo -e "[org/gnome/login-screen]\nbanner-message-enable=true" > "$l_kfile"
  fi

  # Add banner message text if not already present
  if ! grep -Pq 'banner-message-text=' "$l_kfile"; then
    echo -e "\nbanner-message-text=$l_bmessage" >> "$l_kfile"
  fi

  dconf update
else
  echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n - No remediation required\n"
fi

# Task 1.8.3: Ensure GDM disable-user-list option is enabled
l_gdmprofile="gdm"
profile_file="/etc/dconf/profile/$l_gdmprofile"
db_dir="/etc/dconf/db/$l_gdmprofile.d/"
keyfile="$db_dir/00-loginscreen"

# Create profile if it does not exist
if [ ! -f "$profile_file" ]; then
  echo "Creating profile \"$l_gdmprofile\""
  echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfiledb:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > "$profile_file"
fi

# Create dconf database directory if it does not exist
if [ ! -d "$db_dir" ]; then
  echo "Creating dconf database directory \"$db_dir\""
  mkdir -p "$db_dir"
fi

# Check for the presence of the keyfile and the necessary settings
if ! grep -Pq '^\s*disable-user-list\s*=\s*true\b' "$keyfile" 2>/dev/null; then
  echo "Creating gdm keyfile for machine-wide settings"

  # Create or append to the keyfile
  if ! grep -Pq '^\s*\[org/gnome/login-screen\]' "$keyfile" 2>/dev/null; then
    echo -e "[org/gnome/login-screen]\n# Do not show the user list\ndisable-user-list=true" > "$keyfile"
  else
    sed -i '/^\s*\[org\/gnome\/login-screen\]/a\# Do not show the user list\ndisable-user-list=true' "$keyfile"
  fi
fi

dconf update

# Task 1.8.4: Ensure GDM screen locks when the user is idle
{
 l_key_file="/etc/dconf/db/local.d/00-screensaver"
 l_idmv="900" # Set max value for idle-delay in seconds (between 1 and 900)
 l_ldmv="5" # Set max value for lock-delay in seconds (between 0 and 5)
 {
 echo '# Specify the dconf path'
 echo '[org/gnome/desktop/session]'
 echo ''
 echo '# Number of seconds of inactivity before the screen goes blank'
 echo '# Set to 0 seconds if you want to deactivate the screensaver.'
 echo "idle-delay=uint32 $l_idmv"
 echo ''
 echo '# Specify the dconf path'
 echo '[org/gnome/desktop/screensaver]'
 echo ''
 echo '# Number of seconds after the screen is blank before locking the
screen'
 echo "lock-delay=uint32 $l_ldmv"
 } > "$l_key_file"
}

# Task 1.8.5: Ensure GDM screen locks cannot be overridden
{
 # Check if GNMOE Desktop Manager is installed. If package isn't installed, recommendation is
Not Applicable\n
 # determine system's package manager
 l_pkgoutput=""
 if command -v dpkg-query > /dev/null 2>&1; then
 l_pq="dpkg-query -W"
 elif command -v rpm > /dev/null 2>&1; then
 l_pq="rpm -q"
 fi
 # Check if GDM is installed
 l_pcl="gdm gdm3" # Space separated list of packages to check
 for l_pn in $l_pcl; do
 $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y" && echo -e "\n - Package: \"$l_pn\"
exists on the system\n - remediating configuration if needed"
 done
 # Check configuration (If applicable)
 if [ -n "$l_pkgoutput" ]; then
 # Look for idle-delay to determine profile in use, needed for remaining tests
 l_kfd="/etc/dconf/db/$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ |
awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked
 # Look for lock-delay to determine profile in use, needed for remaining tests
 l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/
| awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked
 if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked
 if grep -Prilq '^\h*\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"; then
 echo " - \"idle-delay\" is locked in \"$(grep -Pril
'^\h*\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd")\""
 else
 echo "creating entry to lock \"idle-delay\""
 [ ! -d "$l_kfd"/locks ] && echo "creating directory $l_kfd/locks" && mkdir
"$l_kfd"/locks
 {
 echo -e '\n# Lock desktop screensaver idle-delay setting'
 echo '/org/gnome/desktop/session/idle-delay'
 } >> "$l_kfd"/locks/00-screensaver
 fi
 else
 echo -e " - \"idle-delay\" is not set so it can not be locked\n - Please follow
Recommendation \"Ensure GDM screen locks when the user is idle\" and follow this Recommendation
again"
 fi
 if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked
 if grep -Prilq '^\h*\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"; then
 echo " - \"lock-delay\" is locked in \"$(grep -Pril
'^\h*\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2")\""
 else
 echo "creating entry to lock \"lock-delay\""
 [ ! -d "$l_kfd2"/locks ] && echo "creating directory $l_kfd2/locks" && mkdir
"$l_kfd2"/locks
 {
 echo -e '\n# Lock desktop screensaver lock-delay setting'
 echo '/org/gnome/desktop/screensaver/lock-delay'
 } >> "$l_kfd2"/locks/00-screensaver
 fi
 else
 echo -e " - \"lock-delay\" is not set so it can not be locked\n - Please follow
Recommendation \"Ensure GDM screen locks when the user is idle\" and follow this Recommendation
again"
 fi
 else
 echo -e " - GNOME Desktop Manager package is not installed on the system\n -
Recommendation is not applicable"
 fi
}

# Task 1.8.6: Ensure GDM automatic mounting of removable media is disabled
{
  l_pkgoutput=""
  l_gpname="local"

  if command -v dpkg-query > /dev/null 2>&1; then
    l_pq="dpkg-query -W"
  elif command -v rpm > /dev/null 2>&1; then
    l_pq="rpm -q"
  fi

  l_pcl="gdm gdm3"
  for l_pn in $l_pcl; do
    $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
  done

  if [ -n "$l_pkgoutput" ]; then
    echo -e "$l_pkgoutput"

    # Look for existing settings and set variables if they exist
    l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
    l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"

    # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
    if [ -f "$l_kfile" ]; then
      l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
      echo " - updating dconf profile name to \"$l_gpname\""
    elif [ -f "$l_kfile2" ]; then
      l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")"
      echo " - updating dconf profile name to \"$l_gpname\""
    fi

    # check for consistency
    if [ -f "$l_kfile" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" != "$l_gpname" ]; then
      sed -ri "/^\s*automount\s*=/s/^/# /" "$l_kfile"
      l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"
    fi
    if [ -f "$l_kfile2" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")" != "$l_gpname" ]; then
      sed -ri "/^\s*automount-open\s*=/s/^/# /" "$l_kfile2"
    fi
    [ -z "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-mediaautomount"

    # Check if profile file exists
    if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
      echo -e "\n - dconf database profile exists in: \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\""
    else
      if [ ! -f "/etc/dconf/profile/user" ]; then
        l_gpfile="/etc/dconf/profile/user"
      else
        l_gpfile="/etc/dconf/profile/user2"
      fi
      echo -e " - creating dconf database profile"
      {
        echo -e "\nuser-db:user"
        echo "system-db:$l_gpname"
      } >> "$l_gpfile"
    fi

    # create dconf directory if it doesn't exists
    l_gpdir="/etc/dconf/db/$l_gpname.d"
    if [ -d "$l_gpdir" ]; then
      echo " - The dconf database directory \"$l_gpdir\" exists"
    else
      echo " - creating dconf database directory \"$l_gpdir\""
      mkdir "$l_gpdir"
    fi

    # check automount-open setting
    if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile"; then
      echo " - \"automount-open\" is set to false in: \"$l_kfile\""
    else
      echo " - creating \"automount-open\" entry in \"$l_kfile\""
      ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
      sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \\nautomount-open=false' "$l_kfile"
    fi

    # check automount setting
    if grep -Pqs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
      echo " - \"automount\" is set to false in: \"$l_kfile\""
    else
      echo " - creating \"automount\" entry in \"$l_kfile\""
      ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
      sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \\nautomount=false' "$l_kfile"
    fi

    # update dconf database
    dconf update
  else
    echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
  fi
}

# Task 1.8.7: Ensure GDM disabling automatic mounting of removable media is not overridden
{
  l_pkgoutput=""

  if command -v dpkg-query > /dev/null 2>&1; then
    l_pq="dpkg-query -W"
  elif command -v rpm > /dev/null 2>&1; then
    l_pq="rpm -q"
  fi

  for l_pn in gdm gdm3; do
    if $l_pq "$l_pn" > /dev/null 2>&1; then
      l_pkgoutput="y"
      echo -e "\n - Package: \"$l_pn\" exists on the system\n - remediating configuration if needed"
    fi
  done

  if [ -n "$l_pkgoutput" ]; then
    l_kfd="/etc/dconf/db/$(grep -Psril '^\h*automount\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
    
    l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*automount-open\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"

    if [ -d "$l_kfd" ]; then
      if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/automount\b' "$l_kfd"; then
        echo " - \"automount\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/mediahandling\/automount\b' "$l_kfd")\""
      else
        echo " - creating entry to lock \"automount\""
        [ ! -d "$l_kfd/locks" ] && echo "creating directory $l_kfd/locks" && mkdir "$l_kfd/locks"
        {
          echo -e '\n# Lock desktop media-handling automount setting'
          echo '/org/gnome/desktop/media-handling/automount'
        } >> "$l_kfd/locks/00-media-automount"
      fi
    else
      echo -e " - \"automount\" is not set so it can not be locked\n - Please follow Recommendation \"Ensure GDM automatic mounting of removable media is disabled\" and follow this Recommendation again"
    fi

    if [ -d "$l_kfd2" ]; then
      if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2"; then
        echo " - \"automount-open\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2")\""
      else
        echo " - creating entry to lock \"automount-open\""
        [ ! -d "$l_kfd2/locks" ] && echo "creating directory $l_kfd2/locks" && mkdir "$l_kfd2/locks"
        {
          echo -e '\n# Lock desktop media-handling automount-open setting'
          echo '/org/gnome/desktop/media-handling/automount-open'
        } >> "$l_kfd2/locks/00-media-automount"
      fi
    else
      echo -e " - \"automount-open\" is not set so it can not be locked\n - Please follow Recommendation \"Ensure GDM automatic mounting of removable media is disabled\" and follow this Recommendation again"
    fi

    dconf update
  else
    echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
  fi
}

# Task 1.8.8: Ensure GDM autorun-never is enabled
{
  l_pkgoutput=""
  l_output=""
  l_output2=""
  l_gpname="local"

  if command -v dpkg-query > /dev/null 2>&1; then
    l_pq="dpkg-query -W"
  elif command -v rpm > /dev/null 2>&1; then
    l_pq="rpm -q"
  fi

  l_pcl="gdm gdm3"
  for l_pn in $l_pcl; do
    $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
  done
  echo -e "$l_pkgoutput"

  if [ -n "$l_pkgoutput" ]; then
    echo -e "$l_pkgoutput"
    l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)"

    if [ -f "$l_kfile" ]; then
      l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
      echo " - updating dconf profile name to \"$l_gpname\""
    fi
    [ ! -f "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-mediaautorun"

    if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
      echo -e "\n - dconf database profile exists in: \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\""
    else
      [ ! -f "/etc/dconf/profile/user" ] && l_gpfile="/etc/dconf/profile/user" || l_gpfile="/etc/dconf/profile/user2"
      echo -e " - creating dconf database profile"
      {
        echo -e "\nuser-db:user"
        echo "system-db:$l_gpname"
      } >> "$l_gpfile"
    fi

    l_gpdir="/etc/dconf/db/$l_gpname.d"
    if [ -d "$l_gpdir" ]; then
      echo " - The dconf database directory \"$l_gpdir\" exists"
    else
      echo " - creating dconf database directory \"$l_gpdir\""
      mkdir "$l_gpdir"
    fi

    if grep -Pqs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then
      echo " - \"autorun-never\" is set to true in: \"$l_kfile\""
    else
      echo " - creating or updating \"autorun-never\" entry in \"$l_kfile\""
      if grep -Psq -- '^\h*autorun-never' "$l_kfile"; then
        sed -ri 's/(^\s*autorun-never\s*=\s*)(\S+)(\s*.*)$/\1true \3/' "$l_kfile"
      else
        ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
        sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \\nautorun-never=true' "$l_kfile"
      fi
    fi
  else
    echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
  fi

  dconf update
}

# Task 1.8.9: Ensure GDM autorun-never is not overridden
{
  l_pkgoutput=""
  if command -v dpkg-query > /dev/null 2>&1; then
    l_pq="dpkg-query -W"
  elif command -v rpm > /dev/null 2>&1; then
    l_pq="rpm -q"
  fi

  l_pcl="gdm gdm3"
  for l_pn in $l_pcl; do
    $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="y" && echo -e "\n - Package: \"$l_pn\" exists on the system\n - remediating configuration if needed"
  done

  if [ -n "$l_pkgoutput" ]; then
    l_kfd="/etc/dconf/db/$(grep -Psril '^\h*autorun-never\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d"
    if [ -d "$l_kfd" ]; then
      if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/autorun-never\b' "$l_kfd"; then
        echo " - \"autorun-never\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/media-handling\/autorun-never\b' "$l_kfd")\""
      else
        echo " - creating entry to lock \"autorun-never\""
        [ ! -d "$l_kfd"/locks ] && echo "creating directory $l_kfd/locks" && mkdir "$l_kfd"/locks
        {
          echo -e '\n# Lock desktop media-handling autorun-never setting'
          echo '/org/gnome/desktop/media-handling/autorun-never'
        } >> "$l_kfd"/locks/00-media-autorun
      fi
    else
      echo -e " - \"autorun-never\" is not set so it can not be locked\n - Please follow Recommendation \"Ensure GDM autorun-never is enabled\" and follow this Recommendation again"
    fi
    dconf update
  else
    echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
  fi
}

# Task 1.8.10: Ensure XDMCP is not enabled
conf_file="/etc/gdm/custom.conf"

if [ ! -f "$conf_file" ]; then
  echo "Error: File $conf_file does not exist."
  exit 1
fi

sed -i '/^Enable=true$/d' "$conf_file"

if grep -q '^Enable=true$' "$conf_file"; then
  echo "Failed to remove the line 'Enable=true' from $conf_file."
else
  echo "Successfully removed the line 'Enable=true' from $conf_file."
fi

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################