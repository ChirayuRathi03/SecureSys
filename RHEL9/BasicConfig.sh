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

echo '.'

# Task 1.2.1.2: Ensure gpgcheck is globally activated
sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
find /etc/yum.repos.d/ -name "*.repo" -exec echo "Checking:" {} \; -exec sed -i 's/^gpgcheck\s*=\s*.*/gpgcheck=1/' {} \;

# Task 1.2.1.3: Ensure repo_gpgcheck is globally activated
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

# Task 1.3.1.1: Ensure SELinux is installed
dnf install libselinux -y

echo '.'

# Task 1.3.1.2: Ensure SELinux is not disabled in bootloader configuration
grubby --update-kernel ALL --remove-args "selinux=0 enforcing=0"
grep -Psrq 'kernelopts=.*\b(selinux|enforcing)=0\b' /boot/grub2 /boot/efi
if [ $? -eq 0 ]; then
  grub2-mkconfig -o "$(grep -Prl 'kernelopts=.*\b(selinux|enforcing)=0\b' /boot/grub2 /boot/efi)"
fi

# Task 1.3.1.3: Ensure SELinux policy is configured
SELINUXTYPE=targeted

# Task 1.3.1.4: Ensure the SELinux mode is not disabled
# For 'enforcing' mode
setenforce 1 
SELINUX=enforcing

# For 'permissive' mode
#setenforce 0
#SELINUX=permissive
# Difference between the 2: Enforcing blocks and logs unauthorized actions whereas Permissive allows unauthorized actions but logs them.

# Task 1.3.1.5: Ensure the SELinux mode is enforcing
setenforce 1 
SELINUX=enforcing

# Task 1.4.1: Ensure bootloader password is set
grub2-setpassword

# Task 1.4.2: Ensure access to bootloader config is configured
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

# Task 1.5.1: Ensure address space layout randomization is enabled
printf "
kernel.randomize_va_space = 2
" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.randomize_va_space=2

# Task 1.5.2: Ensure ptrace_scope is restricted
printf "
kernel.yama.ptrace_scope = 1
" >> /etc/sysctl.d/60-kernel_sysctl.conf
sysctl -w kernel.yama.ptrace_scope=1

echo '.'

# Task 1.5.3: Ensure core dump backtraces are disabled
{
  [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir /etc/systemd/coredump.conf.d/
  if grep -Psq -- '^\h*\[Coredump\]' /etc/systemd/coredump.conf.d/60-coredump.conf; then
    printf '%s\n' "ProcessSizeMax=0" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  else
    printf '%s\n' "[Coredump]" "ProcessSizeMax=0" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  fi
}

# Task 1.5.4: Ensure core dump storage is disabled
{
  [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir /etc/systemd/coredump.conf.d/
  if grep -Psq -- '^\h*\[Coredump\]' /etc/systemd/coredump.conf.d/60-coredump.conf; then
    printf '%s\n' "Storage=none" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  else
    printf '%s\n' "[Coredump]" "Storage=none" >> /etc/systemd/coredump.conf.d/60-coredump.conf
  fi
}

# Task 1.6.1: Ensure system wide crypto policy is not set to legacy
update-crypto-policies --set DEFAULT
update-crypto-policies
# If FIPS is required
#fips-mode-setup --enable

echo '.'

# Task 1.6.2: Ensure system wide crypto policy is not set in sshd configuration
sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/# \1/" /etc/sysconfig/sshd
systemctl reload sshd

# Task 1.6.3: Ensure system wide crypto policy disables sha1 hash and signature support
printf '%s\n' "hash = -SHA1" "sign = -*-SHA1" "sha1_in_certs = 0" >> /etc/crypto-policies/policies/modules/NO-SHA1.pmod
update-crypto-policies --set DEFAULT:NO-SHA1

# Task 1.6.4: Ensure system wide crypto policy disables macs less than 128 bits
printf '%s\n' "mac = -*-64" >> /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC

# Task 1.6.5: Ensure system wide crypto policy disables cbc for ssh
printf '%s\n' "cipher@SSH = -*-CBC" >> /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC

echo '.'

# Task 1.6.6: Ensure system wide crypto policy disables chacha20-poly1305 for ssh
printf '%s\n' "cipher@SSH = -CHACHA20-POLY1305" >> /etc/crypto-policies/policies/modules/NOSSHCHACHA20.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NOSSHCHACHA20

# Task 1.6.7: Ensure system wide crypto policy disables EtM for ssh
printf '%s\n' "etm@SSH = DISABLE_ETM" >> /etc/crypto-policies/policies/modules/NO-SSHETM.pmod
update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC:NOSSHCHACHA20:NO-SSHETM

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

echo '.'

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

echo '.'

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

echo '.'

# Task 1.8.4: Ensure GDM screen locks when the user is idle
l_key_file="/etc/dconf/db/local.d/00-screensaver"
l_idmv="900"
l_ldmv="5"

{
  echo '[org/gnome/desktop/session]'
  echo ''
  echo "idle-delay=uint32 $l_idmv"
  echo ''
  echo '[org/gnome/desktop/screensaver]'
  echo ''
  echo "lock-delay=uint32 $l_ldmv"
} > "$l_key_file"

echo '.'

# Task 1.8.5: Ensure GDM screen locks cannot be overridden
l_pkgoutput=""

if command -v dpkg-query > /dev/null 2>&1; then
  l_pq="dpkg-query -W"
elif command -v rpm > /dev/null 2>&1; then
  l_pq="rpm -q"
fi

l_pcl="gdm gdm3"

for l_pn in $l_pcl; do
  if $l_pq "$l_pn" > /dev/null 2>&1; then
    l_pkgoutput="y"
    echo -e "\n - Package: \"$l_pn\" exists on the system\n - Remediating configuration if needed"
  fi
done

if [ -n "$l_pkgoutput" ]; then
  # Determine profile directories for idle-delay and lock-delay
  l_kfd=$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | 
          awk -F'/' '{split($(NF-1),a,".");print a[1]}').d
  l_kfd2=$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | 
           awk -F'/' '{split($(NF-1),a,".");print a[1]}').d

  # Check and create settings for idle-delay
  if [ -d "$l_kfd" ]; then
    if grep -Prilq '^\h*/org/gnome/desktop/session/idle-delay\b' "$l_kfd"; then
      echo " - \"idle-delay\" is locked in \"$(grep -Pril '^\h*/org/gnome/desktop/session/idle-delay\b' "$l_kfd")\""
    else
      echo "Creating entry to lock \"idle-delay\""
      [ ! -d "$l_kfd/locks" ] && echo "Creating directory $l_kfd/locks" && mkdir "$l_kfd/locks"
      echo -e '\n# Lock desktop screensaver idle-delay setting' > "$l_kfd/locks/00-screensaver"
      echo '/org/gnome/desktop/session/idle-delay' >> "$l_kfd/locks/00-screensaver"
    fi
  else
    echo -e " - \"idle-delay\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM screen locks when the user is idle\" and try again"
  fi

  # Check and create settings for lock-delay
  if [ -d "$l_kfd2" ]; then
    if grep -Prilq '^\h*/org/gnome/desktop/screensaver/lock-delay\b' "$l_kfd2"; then
      echo " - \"lock-delay\" is locked in \"$(grep -Pril '^\h*/org/gnome/desktop/screensaver/lock-delay\b' "$l_kfd2")\""
    else
      echo "Creating entry to lock \"lock-delay\""
      [ ! -d "$l_kfd2/locks" ] && echo "Creating directory $l_kfd2/locks" && mkdir "$l_kfd2/locks"
      echo -e '\n# Lock desktop screensaver lock-delay setting' > "$l_kfd2/locks/00-screensaver"
      echo '/org/gnome/desktop/screensaver/lock-delay' >> "$l_kfd2/locks/00-screensaver"
    fi
  else
    echo -e " - \"lock-delay\" is not set so it cannot be locked\n - Please follow Recommendation \"Ensure GDM screen locks when the user is idle\" and try again"
  fi
else
  echo -e " - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
fi

echo '.'

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

echo '.'

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

echo '.'

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

# Task 2.1.1: Ensure autofs services are not in use
systemctl stop autofs.service
systemctl mask autofs.service

# Task 2.1.2: Ensure avahi daemon services are not in use
systemctl stop avahi-daemon.socket avahi-daemon.service
systemctl mask avahi-daemon.socket avahi-daemon.service

# Task 2.1.3: Ensure dhcp server services are not in use
systemctl stop dhcpd.service dhcpd6.service
systemctl mask dhcpd.service dhcpd6.service

# Task 2.1.4: Ensure dns server services are not in use
systemctl stop named.service
systemctl mask named.service

echo '.'

# Task 2.1.5: Ensure dnsmasq services are not in use
systemctl stop dnsmasq.service
systemctl mask dnsmasq.service

# Task 2.1.6: Ensure samba file server services are not in use
systemctl stop smb.service
systemctl mask smb.service

# Task 2.1.7: Ensure ftp server services are not in use
systemctl stop vsftpd.service
systemctl mask vsftpd.service

# Task 2.1.8 Ensure message access server services are not in use
systemctl stop dovecot.socket dovecot.service cyrus-imapd.service
systemctl mask dovecot.socket dovecot.service cyrus-imapd.service

echo '.'

# Task 2.1.9: Ensure network file system services are not in use
systemctl stop nfs-server.service
systemctl mask nfs-server.service

# Task 2.1.10: Ensure nis server services are not in use
systemctl stop ypserv.service
systemctl mask ypserv.service

# Task 2.1.11: Ensure print server services are not in use
systemctl stop cups.socket cups.service
systemctl mask cups.socket cups.service

# Task 2.1.12: Ensure rpcbind services are not in use
systemctl stop rpcbind.socket rpcbind.service
systemctl mask rpcbind.socket rpcbind.service

echo '.'

# Task 2.1.13: Ensure rsync services are not in use
systemctl stop rsyncd.socket rsyncd.service
systemctl mask rsyncd.socket rsyncd.service

# Task 2.1.14: Ensure snmp services are not in use
systemctl stop snmpd.service
systemctl mask snmpd.service

# Task 2.1.15: Ensure telnet server services are not in use
systemctl stop telnet.socket
systemctl mask telnet.socket

echo '.'

# Task 2.1.16: Ensure tftp server services are not in use
systemctl stop tftp.socket tftp.service
systemctl mask tftp.socket tftp.service

# Task 2.1.17: Ensure web proxy server services are not in use
systemctl stop squid.service
systemctl mask squid.service

# Task 2.1.18: Ensure web server services are not in use
systemctl stop httpd.socket httpd.service nginx.service
systemctl mask httpd.socket httpd.service nginx.service

# Task 2.1.19: Ensure xinetd services are not in use
systemctl stop xinetd.service
systemctl mask xinetd.service

echo '.'

# Task 2.1.20: Ensure X window server services are not in use
dnf remove xorg-x11-server-common &> /dev/null

# Task 2.1.21: Ensure mail transfer agents are configured for local-only mode
conf_file="/etc/postfix/main.cf"
line_to_add="inet_interfaces = loopback-only"

if [ ! -f "$conf_file" ]; then
  echo "Error: File $conf_file does not exist."
fi

# Add or modify the line in the configuration file
if grep -q "^inet_interfaces" "$conf_file"; then
  sed -i "s/^inet_interfaces.*/$line_to_add/" "$conf_file"
else
  echo "$line_to_add" >> "$conf_file"
fi

if grep -q "^inet_interfaces = loopback-only" "$conf_file"; then
  echo "Successfully added/modified the line in $conf_file."
else
  echo "Failed to add/modify the line in $conf_file."
  exit 1
fi

systemctl restart postfix

if systemctl is-active --quiet postfix; then
  echo "Postfix has been successfully restarted."
else
  echo "Failed to restart postfix. Please check the service status."
fi

# Task 3.2.x: Ensure 'x' kernel module is not available
f_module_fix() {
  l_dl="y"
  a_showconfig=()

  while IFS= read -r l_showconfig; do
    a_showconfig+=("$l_showconfig")
  done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_name//-/_}"'\b')

  if lsmod | grep "$l_mod_name" &> /dev/null; then
    a_output2+=("Unloading kernel module: \"$l_mod_name\"")
    modprobe -r "$l_mod_name" 2>/dev/null
    rmmod "$l_mod_name" 2>/dev/null
  fi

  if ! grep -Pq -- '\binstall\h+'"${l_mod_name//-/_}"'\h+\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
    a_output2+=("Setting kernel module: \"$l_mod_name\" to \"/bin/false\"")
    printf 'install %s /bin/false\n' "$l_mod_name" > /etc/modprobe.d/"$l_mod_name".conf
  fi

  echo '.'
  
  if ! grep -Pq -- '\bblacklist\h+'"${l_mod_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
    a_output2+=("Denylisting kernel module: \"$l_mod_name\"")
    printf 'blacklist %s\n' "$l_mod_name" >> /etc/modprobe.d/"$l_mod_name".conf
  fi
}

# Task 3.2.1: Ensure dccp kernel module is not available
l_mod_name="dccp"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.2.2: Ensure tipc kernel module is not available
l_mod_name="tipc"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.2.3: Ensure rds kernel module is not available
l_mod_name="rds"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

echo '.'

# Task 3.2.4: Ensure sctp kernel module is not available
l_mod_name="sctp"
l_mod_type="net"
l_mod_path=$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)

for l_mod_base_directory in $l_mod_path; do
  if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A $l_mod_base_directory/${l_mod_name/-/\/})" ]; then
    l_output3="$l_output3\n - \"$l_mod_base_directory\""
    [ "$l_dl" != "y" ] && f_module_fix
  else
    echo -e "Kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\""
  fi
done

[ -n "$l_output3" ] && echo -e "\n\nModule \"$l_mod_name\" exists in:$l_output3"
[ "${#a_output2[@]}" -gt 0 ] && printf '%s\n' "${a_output2[@]}"
echo -e "\nRemediation of kernel module: \"$l_mod_name\" complete\n"

# Task 3.3.1: Ensure ip forwarding is disabled
ipv4_config_file="/etc/sysctl.d/60-netipv4_sysctl.conf"
printf '%s\n' "net.ipv4.ip_forward = 0" > "$ipv4_config_file"

sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.route.flush=1

# Check if IPv6 is enabled
if sysctl -a | grep -q '^net.ipv6.conf.all.forwarding'; then
  ipv6_config_file="/etc/sysctl.d/60-netipv6_sysctl.conf"
  printf '%s\n' "net.ipv6.conf.all.forwarding = 0" > "$ipv6_config_file"

  sysctl -w net.ipv6.conf.all.forwarding=0
  sysctl -w net.ipv6.route.flush=1
fi

# Task 3.3.2: Ensure packet redirect sending is disabled
printf '%s\n' "net.ipv4.conf.all.send_redirects = 0" \
"net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1

# Task 3.3.3: Ensure bogus icmp responses are ignored
printf '%s\n' "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1

echo '.'

# Task 3.3.4: Ensure broadcast icmp requests are ignored
printf '%s\n' "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.5: Ensure icmp redirects are not accepted
printf '%s\n' "net.ipv4.conf.all.accept_redirects = 0" \
"net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

# Check if IPv6 is enabled
if sysctl -a | grep -q 'net.ipv6.conf.all.forwarding'; then
  printf '%s\n' "net.ipv6.conf.all.accept_redirects = 0" \
  "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf
  
  sysctl -w net.ipv6.conf.all.accept_redirects=0
  sysctl -w net.ipv6.conf.default.accept_redirects=0
  sysctl -w net.ipv6.route.flush=1
fi

echo '.'

# Task 3.3.6: Ensure secure icmp redirects are not accepted
printf '%s\n' "net.ipv4.conf.all.secure_redirects = 0" \
"net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1


# Task 3.3.7: Ensure reverse path filtering is enabled
printf '%s\n' "net.ipv4.conf.all.rp_filter = 1" \
"net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

echo '.'

# Task 3.3.8: Ensure source routed packets are not accepted
printf '%s\n' "net.ipv4.conf.all.accept_source_route = 0" \
"net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

if sysctl -a | grep -q 'net.ipv6.conf.all.forwarding'; then
  printf '%s\n' "net.ipv6.conf.all.accept_source_route = 0" \
  "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf

  sysctl -w net.ipv6.conf.all.accept_source_route=0
  sysctl -w net.ipv6.conf.default.accept_source_route=0
  sysctl -w net.ipv6.route.flush=1
fi

# Task 3.3.9: Ensure suspicious packets are logged
printf '%s\n' "net.ipv4.conf.all.log_martians = 1" \
"net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

# Task 3.3.10: Ensure tcp syn cookies is enabled
printf '%s\n' "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo '.'

# Task 3.3.11: Ensure ipv6 router advertisements are not accepted
if sysctl -a | grep -q 'net.ipv6.conf.all.accept_ra'; then
  printf '%s\n' "net.ipv6.conf.all.accept_ra = 0" \
  "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.d/60-netipv6_sysctl.conf

  sysctl -w net.ipv6.conf.all.accept_ra=0
  sysctl -w net.ipv6.conf.default.accept_ra=0
  sysctl -w net.ipv6.route.flush=1
fi

# Task 4.1.1: Ensure nftables is installed
dnf install nftables -y

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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

echo '.'

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
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep -oP 'custom/\S+')/$l_pam_file"    
    if [[ -f "$l_authselect_file" ]]; then
        sed -ri 's/(^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so.*)(\s+deny\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    else
        echo "File $l_authselect_file does not exist. Skipping..."
    fi
done

authselect apply-changes

# Task 5.3.3.1.2: Ensure password unlock time is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep -oP 'custom/\S+')/$l_pam_file"    
    if [[ -f "$l_authselect_file" ]]; then
        sed -ri 's/(^\s*auth\s+(requisite|required|sufficient)\s+pam_faillock\.so.*)(\s+unlock_time\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
    else
        echo "File $l_authselect_file does not exist. Skipping..."
    fi
done

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

authselect apply-changes

# Task 5.3.3.2.1: Ensure password number of changed characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+difok\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

authselect apply-changes

echo '.'

# Task 5.3.3.2.2: Ensure password length is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+minlen\s*=\s*[0-9]+)(.*$)/\1\4/' "$l_authselect_file"
done

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

authselect apply-changes

echo '.'

# Task 5.3.3.2.4: Ensure password same consecutive characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+maxrepeat\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

authselect apply-changes

# Task 5.3.3.2.5: Ensure password maximum sequential characters is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+maxsequence\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

authselect apply-changes

# Task 5.3.3.2.6: Ensure password dictionary check is enabled
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwquality\.so.*)(\s+dictcheck\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

authselect apply-changes

# Task 5.3.3.2.7: Ensure password quality is enforced for the root user
printf '\n%s\n' "enforce_for_root" >> /etc/security/pwquality.conf.d/50-pwroot.conf

# Task 5.3.3.3.1: Ensure password history remember is configured
for l_pam_file in system-auth password-auth; do
    l_authselect_file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file"
    sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so.*)(\s+remember\s*=\s*\S+)(.*$)/\1\4/' "$l_authselect_file"
done

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

echo '.'

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

echo '.'

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

# Task 5.4.1.2: Ensure minimum password days is configured
sed -ri 's/^PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS 1/' /etc/login.defs

echo '.'

# Task 5.4.1.3: Ensure password expiration warning days is configured
sed -ri 's/^PASS_WARN_AGE\s+.*/PASS_WARN_AGE 7/' /etc/login.defs

# Task 6.3.1.1: Ensure auditd packages are installed
dnf install audit audit-libs -y

echo '.'

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

echo '.'

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

echo '.'

# Task 6.3.2.1: Ensure audit log storage size is configured
read -rp "Enter the max_log_file size (MB): " log_file_size

auditd_conf="/etc/audit/auditd.conf"
temp_file=$(mktemp)

if grep -q "^max_log_file" "$auditd_conf"; then
    awk -v key="max_log_file" -v value="$log_file_size" \
    '{ if ($0 ~ key) sub(/max_log_file\s*=\s*[0-9]+/, "max_log_file = " value); print }' \
    "$auditd_conf" > "$temp_file"
    mv "$temp_file" "$auditd_conf"
else
    echo "max_log_file = $log_file_size" >> "$auditd_conf"
fi

# Task 6.3.2.2: Ensure audit logs are not automatically deleted 
auditd_conf="/etc/audit/auditd.conf"
temp_file=$(mktemp)

if grep -q "^max_log_file_action" "$auditd_conf"; then
    awk -v key="max_log_file_action" -v value="keep_logs" \
    '{ if ($0 ~ key) sub(/max_log_file_action\s*=\s*[^ ]+/, "max_log_file_action = " value); print }' \
    "$auditd_conf" > "$temp_file"
    mv "$temp_file" "$auditd_conf"
else
    echo "max_log_file_action = keep_logs" >> "$auditd_conf"
fi

#systemctl restart auditd

echo '.'

# Task 6.3.2.3: Ensure system is disabled when audit logs are full
if grep -q '^disk_full_action' /etc/audit/auditd.conf; then
    sed -i 's/^disk_full_action.*/disk_full_action = halt/' /etc/audit/auditd.conf
else
    echo 'disk_full_action = halt' >> /etc/audit/auditd.conf
fi

if grep -q '^disk_error_action' /etc/audit/auditd.conf; then
    sed -i 's/^disk_error_action.*/disk_error_action = halt/' /etc/audit/auditd.conf
else
    echo 'disk_error_action = halt' >> /etc/audit/auditd.conf
fi

# Commands to set both parameters to 'single':
# sed -i 's/^disk_full_action.*/disk_full_action = single/' /etc/audit/auditd.conf
# sed -i 's/^disk_error_action.*/disk_error_action = single/' /etc/audit/auditd.conf
# replace these with the 'halt' lines above.

# Difference between the 2:
#    single: The system will be switched to single-user mode for manual intervention if the disk is full or if there is a disk error.
#    halt: The system will be halted or powered off if the disk is full or if there is a disk error.

# Task 6.3.2.4: Ensure system warns when audit logs are low on space
if grep -q '^space_left_action' /etc/audit/auditd.conf; then
    sed -i 's/^space_left_action.*/space_left_action = email/' /etc/audit/auditd.conf
else
    echo 'space_left_action = email' >> /etc/audit/auditd.conf
fi

if grep -q '^admin_space_left_action' /etc/audit/auditd.conf; then
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = single/' /etc/audit/auditd.conf
else
    echo 'admin_space_left_action = single' >> /etc/audit/auditd.conf
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

echo '.'

# Task 6.3.3.1: Ensure changes to system administration scope (sudoers) is collected
RULE_FILE="/etc/audit/rules.d/50-scope.rules"

if ! grep -q '/etc/sudoers' "$RULE_FILE"; then
    printf '%s\n' "-w /etc/sudoers -p wa -k scope" >> "$RULE_FILE"
fi

if ! grep -q '/etc/sudoers.d' "$RULE_FILE"; then
    printf '%s\n' "-w /etc/sudoers.d -p wa -k scope" >> "$RULE_FILE"
fi

augenrules --load

# Task 6.3.3.2: Ensure actions as another user are always logged
RULE_FILE="/etc/audit/rules.d/50-user_emulation.rules"

if ! grep -q 'user_emulation' "$RULE_FILE"; then
    printf "
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
" >> "$RULE_FILE"
fi

augenrules --load

# Task 6.3.3.3: Ensure events that modify the sudo log file are collected
RULE_FILE="/etc/audit/rules.d/50-sudo.rules"

SUDO_LOG_FILE=$(grep -r 'logfile' /etc/sudoers* | sed -e 's/.*logfile=//;s/,?.*//' -e 's/"//g')

if [ -n "${SUDO_LOG_FILE}" ]; then
    if ! grep -q "sudo_log_file" "$RULE_FILE"; then
        printf "-w ${SUDO_LOG_FILE} -p wa -k sudo_log_file\n" >> "$RULE_FILE"
    fi
else
    printf "ERROR: Variable 'SUDO_LOG_FILE' is unset.\n"
fi

augenrules --load

echo '.'

# Task 6.3.3.4: Ensure events that modify date and time information are collected
RULE_FILE="/etc/audit/rules.d/50-time-change.rules"

printf "
-a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
-a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
-w /etc/localtime -p wa -k time-change
" >> "$RULE_FILE"

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
" >> "$RULE_FILE"

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

echo '.'

# Task 6.3.3.7: Ensure unsuccessful file access attempts are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-access.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
" >> "$RULE_FILE"
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
" >> "$RULE_FILE"

augenrules --load

echo '.'

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
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

echo '.'

# Task 6.3.3.10: Ensure successful file system mounts are collected 
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-mounts.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b32 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=${UID_MIN} -F auid!=unset -k mounts
" >> "$RULE_FILE"
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
" >> "$RULE_FILE"

augenrules --load

echo '.'

# Task 6.3.3.12: Ensure login and logout events are collected
RULE_FILE="/etc/audit/rules.d/50-login.rules"

printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> "$RULE_FILE"

augenrules --load

# Task 6.3.3.13: Ensure file deletion events by users are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-delete.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

echo '.'

# Task 6.3.3.14: Ensure events that modify the system's Mandatory Access Controls are collected
RULE_FILE="/etc/audit/rules.d/50-MAC-policy.rules"

printf "
-w /etc/selinux -p wa -k MAC-policy
-w /usr/share/selinux -p wa -k MAC-policy
" >> "$RULE_FILE"

augenrules --load

# Task 6.3.3.15: Ensure successful and unsuccessful attempts to use the chcon command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-perm_chng.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

echo '.'

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

echo '.'

# Task 6.3.3.18: Ensure successful and unsuccessful attempts to use the usermod command are collected
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
RULE_FILE="/etc/audit/rules.d/50-usermod.rules"

if [ -n "${UID_MIN}" ]; then
    printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
" >> "$RULE_FILE"
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
" >> "$RULE_FILE"
else
    printf "ERROR: Variable 'UID_MIN' is unset.\n"
fi

augenrules --load

echo '.'

# Task 6.3.3.20: Ensure the audit configuration is immutable
printf '\n-e 2' >> /etc/audit/rules.d/99-finalize.rules
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

echo '.'

# Task 6.3.4.3: Ensure audit log files owner is configured
[ -f /etc/audit/auditd.conf ] && find "$(dirname $(awk -F "=" '/^\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))" -type f ! -user root -exec chown root {} +

# Task 6.3.4.4: Ensure audit log files group owner is configured
read -p "Enter the name of the group to set for audit logs: " GROUP_NAME
find "$(dirname "$(awk -F"=" '/^\s*log_file\s*=\s*/ {print $2}' /etc/audit/auditd.conf | xargs)")" -type f \( ! -group "$GROUP_NAME" -a ! -group root \) -exec chgrp "$GROUP_NAME" {} +
chgrp "$GROUP_NAME" /var/log/audit/
sed -ri "s/^\s*#?\s*log_group\s*=\s*\S+(\s*#.*)?.*$/log_group = $GROUP_NAME\1/" /etc/audit/auditd.conf
#systemctl restart auditd

echo '.'

# Task 6.3.4.5: Ensure audit configuration files mode is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) -exec chmod u-x,g-wx,o-rwx {} +

# Task 6.3.4.6: Ensure audit configuration files owner is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -user root -exec chown root {} +

# Task 6.3.4.7: Ensure audit configuration files group owner is configured
find /etc/audit/ -type f \( -name '*.conf' -o -name '*.rules' \) ! -group root -exec chgrp root {} +

echo '.'

# Task 6.3.4.8: Ensure audit tools mode is configured
chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# Task 6.3.4.9: Ensure audit tools owner is configured
chown root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

# Task 6.3.4.10: Ensure audit tools group owner is configured
chgrp root /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules

echo '.'

# Task 7.1.1: Ensure permissions on /etc/passwd are configured
chmod u-x,go-wx /etc/passwd
chown root:root /etc/passwd

# Task 7.1.2: Ensure permissions on /etc/passwd- are configured
chmod u-x,go-wx /etc/passwd-
chown root:root /etc/passwd-

echo '.'

# Task 7.1.3: Ensure permissions on /etc/group are configured
chmod u-x,go-wx /etc/group
chown root:root /etc/group

# Task 7.1.4: Ensure permissions on /etc/group- are configured
chmod u-x,go-wx /etc/group-
chown root:root /etc/group-

echo '.'

# Task 7.1.5: Ensure permissions on /etc/shadow are configured
chown root:root /etc/shadow
chmod 0000 /etc/shadow

# Task 7.1.6: Ensure permissions on /etc/shadow- are configured
chown root:root /etc/shadow-
chmod 0000 /etc/shadow-

echo '.'

# Task 7.1.7: Ensure permissions on /etc/gshadow are configured
chown root:root /etc/gshadow
chmod 0000 /etc/gshadow

# Task 7.1.8: Ensure permissions on /etc/gshadow- are configured
chown root:root /etc/gshadow-
chmod 0000 /etc/gshadow-

echo '.'

# Task 7.1.9: Ensure permissions on /etc/shells are configured
chmod u-x,go-wx /etc/shells
chown root:root /etc/shells

# Task 7.1.10: Ensure permissions on /etc/security/opasswd are configured
[ -e "/etc/security/opasswd" ] && chmod u-x,go-rwx /etc/security/opasswd
[ -e "/etc/security/opasswd" ] && chown root:root /etc/security/opasswd
[ -e "/etc/security/opasswd.old" ] && chmod u-x,go-rwx /etc/security/opasswd.old
[ -e "/etc/security/opasswd.old" ] && chown root:root /etc/security/opasswd.old

echo '.'

# Task 7.1.11: Ensure world writable files and directories are secured
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

echo '.'

# Task 7.1.12: Ensure no files or directories without an owner and a group exist
exclude_paths=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")

while IFS= read -r mount_point; do
    find "$mount_point" -xdev \( "${exclude_paths[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
        if [ -e "$file" ]; then
            echo "Fixing ownership for: $file"
            chown root:root "$file"
        fi
    done
done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

# Task 7.1.13: Ensure SUID and SGID files are reviewed (Manual)

# Task 7.2.1: Ensure accounts in /etc/passwd use shadowed passwords
pwconv

echo '.'

# Task 7.2.2: Ensure /etc/shadow password fields are not empty
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

# Task 7.2.3: Ensure all groups in /etc/passwd exist in /etc/group
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

# Task 7.2.4: Ensure no duplicate UIDs exist
while read -r count uid; do
    if [ "$count" -gt 1 ]; then
        users=($(awk -F: '($3 == '"$uid"') {print $1}' /etc/passwd))
        base_user=${users[0]}
        for ((i=1; i<${#users[@]}; i++)); do
            usermod -u "$(id -u "$base_user")" "${users[$i]}"
        done
    fi
done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

echo '.'

# Task 7.2.5 Ensure no duplicate GIDs exist
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

echo '.'

# Task 7.2.6: Ensure no duplicate user names exist
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

# Task 7.2.7: Ensure no duplicate group names exist
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

echo '.'

# Task 7.2.8: Ensure local interactive user home directories are configured
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

# Task 7.2.9: Ensure local interactive user dot files access is configured
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

echo '.'

### Written By: 
###     1. Chirayu Rathi
###     2. Aditi Jamsandekar
###     3. Siddhi Jani
############################