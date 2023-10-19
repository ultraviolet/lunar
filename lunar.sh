#!/bin/bash

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

users(){
# Get all users on the system
users=$(cut -d: -f1 /etc/passwd)

for user in $users; do
    # Skip system users
    if id "$user" &>/dev/null; then
        uid=$(id -u "$user")
        if [ "$uid" -lt 1000 ] && [ "$uid" -ne 0 ]; then
            continue
        fi
    else
        continue
    fi
    
    # Check if the user is in the sudo group
    if id -nG "$user" | grep -qw "sudo"; then
        echo "$user is an admin."
    else
        echo "$user is not an admin."
    fi

    # Ask for action
    echo "What do you want to do with $user?"
    echo "1. Grant admin privileges"
    echo "2. Remove admin privileges"
    echo "3. Remove user"
    echo "4. Keep as is"
    echo -n "Enter choice [1-4]: "
    read choice

    case $choice in
        1)
            sudo usermod -aG sudo "$user"
	    sudo usermod -aG adm "$user"	
            echo "$user is now an admin."
            ;;
        2)
            deluser "$user" sudo
	    deluser "$user" adm
            echo "Admin privileges removed from $user."
            ;;
        3)
            userdel -r "$user"
            echo "$user removed from the system."
            ;;
        4)
            echo "No changes made to $user."
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac

    echo "-----------------------------"
done
}

ufw(){
sudo apt update
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw enable
sudo ufw status
echo "UFW has been enabled."
# ufw reset

# # Deny all incoming and outgoing traffic by default
# ufw default deny incoming
# ufw default deny outgoing

# # Allow necessary outgoing traffic (for example, for DNS, HTTP, and HTTPS)
# ufw allow out 53/udp  # DNS
# ufw allow out 80/tcp  # HTTP
# ufw allow out 443/tcp # HTTPS
}


logo(){
echo "         //            __      ___      __     		"
echo "        // //   / / //   ) ) //   ) ) //  ) )       "
echo "       // //   / / //   / / //   / / //             "
echo "      // ((___( ( //   / / ((___( ( //              "
}

ssh(){
 dpkg -l | grep openssh-server
 if [ $? -eq 0 ];
        then
                read -p "Should SSH be installed on the system? [y/n]: " a
                	if [ $a = n ];
                	then
                        	apt-get autoremove -y --purge openssh-server ssh 
	         	else
				cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
				sed -i 's/^#*\s*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*UsePAM .*/UsePAM no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*Protocol .*/Protocol 2/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*AllowTcpForwarding .*/AllowTcpForwarding no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*LogLevel .*/LogLevel VERBOSE/' /etc/ssh/sshd_config
				
				echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
				echo "MaxSessions 2" >> /etc/ssh/sshd_config
				echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
                	fi
        else
                	read -p "Does SSH need to be installed? [y/n]: " a
                	if [ $a = y ];
                	then
                        	apt-get install -y openssh-server ssh
				wait
				# Harden SSH and create backup
    				cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
				sed -i 's/^#*\s*PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*PermitEmptyPasswords .*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*ChallengeResponseAuthentication .*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*UsePAM .*/UsePAM no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*Protocol .*/Protocol 2/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*AllowTcpForwarding .*/AllowTcpForwarding no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*X11Forwarding .*/X11Forwarding no/' /etc/ssh/sshd_config
				sed -i 's/^#*\s*LogLevel .*/LogLevel VERBOSE/' /etc/ssh/sshd_config
				
				echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
				echo "MaxSessions 2" >> /etc/ssh/sshd_config
				echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
			fi
        	fi
}

hidden(){
	VALID_SHELLS="/bin/sh /bin/bash /bin/zsh /bin/tcsh /bin/csh"

 	# Scanning....
	echo "Potentially hidden users:"
	
	# Loop through each line in /etc/passwd
	while IFS=: read -r username _ uid _ _ _ user_shell; do
	    # Check if UID is below 1000 and the shell is valid
	    if [[ $uid -lt 1000 ]] && [[ $VALID_SHELLS =~ $user_shell ]]; then
	        echo "$username (UID: $uid, Shell: $user_shell)"
	    fi
	done < /etc/passwd

 	echo "All Users:"
  	while IFS=: read -r username _ uid _ _ _ user_shell; do
	        echo "$username (UID: $uid, Shell: $user_shell)"
	done < /etc/passwd
}

login_config(){
cp /etc/login.defs /etc/login.defs.backup

# Set password minimum length to 12
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   12/' /etc/login.defs

# Set password maximum age to 60 days
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   60/' /etc/login.defs

# Set password minimum age to 7 days
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs

# Set password warning age to 7 days
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Set maximum number of login retries to 5
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   5/' /etc/login.defs

# Set maximum number of days a password may be left unused
sed -i 's/^INACTIVE.*/INACTIVE   30/' /etc/login.defs

# Ensure default group for new users is set to users
sed -i 's/^USERGROUPS_ENAB.*/USERGROUPS_ENAB yes/' /etc/login.defs

# Set default umask for users to 027
sed -i 's/^UMASK.*/UMASK   027/' /etc/login.defs

# Change encryption to SHA512
sed -i 's/^\(ENCRYPT_METHOD\s*\).*$/\1 SHA512/' /etc/login.defs

echo "login.defs has been secured. Original configuration was backed up to /etc/login.defs.backup"
}

pam(){
cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup
cp /etc/pam.d/common-password /etc/pam.d/common-password.backup

# Enforce account lockout after failed attempts
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" >> /etc/pam.d/common-auth

# Strengthen password requirements
echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=7 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 reject_username maxrepeat=3 maxsequence=3" >> /etc/pam.d/common-password

# Use SHA-512 for password hashing
sed -i 's/password\s*common\s*pam_unix\.so/password    common    pam_unix.so sha512/' /etc/pam.d/common-password

# Password history enforcement (remember 5 passwords)
echo "password requisite pam_unix.so remember=5" >> /etc/pam.d/common-password

echo "PAM configurations have been hardened. Original configurations were backed up with .backup extensions."
}

updates_config(){
# 1. Ensure the system regularly checks for updates.
echo "APT::Periodic::Update-Package-Lists \"1\";" > /etc/apt/apt.conf.d/10periodic
echo "APT::Periodic::Download-Upgradeable-Packages \"1\";" >> /etc/apt/apt.conf.d/10periodic
echo "APT::Periodic::AutocleanInterval \"7\";" >> /etc/apt/apt.conf.d/10periodic

# 2. Ensure only trusted repositories are used.
# This is just an example, you might need to customize based on which repositories you trust.
sed -i '/http:\/\/ppa\.launchpad\.net/d' /etc/apt/sources.list
sed -i '/http:\/\/archive\.canonical\.com/d' /etc/apt/sources.list

# 3. Automate the installation of security updates.
sudo apt install -y unattended-upgrades

# Enable automatic updates
echo 'Unattended-Upgrade::Automatic-Reboot "true";' > /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades

# 4. Remove unnecessary or deprecated software repositories.
# As an example, we're removing the CD-ROM source (commonly left in sources.list but rarely used).
sed -i '/cdrom:/d' /etc/apt/sources.list

# Update package list after making changes.
sudo apt update

echo "Ubuntu update settings have been hardened."
}

shadow() {
	chmod 640 /etc/shadow
	ls -l /etc/shadow
	echo "Shadow has been secured."
}

remove(){
declare -A software_list=(
    ["telnet"]="Telnet server"
    ["vsftpd"]="FTP server"
    ["apache2"]="Apache Web Server"
    ["ncat"]="Netcat"
    ["nmap"]="Network Mapper"
    ["hydra"]="Hydra"
    ["john"]="John the Ripper"
    ["wireshark"]="Wireshark"
    ["metasploit-framework"]="Metasploit"
    ["nginx"]="NGINX"
    ["samba"]="Samba"
    ["bind9"]="DNS"
    ["tftpd"]="TFTPD"
    ["ftp"]="FTP"
    ["x11vnc"]="x11VNC"
    ["tightvncserver"]="Tight VNC"
    ["nfs-kernel-server"]="NFS"
    ["snmp"]="SNMP"
    ["postfix"]="Postfix"
    ["sendmail"]="Sendmail"
    ["xinetd"]="Xinetd"
    ["ophcrack"]="Ophcrack"
    ["snort"]="Snort"
    
)

# Ask user about each software and remove if desired
for software in "${!software_list[@]}"; do
    if dpkg -l | grep -q "^ii  $software "; then
        echo "Found ${software_list[$software]}"
        read -p "Do you want to remove $software? (y/N) " choice
        case "$choice" in
            y|Y) 
                echo "Removing $software..."
                apt-get purge --auto-remove -y $software
                ;;
            *)
                echo "$software kept."
                ;;
        esac
    fi
done
}

secure_misc(){
# Harden Apache2
if dpkg -l | grep -q "^ii  apache2 "; then
    echo "Hardening Apache2..."

    # Backup the apache2.conf file
    cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.backup

    # Turn off server tokens
    sed -i 's/ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-enabled/security.conf

    # Turn off server signature
    sed -i 's/ServerSignature On/ServerSignature Off/' /etc/apache2/conf-enabled/security.conf

    # Disable directory listing
    sed -i 's/Options Indexes FollowSymLinks/Options -Indexes +FollowSymLinks/' /etc/apache2/apache2.conf

    chown -R root:root /etc/apache2
    chown -R root:root /etc/apache
    echo "\<Directory \>" >> /etc/apache2/apache2.conf
    echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
    echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
    echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
    echo "UserDir disabled root" >> /etc/apache2/apache2.conf

    # Restart Apache2 to apply changes
    systemctl restart apache2
    echo "Apache2 hardened."
fi

# Harden vsftpd
if dpkg -l | grep -q "^ii  vsftpd "; then
    echo "Hardening vsftpd..."

    # Backup the vsftpd.conf file
    cp /etc/vsftpd.conf /etc/vsftpd.conf.backup

    # Disable anonymous logins
    echo "anonymous_enable=NO" >> /etc/vsftpd.conf

    # Enable local users
    echo "local_enable=YES" >> /etc/vsftpd.conf

    # Jail users to their home directory
    echo "chroot_local_user=YES" >> /etc/vsftpd.conf

    # Prevent write access for anonymous users
    echo "write_enable=NO" >> /etc/vsftpd.conf

    # Restart vsftpd to apply changes
    systemctl restart vsftpd
    echo "vsftpd hardened."

    sudo gsettings set org.gnome.desktop.session idle-delay 240
    sudo gsettings get org.gnome.desktop.screensaver lock-enabled true
    echo "Secured idle delay and screensaver lock."
    
fi
}

sysctl(){
cp /etc/sysctl.conf /etc/sysctl.conf.backup

# Define security settings
declare -A settings

settings["net.ipv4.conf.default.rp_filter"]="1"
settings["net.ipv4.conf.all.rp_filter"]="1"
settings["net.ipv4.tcp_syncookies"]="1"
settings["net.ipv4.conf.all.accept_redirects"]="0"
settings["net.ipv6.conf.all.accept_redirects"]="0"
settings["net.ipv4.conf.all.send_redirects"]="0"
settings["net.ipv4.conf.all.accept_source_route"]="0"
settings["net.ipv6.conf.all.accept_source_route"]="0"
settings["net.ipv4.conf.all.log_martians"]="1"
settings["fs.file-max"]="65535"
settings["net.ipv4.tcp_tw_recycle"]="0"
settings["net.ipv4.tcp_tw_reuse"]="1"
settings["net.ipv4.ip_forward"]="0"       # Disable IPv4 forwarding
settings["net.ipv6.conf.all.forwarding"]="0"


# Replace or add settings in sysctl.conf
for key in "${!settings[@]}"; do
    # Remove the existing setting if it's there
    sed -i "/^${key}=/d" /etc/sysctl.conf
    # Append the new setting
    echo "${key}=${settings[$key]}" >> /etc/sysctl.conf
done

# Reload sysctl settings
sysctl -p
}
pwquality(){

PWQUALITY_CONF_PATH="/etc/security/pwquality.conf"
# Change settings to be more secure
sed -i 's/^\(minlen\s*=\s*\).*$/\1 12/' $PWQUALITY_CONF_PATH
sed -i 's/^\(dcredit\s*=\s*\).*$/\1 -1/' $PWQUALITY_CONF_PATH
sed -i 's/^\(ucredit\s*=\s*\).*$/\1 -1/' $PWQUALITY_CONF_PATH
sed -i 's/^\(ocredit\s*=\s*\).*$/\1 -1/' $PWQUALITY_CONF_PATH
sed -i 's/^\(lcredit\s*=\s*\).*$/\1 -1/' $PWQUALITY_CONF_PATH
sed -i 's/^\(maxrepeat\s*=\s*\).*$/\1 3/' $PWQUALITY_CONF_PATH
sed -i 's/^\(maxclassrepeat\s*=\s*\).*$/\1 3/' $PWQUALITY_CONF_PATH
sed -i 's/^\(gecoscheck\s*=\s*\).*$/\1 1/' $PWQUALITY_CONF_PATH
sed -i 's/^\(dictpath\s*=\s*\).*$/\1 \/usr\/share\/dict\/words/' $PWQUALITY_CONF_PATH

# If a setting does not exist in the file, append it
grep -q "^minlen" $PWQUALITY_CONF_PATH || echo "minlen = 12" >> $PWQUALITY_CONF_PATH
grep -q "^dcredit" $PWQUALITY_CONF_PATH || echo "dcredit = -1" >> $PWQUALITY_CONF_PATH
grep -q "^ucredit" $PWQUALITY_CONF_PATH || echo "ucredit = -1" >> $PWQUALITY_CONF_PATH
grep -q "^ocredit" $PWQUALITY_CONF_PATH || echo "ocredit = -1" >> $PWQUALITY_CONF_PATH
grep -q "^lcredit" $PWQUALITY_CONF_PATH || echo "lcredit = -1" >> $PWQUALITY_CONF_PATH
grep -q "^maxrepeat" $PWQUALITY_CONF_PATH || echo "maxrepeat = 3" >> $PWQUALITY_CONF_PATH
grep -q "^maxclassrepeat" $PWQUALITY_CONF_PATH || echo "maxclassrepeat = 3" >> $PWQUALITY_CONF_PATH
grep -q "^gecoscheck" $PWQUALITY_CONF_PATH || echo "gecoscheck = 1" >> $PWQUALITY_CONF_PATH
grep -q "^dictpath" $PWQUALITY_CONF_PATH || echo "dictpath = /usr/share/dict/words" >> $PWQUALITY_CONF_PATH

# Set the file permissions so that only root can read and write
chmod 600 $PWQUALITY_CONF_PATH

echo "pwquality.conf has been updated and secured."
}

grub(){

}

	logo
	ufw
	users
 	ssh
  	login_config
    	updates_config
     	shadow
      	remove
       	sysctl
        secure_misc
	pwquality
        echo "Script complete. // lunar //"
    	
   	
