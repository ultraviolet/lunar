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
sudo ufw enable
sudo ufw status
echo "UFW has been enabled."
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

echo "Script completed."
}


	logo
	ufw
	users
 	ssh
  	login_config
   	pam
    	updates_config
     	shadow
      	remove
      
    	
   	
