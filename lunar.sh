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
				sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config

							
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
				pause
                	fi
        else
                	read -p "Does SSH need to be installed? [y/n]: " a
                	if [ $a = y ];
                	then
                        	apt-get install -y openssh-server ssh
				wait
				sed -i 's/LoginGraceTime .*/LoginGraceTime 60/g' /etc/ssh/sshd_config
                        	sed -i 's/PermitRootLogin .*/PermitRootLogin no/g' /etc/ssh/sshd_config
                        	sed -i 's/Protocol .*/Protocol 2/g' /etc/ssh/sshd_config
                        	sed -i 's/#PermitEmptyPasswords .*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
                        	sed -i 's/PasswordAuthentication .*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
                        	sed -i 's/X11Forwarding .*/X11Forwarding no/g' /etc/ssh/sshd_config
							
							sed -i '$a AllowUsers' /etc/ssh/sshd_config
							for x in `cat users`
							do
								sed -i "/^AllowUser/ s/$/ $x /" /etc/ssh/sshd_config
							done
				
			fi
        	fi
}

	logo
	ufw
	users
 	ssh
