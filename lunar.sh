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
            usermod -aG sudo "$user"
            echo "$user is now an admin."
            ;;
        2)
            deluser "$user" sudo
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
apt update
apt install -y ufw
ufw enable
ufw status
echo "UFW has been enabled."
}

logo(){
echo "			    //            __      ___      __     		"
echo "        // //   / / //   ) ) //   ) ) //  ) )       "
echo "       // //   / / //   / / //   / / //             "
echo "      // ((___( ( //   / / ((___( ( //              "
}

do
	logo
	ufw
	users
done
