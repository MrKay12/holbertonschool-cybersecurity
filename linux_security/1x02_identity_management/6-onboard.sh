#!/bin/bash
useradd -m "$1"
passwd -l "$1"
mkdir -p /home/"$1"/.ssh
echo "$2" > /home/"$1"/.ssh/authorized_keys
chmod 700 /home/"$1"/.ssh
chmod 600 /home/"$1"/.ssh/authorized_keys
chown -R "$1":"$1" /home/"$1"/.ssh
