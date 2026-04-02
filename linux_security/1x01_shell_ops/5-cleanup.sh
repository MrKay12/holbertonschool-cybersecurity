#!/bin/bash
while read username; do
	[ -z "$username" ] && continue

	if id "$username" >/dev/null 2>&1; then
		usermod -L "$username"
		echo "User $username locked"
	else
		echo "User $username not found"
	fi
done < "$1"
