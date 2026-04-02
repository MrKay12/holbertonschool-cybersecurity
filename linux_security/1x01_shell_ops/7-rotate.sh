#!/bin/bash

if ! ls $1 &>/dev/null; then
	exit 1
else
    mkdir -p "$dir/backups"

    for file in "$dir"/*.log; do
        [ -f "$file" ] || continue

        if [ "$(wc -c < "$file")" -gt 1024 ]; then
            gzip "$file"
            mv "$file.gz" "$dir/backups/"
        else
            echo "Skipping small file: $(basename "$file")"
        fi
    done
fi
