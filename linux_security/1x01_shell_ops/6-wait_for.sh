#!/bin/bash

host="${1:-127.0.0.1}"

until (echo > "/dev/tcp/$host/80") >/dev/null 2>&1; do
   echo "Waiting..."
   sleep 1
done

echo "Service UP!"
