#!/bin/bash
grep -h "dhcp-server-identifier" /var/lib/dhcp/*.leases 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';'