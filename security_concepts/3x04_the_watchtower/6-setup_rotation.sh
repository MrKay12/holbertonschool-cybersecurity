#!/bin/bash

cat > /etc/logrotate.d/secure_remote << EOF
/var/log/secure_remote.log {
    daily
    rotate 7
    compress
    missingok
}
EOF