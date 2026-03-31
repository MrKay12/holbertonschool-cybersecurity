#!/bin/bash

cat > /usr/local/bin/audit-read-secret <<'EOF'
#!/bin/sh
cat /var/www/html/secret_config.php
EOF

chown root:root /usr/local/bin/audit-read-secret
chmod 755 /usr/local/bin/audit-read-secret

cat > /etc/sudoers.d/audit-read-secret <<EOF
$1 ALL=(root) NOPASSWD: /usr/local/bin/audit-read-secret
EOF

chmod 440 /etc/sudoers.d/audit-read-secret