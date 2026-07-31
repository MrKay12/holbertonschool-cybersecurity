#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Erreur : execution root requise." >&2; exit 1; }
CONFIG_FILE="${CONFIG_FILE:-/etc/logicorp/hardening.conf}"
[[ -r "$CONFIG_FILE" ]] || { echo "Erreur : configuration absente : $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"

package_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }
service_exists() { systemctl list-unit-files "${1}.service" --no-legend 2>/dev/null | grep -q "^${1}\.service"; }
backup_once() { [[ ! -e "$1" || -e "$1.pre-hardening" ]] || cp -a "$1" "$1.pre-hardening"; }

required_packages=(openssh-server nftables wireguard fail2ban)
missing=()
for pkg in "${required_packages[@]}"; do package_installed "$pkg" || missing+=("$pkg"); done
if ((${#missing[@]})); then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y "${missing[@]}"
fi

for pkg in "${REMOVE_PACKAGES[@]}"; do
    package_installed "$pkg" && apt-get purge -y "$pkg"
done

for service in "${DISABLED_SERVICES[@]}"; do
    service_exists "$service" && systemctl disable --now "${service}.service" || true
done

groupadd -f "$SSH_ALLOWED_GROUP"
for user in "${SSH_ALLOWED_USERS[@]}"; do
    id "$user" >/dev/null 2>&1 || { echo "Erreur : utilisateur inconnu : $user" >&2; exit 1; }
    usermod -aG "$SSH_ALLOWED_GROUP" "$user"
    if [[ "$SSH_REQUIRE_AUTHORIZED_KEY" == "yes" ]]; then
        home_dir="$(getent passwd "$user" | cut -d: -f6)"
        [[ -s "$home_dir/.ssh/authorized_keys" ]] || {
            echo "Erreur : aucune cle autorisee pour $user ; SSH ne sera pas durci." >&2
            exit 1
        }
    fi
done

if [[ "$SSH_REQUIRE_AUTHORIZED_KEY" == "yes" && ${#SSH_ALLOWED_USERS[@]} -eq 0 ]]; then
    echo "Erreur : SSH_ALLOWED_USERS est vide. Refus de desactiver les mots de passe." >&2
    exit 1
fi

SSH_DROPIN="/etc/ssh/sshd_config.d/99-logicorp-hardening.conf"
backup_once "$SSH_DROPIN"
cat > "$SSH_DROPIN" <<EOF_SSH
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowGroups ${SSH_ALLOWED_GROUP}
EOF_SSH

sshd -t
systemctl enable ssh >/dev/null
systemctl reload ssh

cat > /etc/fail2ban/jail.d/sshd.local <<EOF_F2B
[sshd]
enabled = true
port = ${SSH_PORT}
maxretry = 5
findtime = 10m
bantime = 1h
backend = systemd
EOF_F2B
systemctl enable --now fail2ban >/dev/null
systemctl restart fail2ban

cat > /etc/sysctl.d/99-logicorp-hardening.conf <<'EOF_SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF_SYSCTL
sysctl --system >/dev/null

echo "Durcissement systeme applique de maniere idempotente."
