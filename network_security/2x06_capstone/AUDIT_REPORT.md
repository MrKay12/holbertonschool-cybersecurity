# Audit Report - LogiCorp Gateway

## Executive Overview

A live technical assessment was performed directly on the LogiCorp gateway.
The audit examined the runtime environment, network topology, exposed services,
security controls, user access, scheduled tasks, application files, logs and
potential persistence mechanisms.

The assessment was conducted in read-only mode. Because the environment does
not necessarily use systemd as PID 1, findings are based primarily on process
inspection, network sockets, configuration files, startup scripts and runtime
artifacts.

The audit also distinguishes observed runtime activity from events deliberately
written into logs by laboratory initialization scripts. Injected log lines are
not treated as independent proof of a real intrusion.

## Scope and Method

- Assessment type: black-box technical audit
- Collection date: 2026-07-29 14:09:06 UTC
- Current user: student
- Evidence directory: `audit_evidence/`

## Evidence directory structure

| Directory | Contents |
|---|---|
| `01_system/` | Host, operating system, processes, mounts and startup scripts |
| `02_network/` | Interfaces, routes, neighbors, DNS, bridges and VLANs |
| `03_attack_surface/` | Listening ports, active connections and exposed processes |
| `04_security_controls/` | Firewall, SELinux, AppArmor, Fail2Ban and Suricata |
| `05_users_access/` | Accounts, privileges, SSH keys and sensitive permissions |
| `06_ssh/` | SSH configuration and effective security settings |
| `07_services/` | Running and installed services, including legacy services |
| `08_persistence/` | Cron jobs and other persistence mechanisms |
| `09_ftp/` | FTP service, configuration, permissions and findings |
| `10_sensitive_data/` | LogiCorp files and exposed secrets |
| `11_logs/` | Authentication, system and application logs |
| `12_intrusion_analysis/` | Injected events, unexplained activity and intrusion artifacts |
| `13_flags/` | Targeted flag searches and evidence index |
- System modifications: none

## 1. System Information

- Hostname: `18818412c63a431594f9fbc4f129e696-2377118072`
- OS: `Ubuntu 22.04.5 LTS`
- Kernel: `6.1.176`
- Architecture: `x86_64`
- Uptime: `up 56 minutes`

### PID 1

```text
Command: ps -p 1 -o pid,ppid,user,group,comm,args

    PID    PPID USER     GROUP    COMMAND         COMMAND
      1       0 root     root     sh              /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh
```


### Startup Script Security Analysis

- Lab simulation assessment: `Startup scripts explicitly inject simulated attack events into log files`
- Password initialization assessment: `A startup script changes account passwords; context and intent must be verified`

```text
Command: 
for file in /etc/run.sh /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh; do
    [ -r "$file" ] || continue

    echo "===== $file ====="

    grep -nE     "fake attack log|brute force source|chpasswd|passwd[[:space:]]|nft[[:space:]]+flush[[:space:]]+ruleset|ttyd|openvscode-server|code-server|setup_ssh|auth\.log|suricata/fast\.log"     "$file" 2>/dev/null || true

    echo
done


===== /etc/run.sh =====
17:echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd
20:python3 /etc/ssh/setup_ssh.py
21:rm /etc/ssh/setup_ssh.py
34:nft flush ruleset 2>/dev/null
36:# fake attack log
37:echo "Feb 12 12:00:00 sandbox sshd[123]: Failed password for root from 10.10.10.10 port 5555 ssh2" >> /var/log/auth.log
38:echo "FLAG{1DS_D3T3CT10N_W0RKS}" >> /var/log/suricata/fast.log
40:# brute force source
43:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
44:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
45:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
46:echo "Accepted password for root from 192.168.1.99 port 5555 ssh2" >> /var/log/auth.log
49:ttyd --cwd /root --writable --credential=$(echo $HOSTNAME | cut -d '-' -f 1):$(echo $HOSTNAME | cut -d '-' -f 1) -p 3001 /bin/bash &
52:openvscode-server --host 0.0.0.0 --connection-token=$(echo $HOSTNAME | cut -d '-' -f 1) --log off 2&>1
```

### Log Entries Injected by Startup Scripts

```text
Command: 
for file in /etc/run.sh /entrypoint.sh /docker-entrypoint.sh /usr/local/bin/entrypoint.sh; do
    [ -r "$file" ] || continue

    echo "===== $file ====="
    grep -nE     "echo .*(auth\.log|secure|syslog|messages|suricata/fast\.log)"     "$file" 2>/dev/null || true
    echo
done


===== /etc/run.sh =====
37:echo "Feb 12 12:00:00 sandbox sshd[123]: Failed password for root from 10.10.10.10 port 5555 ssh2" >> /var/log/auth.log
38:echo "FLAG{1DS_D3T3CT10N_W0RKS}" >> /var/log/suricata/fast.log
43:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
44:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
45:echo "Failed password for invalid user admin from $ATTACK_IP port 4444 ssh2" >> /var/log/auth.log
46:echo "Accepted password for root from 192.168.1.99 port 5555 ssh2" >> /var/log/auth.log
```

The presence of commands such as `chpasswd`, `nft flush ruleset`, `ttyd`
or `openvscode-server` in a startup script confirms insecure initialization
or exposure. It does not, by itself, prove that an external attacker executed
the commands.

## 2. Network Topology

### Interfaces

```text
lo               UNKNOWN        127.0.0.1/8 ::1/128 
eth0@if5         UP             169.254.172.2/22 fe80::1ca6:32ff:fece:f8f6/64 
eth1             UP             10.42.85.186/16 fe80::8ae:32ff:fecb:4b39/64 
```

### Routes

```text
default via 10.42.0.1 dev eth1 
10.42.0.0/16 dev eth1 proto kernel scope link src 10.42.85.186 
blackhole 169.254.169.254 
169.254.170.2 via 169.254.172.1 dev eth0 
169.254.172.1 dev eth0 scope link 
```

### ARP and Neighbor Table

```text
Command: ip neigh show

10.42.0.1 dev eth1 lladdr 0a:b0:93:32:a4:d0 REACHABLE
```

### Topology Observations

The observed interfaces, addresses, routes and neighbors must be compared with
the documented flat network in `192.168.1.0/24`. Any different ranges,
additional interfaces, bridges or VLANs constitute documentation discrepancies.

## 3. Attack Surface

### Listening TCP and UDP Ports

```text
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                                            
tcp   LISTEN 0      511          0.0.0.0:3000      0.0.0.0:*    ino:20410 sk:1 cgroup:unreachable:820 <->         
tcp   LISTEN 0      4096         0.0.0.0:3001      0.0.0.0:*    ino:20403 sk:2 cgroup:unreachable:820 <->         
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    ino:20356 sk:3 cgroup:unreachable:820 <->         
tcp   LISTEN 0      128             [::]:22           [::]:*    ino:20358 sk:4 cgroup:unreachable:820 v6only:1 <->
tcp   LISTEN 0      32                 *:21              *:*    ino:21044 sk:5 cgroup:unreachable:820 v6only:0 <->
```

### Network-Facing Processes

```text
Command: 
ps auxww |
grep -Ei \
"[s]shd|[v]sftpd|[p]roftpd|[p]ure-ftpd|[t]tyd|[o]penvscode|[c]ode-server|[a]pache|[n]ginx|[m]ysql|[m]ariadb|[p]ostgres|[s]uricata|[s]nort|[d]nsmasq|[n]amed|[s]quid|[t]elnet|[c]url|[w]get" || true


root          63  0.0  0.2  10160  4324 ?        S    13:14   0:00 /usr/sbin/vsftpd
root          89  0.0  0.2  15440  5676 ?        Ss   13:14   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root          91  0.0  0.2   9916  5040 ?        S    13:14   0:00 ttyd --cwd /root --writable --credential=18818412c63a431594f9fbc4f129e696:18818412c63a431594f9fbc4f129e696 -p 3001 /bin/bash
root          98  0.0  0.0   2892   960 ?        S    13:14   0:00 sh /usr/bin/openvscode-server --host 0.0.0.0 --connection-token=18818412c63a431594f9fbc4f129e696 --log off 2
root         116  0.0  2.2 624220 44628 ?        Sl   13:14   0:00 /usr/node /usr/out/bootstrap-fork --type=ptyHost --logsPath /root/.openvscode-server/data/logs/20260729T131425
root         152  0.0  0.5  16892 10640 ?        Ss   13:16   0:00 sshd: student [priv]
student      163  0.0  0.4  17168  8032 ?        S    13:16   0:00 sshd: student@pts/0
root        3538  0.0  0.0   2892   972 ?        Ss   14:07   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3539  0.0  0.4  19428  8424 ?        S    14:07   0:00 /usr/bin/curl http://192.168.1.200/ping
root        3546  0.0  0.0   2892   980 ?        Ss   14:08   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3547  0.0  0.4  19428  8480 ?        S    14:08   0:00 /usr/bin/curl http://192.168.1.200/ping
root        3563  0.0  0.0   2892   952 ?        Ss   14:09   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3564  0.0  0.4  19428  8480 ?        S    14:09   0:00 /usr/bin/curl http://192.168.1.200/ping
```

### Full Process Arguments

```text
Command: 
for process in /proc/[0-9]*; do
    [ -r "$process/cmdline" ] || continue

    pid="${process##*/}"
    cmd="$(tr "\0" " " < "$process/cmdline" 2>/dev/null)"

    if [ -n "$cmd" ]; then
        printf "%s: %s\n" "$pid" "$cmd"
    fi
done


1: /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh 
105: /usr/node /usr/out/server-main.js --host 0.0.0.0 --connection-token=18818412c63a431594f9fbc4f129e696 --log off 2 
116: /usr/node /usr/out/bootstrap-fork --type=ptyHost --logsPath /root/.openvscode-server/data/logs/20260729T131425 
152: sshd: student [priv] 
163: sshd: student@pts/0 
164: -bash 
27: /bin/bash /etc/run.sh 
3537: /usr/sbin/CRON -P 
3538: /bin/sh -c /usr/bin/curl http://192.168.1.200/ping 
3539: /usr/bin/curl http://192.168.1.200/ping 
3545: /usr/sbin/CRON -P 
3546: /bin/sh -c /usr/bin/curl http://192.168.1.200/ping 
3547: /usr/bin/curl http://192.168.1.200/ping 
3562: /usr/sbin/CRON -P 
3563: /bin/sh -c /usr/bin/curl http://192.168.1.200/ping 
3564: /usr/bin/curl http://192.168.1.200/ping 
3565: bash /home/student/audit.sh 
3652: bash -c 
for process in /proc/[0-9]*; do
    [ -r "$process/cmdline" ] || continue

    pid="${process##*/}"
    cmd="$(tr "\0" " " < "$process/cmdline" 2>/dev/null)"

    if [ -n "$cmd" ]; then
        printf "%s: %s\n" "$pid" "$cmd"
    fi
done
 
63: /usr/sbin/vsftpd 
78: /usr/sbin/cron -P 
89: sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups 
91: ttyd --cwd /root --writable --credential=18818412c63a431594f9fbc4f129e696:18818412c63a431594f9fbc4f129e696 -p 3001 /bin/bash 
98: sh /usr/bin/openvscode-server --host 0.0.0.0 --connection-token=18818412c63a431594f9fbc4f129e696 --log off 2 
```

## 4. Security Controls

- Firewall observation: `No active firewall rules confirmed`
- SSH PermitRootLogin: `Unknown`
- SSH PasswordAuthentication: `Unknown`

### nftables

```text
Command: 
if command -v nft >/dev/null 2>&1; then
    nft list ruleset
else
    echo "nft unavailable"
fi


Operation not permitted (you must be root)
```

### iptables

```text
Command: 
if command -v iptables >/dev/null 2>&1; then
    echo "===== FILTER ====="
    iptables -L -n -v --line-numbers
    echo
    iptables -S
    echo

    echo "===== NAT ====="
    iptables -t nat -L -n -v --line-numbers
    echo
    iptables -t nat -S
    echo

    echo "===== MANGLE ====="
    iptables -t mangle -L -n -v --line-numbers
else
    echo "iptables unavailable"
fi


iptables unavailable
```

### SELinux

```text
Command: 
if command -v getenforce >/dev/null 2>&1; then
    getenforce
    sestatus 2>/dev/null || true
else
    echo "SELinux unavailable"
fi


SELinux unavailable
```

### AppArmor

```text
Command: 
if command -v aa-status >/dev/null 2>&1; then
    aa-status
elif [ -r /sys/module/apparmor/parameters/enabled ]; then
    cat /sys/module/apparmor/parameters/enabled
else
    echo "AppArmor unavailable"
fi


AppArmor unavailable
```

## 5. Access Control and Identity

### Login-Capable Users

```text
Command: 
awk -F: '
$7 !~ /(nologin|false|sync|shutdown|halt)$/ {
    print $1 ":" $3 ":" $4 ":" $6 ":" $7
}' /etc/passwd


root:0:0:/root:/bin/bash
student:1000:1000:/home/student:/bin/bash
```

### UID 0 Accounts

```text
Command: 
awk -F: '$3 == 0 {print}' /etc/passwd


root:x:0:0:root:/root:/bin/bash
```

### Administrative Groups

```text
Command: 
getent group sudo 2>/dev/null || true
getent group wheel 2>/dev/null || true
getent group adm 2>/dev/null || true
getent group docker 2>/dev/null || true


sudo:x:27:
adm:x:4:
```

### Effective SSH Security Settings

```text
Command: 
if command -v sshd >/dev/null 2>&1; then
    sshd -T 2>/dev/null |
    grep -E \
    "^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|allowusers|allowgroups|denyusers|denygroups|maxauthtries)"
fi
```

## 6. Running Services

```text
Command: 
if command -v service >/dev/null 2>&1; then
    service --status-all
else
    echo "service command unavailable"
fi


 [ + ]  cron
 [ - ]  dbus
 [ - ]  fail2ban
 [ ? ]  hwclock.sh
 [ - ]  openbsd-inetd
 [ - ]  procps
 [ + ]  ssh
 [ + ]  suricata
 [ + ]  vsftpd
 [ - ]  x11-common
```

### Relevant Runtime Processes

```text
Command: 
ps auxww |
grep -Ei \
"[s]shd|[v]sftpd|[p]roftpd|[p]ure-ftpd|[t]tyd|[o]penvscode|[c]ode-server|[a]pache|[n]ginx|[m]ysql|[m]ariadb|[p]ostgres|[s]uricata|[s]nort|[d]nsmasq|[n]amed|[s]quid|[t]elnet|[c]url|[w]get" || true


root          63  0.0  0.2  10160  4324 ?        S    13:14   0:00 /usr/sbin/vsftpd
root          89  0.0  0.2  15440  5676 ?        Ss   13:14   0:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups
root          91  0.0  0.2   9916  5040 ?        S    13:14   0:00 ttyd --cwd /root --writable --credential=18818412c63a431594f9fbc4f129e696:18818412c63a431594f9fbc4f129e696 -p 3001 /bin/bash
root          98  0.0  0.0   2892   960 ?        S    13:14   0:00 sh /usr/bin/openvscode-server --host 0.0.0.0 --connection-token=18818412c63a431594f9fbc4f129e696 --log off 2
root         116  0.0  2.2 624220 44628 ?        Sl   13:14   0:00 /usr/node /usr/out/bootstrap-fork --type=ptyHost --logsPath /root/.openvscode-server/data/logs/20260729T131425
root         152  0.0  0.5  16892 10640 ?        Ss   13:16   0:00 sshd: student [priv]
student      163  0.0  0.4  17168  8032 ?        S    13:16   0:00 sshd: student@pts/0
root        3538  0.0  0.0   2892   972 ?        Ss   14:07   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3539  0.0  0.4  19428  8424 ?        S    14:07   0:00 /usr/bin/curl http://192.168.1.200/ping
root        3546  0.0  0.0   2892   980 ?        Ss   14:08   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3547  0.0  0.4  19428  8480 ?        S    14:08   0:00 /usr/bin/curl http://192.168.1.200/ping
root        3563  0.0  0.0   2892   952 ?        Ss   14:09   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3564  0.0  0.4  19428  8480 ?        S    14:09   0:00 /usr/bin/curl http://192.168.1.200/ping
```

## 7. Scheduled Tasks and Persistence

### System Cron Files

```text
Command: 
for file in /etc/crontab /etc/cron.d/*; do
    if [ -f "$file" ]; then
        echo "===== $file ====="
        ls -l "$file"
        cat "$file"
        echo
    fi
done

for directory in \
    /etc/cron.hourly \
    /etc/cron.daily \
    /etc/cron.weekly \
    /etc/cron.monthly
do
    if [ -d "$directory" ]; then
        echo "===== $directory ====="
        find "$directory" \
            -maxdepth 1 \
            -type f \
            -printf "%M %u:%g %p\n" \
            -exec sed -n "1,300p" {} \;
        echo
    fi
done


===== /etc/crontab =====
-rw-r--r--. 1 root root 1136 Mar 23  2022 /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#

===== /etc/cron.d/e2scrub_all =====
-rw-r--r--. 1 root root 201 Jan  8  2022 /etc/cron.d/e2scrub_all
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r

===== /etc/cron.d/logicorp =====
-rw-r--r--. 1 root root 77 Feb 12 19:25 /etc/cron.d/logicorp
* * * * * root /usr/bin/curl http://192.168.1.200/ping
# FLAG{CR0N_B4CKD00R}

===== /etc/cron.hourly =====
-rw-r--r-- root:root /etc/cron.hourly/.placeholder
# DO NOT EDIT OR REMOVE
# This file is a simple placeholder to keep dpkg from removing this directory

===== /etc/cron.daily =====
-rwxr-xr-x root:root /etc/cron.daily/dpkg
#!/bin/sh

# Skip if systemd is running.
if [ -d /run/systemd/system ]; then
  exit 0
fi

/usr/libexec/dpkg/dpkg-db-backup
-rwxr-xr-x root:root /etc/cron.daily/apt-compat
#!/bin/sh

set -e

# Systemd systems use a systemd timer unit which is preferable to
# run. We want to randomize the apt update and unattended-upgrade
# runs as much as possible to avoid hitting the mirrors all at the
# same time. The systemd time is better at this than the fixed
# cron.daily time
if [ -d /run/systemd/system ]; then
    exit 0
fi

check_power()
{
    # laptop check, on_ac_power returns:
    #       0 (true)    System is on main power
    #       1 (false)   System is not on main power
    #       255 (false) Power status could not be determined
    # Desktop systems always return 255 it seems
    if command -v on_ac_power >/dev/null; then
        if on_ac_power; then
            :
        elif [ $? -eq 1 ]; then
            return 1
        fi
    fi
    return 0
}

# sleep for a random interval of time (default 30min)
# (some code taken from cron-apt, thanks)
random_sleep()
{
    RandomSleep=1800
    eval $(apt-config shell RandomSleep APT::Periodic::RandomSleep)
    if [ $RandomSleep -eq 0 ]; then
	return
    fi
    if [ -z "$RANDOM" ] ; then
        # A fix for shells that do not have this bash feature.
	RANDOM=$(( $(dd if=/dev/urandom bs=2 count=1 2> /dev/null | cksum | cut -d' ' -f1) % 32767 ))
    fi
    TIME=$(($RANDOM % $RandomSleep))
    sleep $TIME
}

# delay the job execution by a random amount of time
random_sleep

# ensure we don't do this on battery
check_power || exit 0

# run daily job
exec /usr/lib/apt/apt.systemd.daily
-rw-r--r-- root:root /etc/cron.daily/.placeholder
# DO NOT EDIT OR REMOVE
# This file is a simple placeholder to keep dpkg from removing this directory
-rwxr-xr-x root:root /etc/cron.daily/logrotate
#!/bin/sh

# skip in favour of systemd timer
if [ -d /run/systemd/system ]; then
    exit 0
fi

# this cronjob persists removals (but not purges)
if [ ! -x /usr/sbin/logrotate ]; then
    exit 0
fi

/usr/sbin/logrotate /etc/logrotate.conf
EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"
fi
exit $EXITVALUE
-rwxr-xr-x root:root /etc/cron.daily/man-db
#!/bin/sh
#
# man-db cron daily

set -e

if [ -d /run/systemd/system ]; then
    # Skip in favour of systemd timer.
    exit 0
fi

# This should be set by cron, but apparently isn't always; see
# https://bugs.debian.org/209185.  Add fallbacks so that start-stop-daemon
# can be found.
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

iosched_idle=
# Don't try to change I/O priority in a vserver or OpenVZ.
if ! egrep -q '(envID|VxID):.*[1-9]' /proc/self/status && \
   ([ ! -d /proc/vz ] || [ -d /proc/bc ]); then
    iosched_idle='--iosched idle'
fi

if ! [ -d /var/cache/man ]; then
    # Recover from deletion, per FHS.
    install -d -o man -g man -m 0755 /var/cache/man
fi

# expunge old catman pages which have not been read in a week
if [ -d /var/cache/man ]; then
  cd /
  start-stop-daemon --start --pidfile /dev/null --startas /bin/sh \
	--oknodo --chuid man $iosched_idle -- -c \
	"find /var/cache/man -type f -name '*.gz' -atime +6 -print0 | \
	 xargs -r0 rm -f"
fi

# regenerate man database
if [ -x /usr/bin/mandb ]; then
    # --pidfile /dev/null so it always starts; mandb isn't really a daemon,
    # but we want to start it like one.
    start-stop-daemon --start --pidfile /dev/null \
		      --startas /usr/bin/mandb --oknodo --chuid man \
		      $iosched_idle \
		      -- --no-purge --quiet
fi

exit 0

===== /etc/cron.weekly =====
-rwxr-xr-x root:root /etc/cron.weekly/man-db
#!/bin/sh
#
# man-db cron weekly

set -e

if [ -d /run/systemd/system ]; then
    # Skip in favour of systemd timer.
    exit 0
fi

# This should be set by cron, but apparently isn't always; see
# https://bugs.debian.org/209185.  Add fallbacks so that start-stop-daemon
# can be found.
export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

iosched_idle=
# Don't try to change I/O priority in a vserver or OpenVZ.
if ! egrep -q '(envID|VxID):.*[1-9]' /proc/self/status && \
   ([ ! -d /proc/vz ] || [ -d /proc/bc ]); then
    iosched_idle='--iosched idle'
fi

if ! [ -d /var/cache/man ]; then
    # Recover from deletion, per FHS.
    install -d -o man -g man -m 0755 /var/cache/man
fi

# regenerate man database
if [ -x /usr/bin/mandb ]; then
    # --pidfile /dev/null so it always starts; mandb isn't really a daemon,
    # but we want to start it like one.
    start-stop-daemon --start --pidfile /dev/null \
		      --startas /usr/bin/mandb --oknodo --chuid man \
		      $iosched_idle \
		      -- --quiet
fi

exit 0
-rw-r--r-- root:root /etc/cron.weekly/.placeholder
# DO NOT EDIT OR REMOVE
# This file is a simple placeholder to keep dpkg from removing this directory

===== /etc/cron.monthly =====
-rw-r--r-- root:root /etc/cron.monthly/.placeholder
# DO NOT EDIT OR REMOVE
# This file is a simple placeholder to keep dpkg from removing this directory
```

### Runtime Cron-Related Processes

```text
Command: 
ps auxww |
grep -Ei \
"[c]ron|[c]url|[w]get|192\.168\.1\.200" || true


root          78  0.0  0.1   3888  2076 ?        Ss   13:14   0:00 /usr/sbin/cron -P
root        3545  0.0  0.2   7324  4100 ?        S    14:08   0:00 /usr/sbin/CRON -P
root        3546  0.0  0.0   2892   980 ?        Ss   14:08   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3547  0.0  0.4  19428  8480 ?        S    14:08   0:00 /usr/bin/curl http://192.168.1.200/ping
root        3562  0.0  0.2   7324  4100 ?        S    14:09   0:00 /usr/sbin/CRON -P
root        3563  0.0  0.0   2892   952 ?        Ss   14:09   0:00 /bin/sh -c /usr/bin/curl http://192.168.1.200/ping
root        3564  0.0  0.4  19428  8480 ?        S    14:09   0:00 /usr/bin/curl http://192.168.1.200/ping
```

Any undocumented root cron command, repeated outbound connection, downloaded
script or command contacting an unexpected system should be treated as a
potential persistence or beaconing mechanism.

## 8. Sensitive Data Exposure

### LogiCorp Files

```text
Command: 
for directory in \
    /etc/logicorp \
    /opt/logicorp \
    /srv/ftp \
    /var/lib/logicorp \
    /usr/local/logicorp
do
    [ -d "$directory" ] || continue

    find "$directory" \
        -maxdepth 6 \
        -type f \
        -readable \
        -size -5M \
        -print \
        -exec sh -c '
            echo "===== $1 ====="
            sed -n "1,500p" "$1"
            echo
        ' sh {} \; 2>/dev/null
done


/etc/logicorp/db.conf
===== /etc/logicorp/db.conf =====
DB_HOST=192.168.1.50
DB_PORT=3306
# FLAG{Z3R0_TRU5T_Z0N3S}

/etc/logicorp/telnet.flag
===== /etc/logicorp/telnet.flag =====
# FLAG{UNN3C3SS4RY_S3RV1C3}

/etc/logicorp/network.conf
===== /etc/logicorp/network.conf =====
NETWORK_MODE=FLAT
# FLAG{AUD1T_FL4T_N3TW0RK}

/etc/logicorp/security.policy
===== /etc/logicorp/security.policy =====
root login should never happen
FLAG{R00T_L0G1N_D3T3CT3D}

/opt/logicorp/backups/backup.sql
===== /opt/logicorp/backups/backup.sql =====
root_password_backup=123456
FLAG{S3NS1T1V3_B4CKUP_EXP0S3D}

/srv/ftp/readme.txt
===== /srv/ftp/readme.txt =====
Finance invoices here
```

### Sensitive Content Matches

```text
Command: 
grep -RniE \
"FLAG\{|password|passwd|credential|secret|token|api[_-]?key|root_password|PermitRootLogin|PasswordAuthentication" \
/etc/logicorp \
/opt/logicorp \
/srv/ftp \
/var/ftp \
/home/ftp \
/etc/vsftpd.conf \
/etc/vsftpd \
/etc/ftpusers \
/etc/pam.d/vsftpd \
/var/log/vsftpd.log \
/var/log/xferlog \
/var/log/proftpd \
/etc/cron.d \
/etc/fail2ban \
/var/backups \
2>/dev/null || true


/etc/logicorp/db.conf:3:# FLAG{Z3R0_TRU5T_Z0N3S}
/etc/logicorp/telnet.flag:1:# FLAG{UNN3C3SS4RY_S3RV1C3}
/etc/logicorp/network.conf:2:# FLAG{AUD1T_FL4T_N3TW0RK}
/etc/logicorp/security.policy:2:FLAG{R00T_L0G1N_D3T3CT3D}
/opt/logicorp/backups/backup.sql:1:root_password_backup=123456
/opt/logicorp/backups/backup.sql:2:FLAG{S3NS1T1V3_B4CKUP_EXP0S3D}
/etc/vsftpd.conf:157:# FLAG{CL34RT3XT_FTP}
/etc/cron.d/logicorp:2:# FLAG{CR0N_B4CKD00R}
/etc/fail2ban/action.d/route.conf:11:#   - It's per host, ideal as action against ssh password bruteforcing to block further attack attempts.
/etc/fail2ban/action.d/route.conf:15:#   - Blocking is per IP and NOT per service, but ideal as action against ssh password bruteforcing hosts
/etc/fail2ban/action.d/blocklist_de.conf:10:# This action requires the server 'email address' and the associated apikey.
/etc/fail2ban/action.d/blocklist_de.conf:27:#     password incorrectly.
/etc/fail2ban/action.d/blocklist_de.conf:57:actionban = curl --fail --data-urlencode "server=<email>" --data "apikey=<apikey>" --data "service=<service>" --data "ip=<ip>" --data-urlencode "logs=<matches><br>" --data 'format=text' --user-agent "<agent>" "https://www.blocklist.de/en/httpreports.html"
/etc/fail2ban/action.d/blocklist_de.conf:73:# Option:  apikey
/etc/fail2ban/action.d/blocklist_de.conf:74:# Notes    your user blocklist.de user account apikey
/etc/fail2ban/action.d/blocklist_de.conf:77:#apikey =
/etc/fail2ban/action.d/abuseipdb.conf:16:#     password incorrectly.
/etc/fail2ban/action.d/abuseipdb.conf:19:# This action relies on a api_key being added to the above action conf,
/etc/fail2ban/action.d/abuseipdb.conf:24:#            abuseipdb[abuseipdb_apikey="my-api-key", abuseipdb_category="18,22"]
/etc/fail2ban/action.d/abuseipdb.conf:88:actionban = lgm=$(printf '%%.1000s\n...' "<matches>"); curl -sSf "https://api.abuseipdb.com/api/v2/report" -H "Accept: application/json" -H "Key: <abuseipdb_apikey>" --data-urlencode "comment=$lgm" --data-urlencode "ip=<ip>" --data "categories=<abuseipdb_category>"
/etc/fail2ban/action.d/abuseipdb.conf:99:# Option:  abuseipdb_apikey
/etc/fail2ban/action.d/abuseipdb.conf:104:abuseipdb_apikey =
/etc/fail2ban/action.d/firewallcmd-common.conf:43:#          kpasswd ldap ldaps libvirt libvirt-tls mdns mosh mountd ms-wbt mysql nfs ntp openvpn pmcd pmproxy pmwebapi pmwebapis pop3s 
/etc/fail2ban/action.d/cloudflare.conf:44:#actionban = curl -s -o /dev/null https://www.cloudflare.com/api_json.html -d 'a=ban' -d 'tkn=<cftoken>' -d 'email=<cfuser>' -d 'key=<ip>'
/etc/fail2ban/action.d/cloudflare.conf:59:#actionunban = curl -s -o /dev/null https://www.cloudflare.com/api_json.html -d 'a=nul' -d 'tkn=<cftoken>' -d 'email=<cfuser>' -d 'key=<ip>'
/etc/fail2ban/action.d/cloudflare.conf:68:_cf_api_prms = -H 'X-Auth-Email: <cfuser>' -H 'X-Auth-Key: <cftoken>' -H 'Content-Type: application/json'
/etc/fail2ban/action.d/cloudflare.conf:79:# cfapikey = 
/etc/fail2ban/action.d/cloudflare.conf:81:cftoken =
/etc/fail2ban/action.d/smtp.py:78:		self, jail, name, host="localhost", user=None, password=None,
/etc/fail2ban/action.d/smtp.py:93:		password : str, optional
/etc/fail2ban/action.d/smtp.py:94:			Password used for authentication with SMTP server.
/etc/fail2ban/action.d/smtp.py:115:		self.password =password
/etc/fail2ban/action.d/smtp.py:162:			if self.user and self.password: # pragma: no cover (ATM no tests covering that)
/etc/fail2ban/action.d/smtp.py:163:				smtp.login(self.user, self.password)
/etc/fail2ban/action.d/xarf-login-attack.conf:10:#     password incorrectly.
/etc/fail2ban/action.d/mynetwatchman.conf:9:# <mnwpass> (your mNW password).
/etc/fail2ban/action.d/mynetwatchman.conf:21:# mnwpass = SECRET
/etc/fail2ban/action.d/mynetwatchman.conf:66:            <getcmd> "<mnwurl>?AT=2&AV=0&AgentEmail=$MNWLOGIN&AgentPassword=$MNWPASS&AttackerIP=<ip>&SrcPort=<srcport>&ProtocolID=$PROTOCOL&DestPort=<port>&AttackCount=<failures>&VictimIP=<myip>&AttackDateTime=$DATETIME" 2>&1 >> <tmpfile>.out && grep -q 'Attack Report Insert Successful' <tmpfile>.out && rm -f <tmpfile>.out
/etc/fail2ban/action.d/mynetwatchman.conf:93:# Notes.:  The password corresponding to your mNW login e-mail address. MUST be
/etc/fail2ban/action.d/netscaler.conf:16:# ns_auth: username:password, suggest base64 encoded for a little added security (echo -n "username:password" | base64)
/etc/fail2ban/action.d/nginx-block-map.conf:8:# Example (argument "token_id" resp. cookie "session_id" used here as unique identifier for user):
/etc/fail2ban/action.d/nginx-block-map.conf:13:#     #map $arg_token_id      $blck_lst_tok { include blacklisted-tokens.map; }
/etc/fail2ban/action.d/logicorp-flag.conf:2:actionban = echo FLAG{SSH_BRUTE_BLOCKED} > /opt/logicorp/advanced_flags/ban.flag
/etc/fail2ban/filter.d/oracleims.conf:20:# Notes.:  regex to match the password failures messages
/etc/fail2ban/filter.d/oracleims.conf:45:# mi="Bad password"
/etc/fail2ban/filter.d/oracleims.conf:47:# di="535 5.7.8 Bad username or password (Authentication failed)."/>
/etc/fail2ban/filter.d/oracleims.conf:55:failregex = tr="[A-Z]+\|[0-9.]+\|\d+\|<HOST>\|\d+" ap="[^"]*" mi="Bad password" us="[^"]*" di="535 5.7.8 Bad username or password( \(Authentication failed\))?\."/>$
/etc/fail2ban/filter.d/screensharingd.conf:19:# Notes.:  regex to match the password failures messages in the logfile. The
/etc/fail2ban/filter.d/asterisk.conf:23:failregex = ^Registration from '[^']*' failed for '<HOST>(:\d+)?' - (?:Wrong password|Username/auth name mismatch|No matching peer found|Not a local domain|Device does not match ACL|Peer is not supposed to register|ACL error \(permit/deny\)|Not a local domain)$
/etc/fail2ban/filter.d/asterisk.conf:28:            ^SecurityEvent="(?:FailedACL|InvalidAccountID|ChallengeResponseFailed|InvalidPassword)"(?:(?:,(?!RemoteAddress=)\w+="[^"]*")*|.*?),RemoteAddress="IPV[46]/[^/"]+/<HOST>/\d+"(?:,(?!RemoteAddress=)\w+="[^"]*")*$
/etc/fail2ban/filter.d/monit.conf:21:failregex = ^%(__prefix_line)s(?:error\s*:\s+)?(?:%(_prefix)s):\s+(?:access denied\s+--\s+)?[Cc]lient '?<HOST>'?(?:\s+supplied|\s*:)\s+(?:unknown user '<F-ALT_USER>[^']+</F-ALT_USER>'|wrong password for user '<F-USER>[^']*</F-USER>'|empty password)
/etc/fail2ban/filter.d/dovecot.conf:17:            ^pam\(\S+,<HOST>(?:,\S*)?\): pam_authenticate\(\) failed: (?:User not known to the underlying authentication module: \d+ Time\(s\)|Authentication failure \(password mismatch\?\)|Permission denied)\s*$
/etc/fail2ban/filter.d/dovecot.conf:18:            ^[a-z\-]{3,15}\(\S*,<HOST>(?:,\S*)?\): (?:unknown user|invalid credentials|Password mismatch)
/etc/fail2ban/filter.d/zoneminder.conf:12:# Notes.:  regex to match the password failure messages in the logfile.
/etc/fail2ban/filter.d/lighttpd-auth.conf:1:# Fail2Ban filter to match wrong passwords as notified by lighttpd's auth Module
/etc/fail2ban/filter.d/lighttpd-auth.conf:6:failregex = ^: \((?:http|mod)_auth\.c\.\d+\) (?:password doesn\'t match .* username: .*|digest: auth failed for .*: wrong password|get_password failed), IP: <HOST>\s*$
/etc/fail2ban/filter.d/dropbear.conf:29:            ^[Bb]ad (PAM )?password attempt for .+ from <HOST>(:\d+)?$
/etc/fail2ban/filter.d/dropbear.conf:47:# http://svn.dd-wrt.com/changeset/16642/src/router/dropbear/svr-authpasswd.c
/etc/fail2ban/filter.d/sshd.conf:3:# If you want to protect OpenSSH from being bruteforced by password
/etc/fail2ban/filter.d/sshd.conf:5:# PasswordAuthentication in sshd_config.
/etc/fail2ban/filter.d/openwebmail.conf:8:failregex = ^ - \[\d+\] \(<HOST>\) (?P<USER>\S+) - login error - (no such user - loginname=(?P=USER)|auth_unix.pl, ret -4, Password incorrect)$
/etc/fail2ban/filter.d/murmur.conf:23:failregex = ^Invalid server password$
/etc/fail2ban/filter.d/murmur.conf:24:            ^Wrong certificate or password for existing user$
/etc/fail2ban/filter.d/froxlor-auth.conf:5:# <syslog prefix> Froxlor: [Login Action <HOST>] User '<USER>' tried to login with wrong password.
/etc/fail2ban/filter.d/froxlor-auth.conf:22:# Notes.:  regex to match the password failures messages in the logfile. The
/etc/fail2ban/filter.d/froxlor-auth.conf:32:            ^User \S* tried to login with wrong password.$
/etc/fail2ban/filter.d/squirrelmail.conf:4:failregex = ^ \[LOGIN_ERROR\].*from <HOST>: Unknown user or password incorrect\.$
/etc/fail2ban/filter.d/nginx-http-auth.conf:7:failregex = ^ \[error\] \d+#\d+: \*\d+ user "(?:[^"]+|.*?)":? (?:password mismatch|was not found in "[^\"]*"), client: <HOST>, server: \S*, request: "\S+ \S+ HTTP/\d+\.\d+", host: "\S+"(?:, referrer: "\S+")?\s*$
/etc/fail2ban/filter.d/domino-smtp.conf:26:# Notes.:  regex to match the password failure messages in the logfile. The
/etc/fail2ban/filter.d/domino-smtp.conf:34:# [28325:00010-3735542592] 22-06-2014 09:56:12   smtp: postmaster [1.2.3.4] authentication failure using internet password
/etc/fail2ban/filter.d/domino-smtp.conf:35:# 08-09-2014 06:14:27   smtp: postmaster [1.2.3.4] authentication failure using internet password
/etc/fail2ban/filter.d/domino-smtp.conf:41:            ^%(__prefix)ssmtp: (?:[^\[]+ )*\[?<HOST>\]? authentication failure using internet password\s*$
/etc/fail2ban/filter.d/haproxy-http-auth.conf:25:# Notes.:  regex to match the password failures messages in the logfile. The
/etc/fail2ban/filter.d/mysqld-auth.conf:20:failregex = ^%(__prefix_line)s(?:(?:\d{6}|\d{4}-\d{2}-\d{2})[ T]\s?\d{1,2}:\d{2}:\d{2} )?(?:\d+ )?\[\w+\] (?:\[[^\]]+\] )*Access denied for user '<F-USER>[^']+</F-USER>'@'<HOST>' (to database '[^']*'|\(using password: (YES|NO)\))*\s*$
/etc/fail2ban/filter.d/mysqld-auth.conf:29:# 130322 11:26:54 [Warning] Access denied for user 'root'@'127.0.0.1' (using password: YES)
/etc/fail2ban/filter.d/ejabberd-auth.conf:10:# Notes.:  regex to match the password failures messages in the logfile. The
/etc/fail2ban/filter.d/solid-pop3d.conf:17:            ^%(__prefix_line)scan't find APOP secret for user .*? - <HOST>$
/etc/fail2ban/filter.d/proftpd.conf:17:__suffix_failed_login = ([uU]ser not authorized for login|[nN]o such user found|[iI]ncorrect password|[pP]assword expired|[aA]ccount disabled|[iI]nvalid shell: '\S+'|[uU]ser in \S+|[lL]imit (access|configuration) denies login|[nN]ot a UserAlias|[mM]aximum login length exceeded)
/etc/fail2ban/filter.d/slapd.conf:3:# Detecting invalid credentials: error code 49
/etc/fail2ban/filter.d/slapd.conf:4:# http://www.openldap.org/doc/admin24/appendix-ldap-result-codes.html#invalidCredentials (49)
/etc/fail2ban/filter.d/grafana.conf:9:failregex = ^(?: lvl=err?or)? msg="Invalid username or password"(?: uname=(?:"<F-ALT_USER>[^"]+</F-ALT_USER>"|<F-USER>\S+</F-USER>)| error="<F-ERROR>[^"]+</F-ERROR>"| \S+=(?:\S*|"[^"]+"))* remote_addr=<ADDR>$
/etc/fail2ban/filter.d/sogo-auth.conf:7:failregex = ^ sogod \[\d+\]: SOGoRootPage Login from '<HOST>(?:,[^']*)?' for user '[^']*' might not have worked( - password policy: \d*  grace: -?\d*  expire: -?\d*  bound: -?\d*)?\s*$
/etc/fail2ban/filter.d/apache-auth.conf:30:            ^%(auth_type)suser <F-USER>(?:\S*|.*?)</F-USER>: password mismatch\b
/etc/fail2ban/filter.d/nsd.conf:19:# Notes.:  regex to match the password failures messages in the logfile. The
/etc/fail2ban/jail.conf:232:action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
/etc/fail2ban/jail.conf:239:# `action_blocklist_de` used for the action, set value of `blocklist_de_apikey`
/etc/fail2ban/jail.conf:243:action_blocklist_de  = blocklist_de[email="%(sender)s", service="%(__name__)s", apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]
/etc/fail2ban/jail.conf:906:# knocking_url variable must be overridden to some secret value in jail.local
```

## 9. FTP Security Assessment

### FTP Configuration

```text
Command: 
if [ -r /etc/vsftpd.conf ]; then
    echo "===== EFFECTIVE VSFTPD SETTINGS ====="

    grep -Ev "^[[:space:]]*(#|$)" /etc/vsftpd.conf |
    grep -Ei \
    "^(listen|listen_ipv6|anonymous_enable|local_enable|write_enable|anon_upload_enable|anon_mkdir_write_enable|anon_other_write_enable|chroot_local_user|allow_writeable_chroot|ssl_enable|force_local_logins_ssl|force_local_data_ssl|rsa_cert_file|rsa_private_key_file|pasv_enable|pasv_min_port|pasv_max_port|local_root|anon_root|hide_ids|download_enable|dirlist_enable|file_open_mode|local_umask|xferlog_enable|dual_log_enable|log_ftp_protocol|ftpd_banner|banner_file|userlist_enable|userlist_deny)=" || true
else
    echo "/etc/vsftpd.conf unavailable"
fi


===== EFFECTIVE VSFTPD SETTINGS =====
listen=NO
listen_ipv6=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
xferlog_enable=YES
rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
ssl_enable=NO
anonymous_enable=YES
```

### FTP Security Findings

```text
Command: 
if [ -r /etc/vsftpd.conf ]; then
    anonymous_enable="$(
        awk -F= '
        /^[[:space:]]*anonymous_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        ' /etc/vsftpd.conf
    )"

    ssl_enable="$(
        awk -F= '
        /^[[:space:]]*ssl_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        ' /etc/vsftpd.conf
    )"

    write_enable="$(
        awk -F= '
        /^[[:space:]]*write_enable=/ {
            gsub(/[[:space:]]/, "", $2)
            value=toupper($2)
        }
        END { print value }
        ' /etc/vsftpd.conf
    )"

    echo "anonymous_enable=${anonymous_enable:-DEFAULT/UNKNOWN}"
    echo "ssl_enable=${ssl_enable:-DEFAULT/UNKNOWN}"
    echo "write_enable=${write_enable:-DEFAULT/UNKNOWN}"

    if [ "$anonymous_enable" = "YES" ]; then
        echo "[HIGH] Anonymous FTP access is enabled"
    fi

    if [ "$ssl_enable" != "YES" ]; then
        echo "[HIGH] FTP communications are not protected by TLS"
    fi

    if [ "$write_enable" = "YES" ]; then
        echo "[MEDIUM] FTP write operations are enabled"
    fi
fi

if find /srv/ftp /var/ftp /home/ftp \
    -type d \
    -perm -0002 \
    -print -quit 2>/dev/null |
    grep -q .
then
    echo "[CRITICAL] A world-writable FTP directory was detected"
fi


anonymous_enable=YES
ssl_enable=NO
write_enable=YES
[HIGH] Anonymous FTP access is enabled
[HIGH] FTP communications are not protected by TLS
[MEDIUM] FTP write operations are enabled
```

### FTP Files and Permissions

```text
Command: 
for directory in \
    /srv/ftp \
    /var/ftp \
    /home/ftp
do
    if [ -e "$directory" ]; then
        echo "===== $directory ====="

        find "$directory" \
            -maxdepth 8 \
            -printf "%M %u:%g %s %p\\n" 2>/dev/null

        echo
        echo "===== READABLE CONTENT ====="

        find "$directory" \
            -maxdepth 8 \
            -type f \
            -readable \
            -size -10M \
            -print \
            -exec sh -c '
                echo "----- $1 -----"
                sed -n "1,1000p" "$1"
                echo
            ' sh {} \; 2>/dev/null
    fi
done


===== /srv/ftp =====
drwxr-xr-x root:ftp 4096 /srv/ftp
-rw-r--r-- root:root 22 /srv/ftp/readme.txt

===== READABLE CONTENT =====
/srv/ftp/readme.txt
----- /srv/ftp/readme.txt -----
Finance invoices here
```

### FTP Log Evidence

```text
Command: 
for file in \
    /var/log/vsftpd.log \
    /var/log/xferlog \
    /var/log/proftpd/proftpd.log \
    /var/log/auth.log \
    /var/log/syslog
do
    if [ -r "$file" ]; then
        echo "===== $file ====="

        grep -Ei \
        "ftp|vsftpd|login|anonymous|upload|download|connect|failed|success|FLAG\\{" \
        "$file" 2>/dev/null |
        tail -n 1000

        echo
    fi
done


===== /var/log/auth.log =====
Feb 12 12:00:00 sandbox sshd[123]: Failed password for root from 10.10.10.10 port 5555 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
```

## 10. Authentication and Intrusion Evidence

### Raw Authentication Evidence

```text
Command: 
for file in \
    /var/log/auth.log \
    /var/log/secure \
    /var/log/syslog \
    /var/log/messages
do
    if [ -r "$file" ]; then
        echo "===== $file ====="

        grep -Ei \
        "accepted|failed|invalid user|root|sudo|authentication failure|session opened|session closed|blocked|ban|unban|FLAG\{" \
        "$file" 2>/dev/null |
        tail -n 500

        echo
    fi
done


===== /var/log/auth.log =====
Feb 12 12:00:00 sandbox sshd[123]: Failed password for root from 10.10.10.10 port 5555 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2
Accepted password for root from 192.168.1.99 port 5555 ssh2
```

### Authentication Evidence After Excluding Known Lab Injections

```text
Command: 
for file in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages; do
    [ -r "$file" ] || continue

    echo "===== $file ====="

    grep -Ei     "accepted|failed|invalid user|root|sudo|authentication failure|session opened|session closed|blocked|ban|unban"     "$file" 2>/dev/null |
    grep -Fv "Failed password for root from 10.10.10.10 port 5555 ssh2" |
    grep -Fv "Failed password for invalid user admin from 10.10.10.66 port 4444 ssh2" |
    grep -Fv "Accepted password for root from 192.168.1.99 port 5555 ssh2" |
    tail -n 1000

    echo
done


===== /var/log/auth.log =====
```

### Additional Intrusion Artifact Search

```text
Command: 
grep -RniE "(chpasswd|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)|/dev/tcp|bash[[:space:]]+-i|nc[[:space:]].*(-e|--exec)|socat.*EXEC|curl.+\|[[:space:]]*(sh|bash)|wget.+\|[[:space:]]*(sh|bash))" /opt /usr/local /srv /root /home /tmp /var/tmp /etc/cron.d /etc/profile.d 2>/dev/null || true


/usr/local/lib/python3.10/dist-packages/urllib3/response.py:492:        tr_enc = self.headers.get("transfer-encoding", "").lower()
/home/student/audit.sh:184:    grep -nE     "fake attack log|brute force source|chpasswd|passwd[[:space:]]|nft[[:space:]]+flush[[:space:]]+ruleset|ttyd|openvscode-server|code-server|setup_ssh|auth\.log|suricata/fast\.log"     "$file" 2>/dev/null || true
/home/student/audit.sh:205:    grep -nE     "chpasswd|passwd[[:space:]]|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)"     "$file" 2>/dev/null || true
/home/student/audit.sh:912:grep -RniE "(chpasswd|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)|/dev/tcp|bash[[:space:]]+-i|nc[[:space:]].*(-e|--exec)|socat.*EXEC|curl.+\|[[:space:]]*(sh|bash)|wget.+\|[[:space:]]*(sh|bash))" /opt /usr/local /srv /root /home /tmp /var/tmp /etc/cron.d /etc/profile.d 2>/dev/null || true
/home/student/audit.sh:1055:if grep -qiE "chpasswd|passwd|usermod|useradd" "$(evidence_path "startup_password_changes.txt")" 2>/dev/null; then
/home/student/audit.sh:1150:The presence of commands such as \`chpasswd\`, \`nft flush ruleset\`, \`ttyd\`
/home/student/audit_evidence/07_services/services_processes.txt:4:root           1  0.0  0.0   2892   948 ?        Ss   13:14   0:00 /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh
/home/student/audit_evidence/03_attack_surface/process_command_lines.txt:14:1: /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh 
/home/student/audit_evidence/12_intrusion_analysis/startup_security_analysis.txt:7:    grep -nE     "fake attack log|brute force source|chpasswd|passwd[[:space:]]|nft[[:space:]]+flush[[:space:]]+ruleset|ttyd|openvscode-server|code-server|setup_ssh|auth\.log|suricata/fast\.log"     "$file" 2>/dev/null || true
/home/student/audit_evidence/12_intrusion_analysis/startup_security_analysis.txt:14:17:echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd
/home/student/audit_evidence/12_intrusion_analysis/startup_password_changes.txt:6:    grep -nE     "chpasswd|passwd[[:space:]]|usermod[[:space:]].*(-p|--password)|useradd[[:space:]].*(-p|--password)"     "$file" 2>/dev/null || true
/home/student/audit_evidence/12_intrusion_analysis/startup_password_changes.txt:12:17:echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd
/home/student/audit_evidence/01_system/system_processes.txt:4:root           1  0.0  0.0   2892   948 ?        Ss   13:14   0:00 /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh
/home/student/audit_evidence/01_system/system_startup_scripts.txt:35:echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd
/home/student/audit_evidence/01_system/system_pid1.txt:4:      1       0 root     root     sh              /bin/sh -c echo root:`echo $HOSTNAME | cut -d '-' -f 1` | chpasswd && service ssh restart > /dev/null && /etc/run.sh
```

### Assessment

- Filtered authentication indicators: `4`
- Additional suspicious artifact matches: `15`
- Conclusion: **Unexplained indicators remain after known simulated events are excluded; manual correlation is required**

Authentication records that are reproduced verbatim by `/etc/run.sh` or
another startup script must be classified as simulated laboratory evidence.
Only events remaining after this exclusion should be correlated with file
timestamps, process activity, SSH keys, cron jobs and network connections.

## 11. Discrepancies vs Documentation

The following documentation items must be compared with runtime evidence:

- documented network `192.168.1.0/24` versus observed addressing;
- documented SSH exposure versus actual listening interfaces;
- documented FTP requirement versus actual FTP configuration;
- claimed absence of firewall versus observed rules;
- documented services versus additional ports and processes;
- claimed absence of segmentation versus detected interfaces, bridges or VLANs;
- documented administration methods versus remote shell or development tools;
- documented operational tasks versus actual cron jobs and startup scripts.

## 12. Risk Matrix

### Critical

- Independently verified unauthorized root SSH login
- Unauthorized root scheduled task or unexplained outbound beacon
- Exposed remote shell service
- Database exposed to unauthorized networks
- Sensitive administrative credentials in readable files

### High

- Cleartext FTP
- No effective firewall enforcement
- Development tools exposed on all interfaces
- World-readable backup or configuration files
- Unknown SSH keys, privileged accounts or unexplained password changes

### Medium

- Legacy Telnet components
- Missing SELinux or AppArmor enforcement
- Undocumented services or scheduled tasks
- Incomplete security monitoring

### Low

- Documentation and network topology drift

## 13. Flags Recovered During Audit

```text
FLAG{1DS_D3T3CT10N_W0RKS}
FLAG{AUD1T_FL4T_N3TW0RK}
FLAG{CL34RT3XT_FTP}
FLAG{CR0N_B4CKD00R}
FLAG{R00T_L0G1N_D3T3CT3D}
FLAG{R00T_SSH_1S_D4NG3R}
FLAG{S3NS1T1V3_B4CKUP_EXP0S3D}
FLAG{SSH_BRUTE_BLOCKED}
FLAG{UNN3C3SS4RY_S3RV1C3}
FLAG{Z3R0_TRU5T_Z0N3S}
```

## 14. Preliminary Recommendations

1. Disable direct SSH root login.
2. Disable SSH password authentication where possible.
3. Restrict administrative access through a VPN or trusted source ranges.
4. Remove unauthorized remote shell and development services.
5. Investigate all undocumented root cron jobs.
6. Apply a default-deny firewall policy.
7. Isolate Finance, Guest, internal systems and the database.
8. Protect the legacy FTP workflow with a secure tunnel or VPN.
9. Rotate credentials exposed in configuration or backup files.
10. Remove world-readable permissions from sensitive files.
11. Separate simulated laboratory log entries from genuine authentication events.
12. Review all authentication activity remaining after known injected events are removed.
13. Replace the predictable root-password initialization mechanism with a secure secret.
14. Correct startup redirections such as `2&>1` to `>/dev/null 2>&1` where intended.
15. Establish centralized logging and monitoring with tamper-resistant log collection.

## Conclusion

The live audit provides technical evidence of the actual state of the LogiCorp
gateway and identifies discrepancies that cannot be discovered from
documentation alone.

The startup configuration demonstrates that some apparent attack evidence is
artificially generated by the laboratory. Consequently, those injected SSH and
Suricata entries do not confirm a real intrusion. The same startup script still
confirms serious security weaknesses, including predictable root-password
initialization, firewall removal and exposed remote administration services.

This audit cannot prove that no intrusion occurred. A compromise should only be
confirmed when independent evidence remains after known simulated events are
excluded and correlated across authentication logs, processes, files, cron,
SSH keys and network activity.
