# Audit evidence directory

This directory contains the evidence collected by `audit.sh`. Files are grouped
by audit domain to simplify navigation and review.

| Directory | Contents |
|---|---|
| `01_system/` | Host identity, OS, processes, mounts and startup scripts |
| `02_network/` | Interfaces, routes, neighbors, DNS, bridges and VLANs |
| `03_attack_surface/` | Listening ports, active connections and exposed processes |
| `04_security_controls/` | Firewall, SELinux, AppArmor, Fail2Ban and Suricata |
| `05_users_access/` | Accounts, privileges, keys and sensitive permissions |
| `06_ssh/` | SSH configuration and effective security settings |
| `07_services/` | Running, installed and legacy services |
| `08_persistence/` | Cron jobs and persistence mechanisms |
| `09_ftp/` | FTP service, configuration, permissions and findings |
| `10_sensitive_data/` | LogiCorp files and exposed secrets |
| `11_logs/` | Authentication, system and application logs |
| `12_intrusion_analysis/` | Injected events and unexplained intrusion indicators |
| `13_flags/` | Recovered flags, targeted searches and evidence index |

## Important

Files in `12_intrusion_analysis/` distinguish laboratory-generated events
from unexplained evidence. Injected log lines must not be treated as independent
proof of a real compromise.
