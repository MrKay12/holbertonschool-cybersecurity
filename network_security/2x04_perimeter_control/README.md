# Perimeter Control

## Description

This project demonstrates how to secure a Linux server using **nftables** and **WireGuard**.

The objective is to reduce the server's attack surface by allowing only required services, creating a secure VPN tunnel, and restricting administrative access through the VPN.

---

## Requirements

- Ubuntu/Debian
- Root privileges
- OpenSSH
- nftables
- WireGuard

---

## Project Files

| File | Description |
|------|-------------|
| `0-audit.sh` | Lists listening TCP/UDP ports and associated processes. |
| `1-install.sh` | Installs nftables and WireGuard, enables nftables service. |
| `2-panic.sh` | Emergency script that resets the firewall and schedules itself after 5 minutes. |
| `skeleton.conf` | nftables firewall configuration. |
| `6-deploy.sh` | Copies and deploys the firewall configuration to the target machine. |
| `7-keygen.sh` | Generates server and client WireGuard key pairs. |
| `wg0.conf` | WireGuard server configuration. |
| `client.conf` | WireGuard client configuration. |
| `11-verify.sh` | Displays the latest WireGuard handshake timestamp. |
| `12-forward.sh` | Enables IPv4 forwarding permanently. |

---

## Firewall Configuration

### Input Policy

- DROP by default
- Allow established and related connections
- Allow loopback traffic
- Allow ICMP
- Allow WireGuard (UDP 51820)
- Allow SSH only from VPN client (10.200.0.2)

### Forward Policy

- DROP by default
- Allow traffic entering through `wg0`

### Output Policy

- ACCEPT

### NAT

A NAT table performs masquerading so VPN clients can access external networks.

---

## WireGuard Network

Server:

- Address: `10.200.0.1/24`
- Port: `51820`

Client:

- Address: `10.200.0.2/24`

---

## Usage

### 1. Audit the system

```bash
./0-audit.sh
```

### 2. Install required packages

```bash
sudo ./1-install.sh
```

### 3. Generate keys

```bash
./7-keygen.sh
```

### 4. Configure WireGuard

Copy the generated keys into:

- `wg0.conf`
- `client.conf`

### 5. Enable IP forwarding

```bash
sudo ./12-forward.sh
```

### 6. Deploy the firewall

```bash
./6-deploy.sh user@server
```

### 7. Start WireGuard

Server:

```bash
sudo wg-quick up wg0
```

Client:

```bash
sudo wg-quick up client
```

### 8. Verify the tunnel

```bash
ping 10.200.0.1
```

```bash
sudo ./11-verify.sh
```

---

## Security Features

- Default deny firewall
- Stateful filtering
- Loopback protection
- ICMP allowed for diagnostics
- SSH restricted to VPN
- VPN encrypted with WireGuard
- NAT for VPN clients
- Automatic firewall recovery using the panic script

---

## Notes

Always execute `2-panic.sh` before testing a new firewall configuration. If an incorrect rule blocks SSH access, the firewall will automatically reset after five minutes, preventing permanent lockout.