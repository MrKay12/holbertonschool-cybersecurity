#!/bin/bash

apt-get update
apt-get install -y nftables wireguard wireguard-tools
systemctl enable nftables