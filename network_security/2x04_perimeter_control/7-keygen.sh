#!/bin/bash

# Generate server key pair
wg genkey | tee server_private | wg pubkey > server_public

# Generate client key pair
wg genkey | tee client_private | wg pubkey > client_public