#!/bin/bash
awk '$2=="localhost" {print $1; exit}' /etc/hosts