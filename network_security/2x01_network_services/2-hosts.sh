#!/bin/bash
awk '$2=="localhost" {printf "%s",$1; exit}' /etc/hosts