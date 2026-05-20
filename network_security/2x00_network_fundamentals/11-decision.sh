#!/bin/bash
ip route get "$1" | grep -q via && echo REMOTE || echo LOCAL