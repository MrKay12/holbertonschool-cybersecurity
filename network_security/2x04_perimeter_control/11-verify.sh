#!/bin/bash

wg show wg0 latest-handshakes | awk '{print $2}'