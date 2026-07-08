#!/bin/bash
tshark -r "$1" -T fields -e urlencoded-form.value
