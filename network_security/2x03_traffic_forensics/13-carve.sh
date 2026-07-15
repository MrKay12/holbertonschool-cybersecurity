#!/bin/bash
mkdir -p extracted_files && tshark -r "$1" --export-objects http,extracted_files -q && md5sum extracted_files/*