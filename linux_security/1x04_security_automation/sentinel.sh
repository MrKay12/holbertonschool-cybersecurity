#!/bin/bash

set -euo pipefail

CONFIG_FILE="./sentinel.conf"

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Error: Configuration file '$CONFIG_FILE' not found." >&2
    exit 1
fi

source "$CONFIG_FILE"

if [[ -z "${SERVICES+x}" ]]; then
    echo "Error: SERVICES variable is not defined in config." >&2
    exit 1
fi

if [[ -z "${FILES_TO_WATCH+x}" ]]; then
    echo "Error: FILES_TO_WATCH variable is not defined in config." >&2
    exit 1
fi

if [[ ${#SERVICES[@]} -eq 0 ]]; then
    echo "Error: SERVICES array is empty." >&2
    exit 1
fi

if [[ ${#FILES_TO_WATCH[@]} -eq 0 ]]; then
    echo "Error: FILES_TO_WATCH array is empty." >&2
    exit 1
fi

echo "Configuration loaded successfully."
echo "Services: ${SERVICES[*]}"
echo "Files to watch: ${FILES_TO_WATCH[*]}"