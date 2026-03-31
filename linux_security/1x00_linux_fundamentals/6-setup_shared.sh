#!/bin/bash
mkdir -p "/shared/devs" && chgrp "developers" "/shared/devs" && chmod 2775 "/shared/devs" && chmod +t "/shared/devs"