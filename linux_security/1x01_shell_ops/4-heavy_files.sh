#!/bin/bash
ls -l | awk '$5 > 1024 {print $9}'