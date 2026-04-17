#!/bin/bash
set -e

cp /home/student/sentinel.service /etc/systemd/system/
cp /home/student/sentinel.timer /etc/systemd/system/

systemctl daemon-reload

systemctl enable sentinel.timer
systemctl start sentinel.timer