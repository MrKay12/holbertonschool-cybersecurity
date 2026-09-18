#!/bin/bash

echo '$template json_fmt,"{\"time\":\"%timestamp%\", \"host\":\"%hostname%\", \"msg\":\"%msg%\"}"' >> /etc/rsyslog.conf