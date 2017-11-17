#!/bin/bash

for pid in `ps -e -o pid,command  | grep icnproxy.py | grep -v grep | awk '{ print $1 }'`
do
    echo killing $pid
    kill -2 $pid
done
