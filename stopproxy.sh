#!/bin/bash

let done=1
while [ $done -eq 1 ]
do
    let done=0
    for pid in `ps -e -o pid,command  | grep icnproxy.py | grep -v grep | awk '{ print $1 }'`
    do
	echo killing $pid
	kill -2 $pid
	let done=1
    done

done
