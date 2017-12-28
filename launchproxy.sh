#!/bin/bash

cd $HOME/gn3proxy/

if [ ! -d venv ]
then
    echo "Virtual Env missing. Creating ./venv/"
    virtualenv -p python3.6 venv
    source venv/bin/activate
    pip install tornado
else
    source venv/bin/activate
fi

rm icnproxy.log
nohup python icnproxy.py > nohup.out 2> nohup.out&
sleep 60
echo ""
