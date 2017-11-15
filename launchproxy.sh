#!/bin/bash

if [ ! -d venv ]
then
    echo "Virtual Env missing. Creating ./venv/"
    virtualenv -p python3.6 venv
    source venv/bin/activate
    pip install tornado
else
    source venv/bin/activate
fi

python icnproxy.py
