#!/bin/bash

if [ ! -d venv ]
then
    echo "Virtual Env missing. Creating ./venv/"
    virtualenv -p python3.6 venv
    source venv/bin/activate
    pip install gunicorn
    pip install falcon
else
    source venv/bin/activate
fi

gunicorn --reload --bind 0.0.0.0:8080 icnproxy
