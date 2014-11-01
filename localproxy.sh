#!/bin/bash

# Run proxy and redirect HTTP flows to it. Client and proxy are assumed to be
# on the same host.
#
# Note:
#  - System user 'gn3p' must exist with the appropriate privilige to run
#    gn3proxy.py
#  - Use as root (to manipulate nat table with iptables and switch to system
#    user 'gn3p'
#
# Author:
#  Francisco J. Ros <fjros@um.es>
#

PRX_PATH='/home/fjrm/research/projects/GN3plus/gn3proxy'
PRX_PORT=8080
PRX_MAC='20:cf:30:86:b9:35'
PRX_IP='155.54.205.27'
PLUGIN='/home/fjrm/research/projects/GN3plus/gn3proxy/plugins/cdnapp.py'
CONTROLLER='155.54.205.103:8080'

iptables -t nat -F
iptables -t nat -A OUTPUT --match owner --uid-owner gn3p -p tcp --dport 80 -j ACCEPT
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination $PRX_IP:$PRX_PORT

su - gn3p -s /bin/bash -c "$PRX_PATH/gn3proxy.py -p 8080 -x $PLUGIN -c $CONTROLLER $PRX_MAC"
