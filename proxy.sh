#!/bin/bash

# Run proxy and redirect HTTP flows to it. Client and proxy are assumed to be
# on different hosts. The network must enforce that HTTP flows reach this host.
#
# Note:
#  Use as root (to manipulate nat table with iptables, gn3proxy can be used
#               as an unprivileged user).
#
# Author:
#  Francisco J. Ros <fjros@um.es>
#

PRX_PATH='.'
PRX_PORT=8080
PRX_MAC='00:10:60:58:08:ea'
PRX_IP='10.0.111.33'
PLUGIN='./plugins/cdnapp.py'
CONTROLLER='10.7.0.1:8080'

iptables -t nat -F
iptables -t nat -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $PRX_IP:$PRX_PORT
$PRX_PATH/gn3proxy.py -p $PRX_PORT -x $PLUGIN -c $CONTROLLER $PRX_MAC
