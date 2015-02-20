# GN3proxy

Simple HTTP proxy that communicates with a [CDN-Floodlight](TBD) application.
It has been developed in Python and features a minimalist plugin architecture
to invoke external functions when an HTTP method is handled.

The software has been developed by the University of Murcia for the Joint
Research Activity 2 Task 2 (JRA2T2) of the GN3plus project. For more
information, take a look to [CDN-Floodlight](TBD).

The code is released under the Apache License, Version 2.0.

## Install

Make sure that Python is installed in your system and clone this repository:

> `git clone https://gitlab.atica.um.es/gn3proxy` (TBD)

To run your proxy, you will also need `iptables` to redirect incoming HTTP
traffic to GN3proxy.

## Using

Run:

> `./gn3proxy.py [-h] [-p PORT] [-c CONTROLLER] [-x PLUGIN] <proxy_mac_address>`

To simplify things, you can edit `proxy.sh` to reflect your deployment and
simply run:

> `./proxy.sh`

## Plugins

If desired, the core functionality of the proxy can be extended by means of
simple plugins.

On startup, you can pass a plugin file with the `-x` option. It must contain
Python code that defines (at least) a function with the same name of an HTTP
method (e.g. 'get', 'post' or 'put'). It will be invoked when processing a
request of the corresponding type. Such function must accept four parameters:

* **controller**: address of the CDN-Floodlight controller.
* **prxid**: unique identifier for this proxy (MAC address).
* **resource**: tuple (hostname, uri) of the resource being requested.
* **flow**: specification of the flow that must be programmed by the
CDN-Floodlight controller.

You can find an example of the plugin usage in *plugins/cdnapp.py*.
 
## Author

The code has been written by [Francisco J. Ros](http://masimum.inf.um.es/fjrm).
The design of the overall solution is due to the whole UMU team involved within
the JRA2T2 of the GN3plus project, including Jordi Ortiz, Pedro Martinez-Julia,
and Antonio F. Skarmeta, who also supported the development and testing of the
application.
