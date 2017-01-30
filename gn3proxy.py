#!/usr/bin/python2

# Copyright 2014, University of Murcia (Spain)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Author:
#   Francisco J. Ros
#   <fjros@um.es>

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from argparse import ArgumentParser
import httplib, socket
import os

DEFAULT_HTTP_PORT = 80
if os.environ.has_key("CONTROLLER_IPADDR"):
    DEFAULT_CONTROLLER = os.environ["CONTROLLER_IPADDR"] + ":8080"
    print("Controller: %s" % DEFAULT_CONTROLLER)
else:
    DEFAULT_CONTROLLER = 'localhost:8080'

class Plugin:
    """ Simple plugin framework.
    """

    HOOK_GET = 'get'
    HOOK_HEAD = 'head'
    HOOK_POST = 'post'
    HOOK_PUT = 'put'
    HOOK_DELETE = 'delete'
    HOOK_OPTIONS = 'options'
    HOOK_TRACE = 'trace'
    HOOK_CONNECT = 'connect'

    __HOOKS = [ HOOK_GET, HOOK_HEAD, HOOK_POST, HOOK_PUT,
                HOOK_DELETE, HOOK_OPTIONS, HOOK_TRACE, HOOK_CONNECT]

    def __init__(self, filename=None):
        self.module = None
        if filename is not None:
            import imp, os
            assert os.path.isfile(filename)
            self.module = imp.load_source('plugin', filename)

    @staticmethod
    def delegate(command, *args):
        global PLUGINMGR
        if PLUGINMGR.module is None:
            return

        assert command in Plugin.__HOOKS
        try:
            func = getattr(PLUGINMGR.module, command)
        except:
            return None
        return func(*args)


class HttpProxyConnection(httplib.HTTPConnection):
    """ Specialization of HTTPConnection to get source tcp port before
        connecting with destination server.
    """

    def __init__(self, host, port=None, strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        httplib.HTTPConnection.__init__(self, host, port, strict, timeout, source_address=None)
        self.auto_open = 0
        self._create_connection = self.__noop # not needed because we're overriding connect(),
                                              # but just in case the implementation changes
                                              # and more invocations are added

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            self.sock.settimeout(timeout)
        self.sock.bind(('', 0))
        self._localaddr, self._localport = self.sock.getsockname()
        print(host)
        self._peeraddr = socket.gethostbyname(host)
        if port == None:
            self._peerport = 80
        else:
            self._peerport = port

    def connect(self):
        self.sock.connect((self._peeraddr, self._peerport))

        if self._tunnel_host:
            self._tunnel()

    def localaddr(self):
        return self._localaddr

    def peeraddr(self):
        return self._peeraddr

    def proto(self):
        return socket.IPPROTO_TCP

    def localport(self):
        return self._localport

    def peerport(self):
        return self._peerport

    def __noop(self):
        pass


class HttpProxyHandler(BaseHTTPRequestHandler):
    """ Simple HTTP proxy handler that makes use of a plugin framework for
        notifications.
    """

    def __parse_request(self):
        """ Return a tuple with different values from this HTTP request.
            :returns destination server as found in Host header,
                     HTTP method (GET, POST, PUT, etc), HTTP URI,
                     HTTP headers as a dictionary (always 'connection: close'
                     to server), and HTTP body.
        """
        host = self.headers.get('Host')
        method = self.command
        uri = self.path
        headers = dict()
        for header in self.headers.headers:
            h, v = header.split(': ')
            headers[h.lower()] = v.rstrip('\r\n')
        headers['connection'] = 'close'

        length = self.headers.getheader('Content-Length')
        if length == None:
            length = 0
        else:
            length = int(length)
        body = self.rfile.read(length)

        return host, method, uri, headers, body

    def __handle(self, conn, method, uri, headers, body, buflen=1500):
        """ Relay request to destination and send response back to client
            (without 'connection' headers)
        """
        # Relay request
        #  conn.request adds some headers on its own, we can avoid them by
        #  using conn.putheader, conn.endheaders, and (optionally) conn.send.
        #
        #  We leave these extra headers since they don't seem to cause any harm.
        #
        conn.request(method, uri, body, headers)
        #conn.putrequest(method, uri, skip_host=True, skip_accept_encoding=True)
        #for h, v in headers.iteritems():
        #    conn.putheader(h, v)
        #conn.endheaders(message_body=body)
        response = conn.getresponse()

        # Send response back
        #
        self.send_response(response.status)
        for h, v in response.getheaders():
            if h.lower() != 'connection':
                self.send_header(h, v)
        self.end_headers()
        body = response.read(buflen)
        while len(body) > 0:
            self.wfile.write(body)
            body = response.read(buflen)
        conn.close()

    def __doit(self, hook):
        global CONTROLLER, PRXMAC

        host, method, uri, headers, body = self.__parse_request()
        conn = HttpProxyConnection(host)
        Plugin.delegate(hook, CONTROLLER, PRXMAC,
            ( host, uri ),
            { 'smac': PRXMAC,
              'saddr': conn.localaddr(),
              'daddr': conn.peeraddr(),
              'proto': conn.proto(),
              'sport': conn.localport(),
              'dport': conn.peerport() })
        conn.connect()
        self.__handle(conn, method, uri, headers, body)

    def do_GET(self):
        self.__doit(Plugin.HOOK_GET)

    def do_HEAD(self):
        self.__doit(Plugin.HOOK_HEAD)

    def do_POST(self):
        self.__doit(Plugin.HOOK_POST)

    def do_PUT(self):
        self.__doit(Plugin.HOOK_PUT)

    def do_DELETE(self):
        self.__doit(Plugin.HOOK_DELETE)

    def do_OPTIONS(self):
        self.__doit(Plugin.HOOK_OPTIONS)

    def do_TRACE(self):
        self.__doit(Plugin.HOOK_TRACE)

    def do_CONNECT(self):
        self.__doit(Plugin.HOOK_CONNECT)


class ThreadedHttpProxy(ThreadingMixIn, HTTPServer):
    """ Simple HTTP proxy that handles each request in a separate
        thread.
    """


if __name__ == '__main__':
    global PLUGINMGR, CONTROLLER, PRXMAC

    if os.environ.has_key("PROXY_MACADDR"):
        PRXMAC = os.environ["PROXY_MACADDR"]
        print("Proxy mac: %s" % PRXMAC)
    else:
        PRXMAC = 'ff:ff:ff:ff:ff:ff'

    # Parse command line
    argparser = ArgumentParser()
    argparser.add_argument("-p", "--port", type=int, default=DEFAULT_HTTP_PORT,
        help="tcp port where the proxy is listening")
    argparser.add_argument("-c", "--controller", default=DEFAULT_CONTROLLER,
        help="ip address and port where controller is listening")
    argparser.add_argument("-x", "--plugin", default=None,
        help="plugin filename to delegate GET notifications")
    argparser.add_argument("-mac", default=PRXMAC,
        help="mac address of the nic attached to the data network")
    args = argparser.parse_args()
    port = args.port
    CONTROLLER = args.controller
    PRXMAC = args.mac
    filename = args.plugin

    # Start proxy
    PLUGINMGR = Plugin(filename)
    server = ThreadedHttpProxy(('', port), HttpProxyHandler)
    try:
        print("Starting proxy on port %d" % port)
        server.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down proxy")
        server.socket.close()
