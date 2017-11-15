#!/usr/bin/python

# Copyright 2017, University of Murcia (Spain)
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
#   Jordi Ortiz
#   <jordi.ortiz@um.es>



import base64
import tornado.httpserver
import tornado.ioloop
import tornado.web
import http.client
import json
import logging
import logging.config
import socket
import sys
import configparser

global controller
global controllerport
global proxyaddr
global proxymac
global ctrlurl
global user
global passwd
global serviceport

global sourceport

class myHTTPConnection(http.client.HTTPConnection):

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, source_port=None):
        super().__init__(host, port, timeout, source_address)
        # self.sock = self._create_connection(
        #     (self.host, self.port), self.timeout, self.source_address)
        self.sock = self.createSocket(
            (self.host, self.port), self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def connect(self):
         self.sock.connect(self.sa)
         if self._tunnel_host:
            self._tunnel()

    def getSocketInfo(self):
        (laddr, lport) = self.sock.getsockname()
        # only source info is recovered since destination is already known as parameter
        return (laddr, lport)

    # createSocket replaces the create_connection method from socket so that we can split between socket creation and
    # actually connect to the other end
    def createSocket(self, address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                      source_address=None, source_port=None):
        host, port = address
        err = None
        for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    sock.settimeout(timeout)
                if source_address:
                    logger.debug("Binding to {}".format(source_address))
                    if source_port:
                        sock.bind((source_address, source_port))
                    else:
                        sock.bind((source_address, 0))
                    logger.debug("Bind success")
                # DO NOT CONNECT!
                # sock.connect(sa)
                self.sa = sa
                # Break explicitly a reference cycle
                err = None
                return sock

            except socket.error as _:
                err = _
                if sock is not None:
                    sock.close()

        if err is not None:
            raise err
        else:
            raise socket.error("getaddrinfo returns an empty list")


class ICNProxy(tornado.web.RequestHandler):

    def get(self, *args, **kwargs):
        global sourceport
        global proxyport
        global serviceport
        req = self.request
        logger.debug("Received GET {}".format(req.uri))

        server = socket.gethostbyname(req.host)
        method = "GET"
        url = req.full_url()
        logger.info("Received request {} {} {} {}".format(server, proxyport, method, url))
        http_connection = myHTTPConnection(server, serviceport, source_address=proxyaddr, source_port=sourceport)
        sourceport += 1
        if sourceport == 65535:
            sourceport = 1025

        # Make request to controller
        (laddr, lport) = http_connection.getSocketInfo()
        raddr = server
        rport = serviceport

        ctrl_connection = http.client.HTTPConnection(controller, controllerport)
        flow = { "smac": proxymac,
              "saddr": laddr,
              "daddr": raddr,
              "proto": "'HTTP'",
              "sport": lport,
              "dport": rport}
        body = {"proxy": proxymac, "hostname": server, "uri": url, "flow": flow}

        logger.debug("body: {}".format(json.dumps(body)))

        userpass = user + ":" + passwd
        buserpass = bytes(userpass, encoding="ascii")
        bauth = base64.b64encode(buserpass).decode("ascii")

        ctrl_connection.request('POST', 'http://' + controller + ':' + str(controllerport) + ctrlurl, json.dumps(body), {'Authorization' : 'Basic %s' % bauth})
        ctrlresponse = ctrl_connection.getresponse()
        logger.debug("Received controller response: {} {}".format(ctrlresponse.status, ctrlresponse.msg))
        ctrl_connection.close()
        # Continue downloading from origin

        http_connection.connect()
        http_connection.request(method, url)
        response = http_connection.getresponse()
        body = response.read()
        http_connection.close()
        logger.debug("Content provider or cache contacted: {} {}".format(response.status, response.msg))
        self.set_status(response.status)
        self._headers = tornado.httputil.HTTPHeaders()
        for (hname, hvalue) in response.getheaders():
            if hname not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                self.add_header(hname, hvalue)
        self.write(body)
        logger.info("End Request {}".format(url))


def run_proxy(port, start_ioloop=True):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """
    app = tornado.web.Application([
        (r'.*', ICNProxy),
    ])

    server = tornado.httpserver.HTTPServer(app)
    server.bind(port)
    server.start(0)  # autodetect number of cores and fork a process for each
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    logging.config.fileConfig('logging.conf')
    logger = logging.getLogger(__name__)

    parser = configparser.ConfigParser()
    parser.read('icnproxy.ini')

    controller = socket.gethostbyname(parser['DEFAULT']['controller'])
    controllerport = parser['DEFAULT']['controllerport']
    proxymac = parser['DEFAULT']['proxymac']
    ctrlurl = parser['DEFAULT']['controlurl']
    user = parser['DEFAULT']['user']
    passwd = parser['DEFAULT']['passwd']
    proxyaddr = parser['DEFAULT']['proxyaddr']
    proxyport = int(parser['DEFAULT']['proxyport'])
    serviceport = int(parser['DEFAULT']['serviceport'])
    logger.info("Read config: {} {} {} {} {} {} {}".format(controller, controllerport, proxyaddr, proxymac, ctrlurl, user, passwd))
    logger.debug("DEBUG OUTPUT ENABLED")

    sourceport = 1025

    print ("Starting HTTP proxy on port %d" % proxyport)
    run_proxy(proxyport)
