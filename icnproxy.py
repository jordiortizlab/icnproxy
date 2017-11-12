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
import falcon
import http.client
import json
import logging
import logging.config
import socket
import sys
import configparser

global controller
global controllerport
global proxymac
global ctrlurl
global user
global passwd

class myHTTPConnection(http.client.HTTPConnection):

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
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
                      source_address=None):
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
                    sock.bind(source_address)
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


class ICNProxy(object):

    def on_get(self, req, resp, **kwargs):
        logger.debug("Received GET")
        # En kwargs tienes los parametros.
        # Create a response using msgpack
        self.on_post(req, resp)
        # resp.data = msgpack.packb(resp.pretty_print(), use_bin_type=True)
        # resp.content_type = 'application/msgpack'
        # The following line can be omitted because 200 is the default
        # status returned by the framework, but it is included here to
        # illustrate how this may be overridden as needed.
        #resp.status = falcon.HTTP_200
    def on_put(self, req, resp):
        logger.error('NON IMPLEMENTED PUT')
        return
        # body = {'status':"OK"}
        # resp.body = json.dumps(doc, ensure_ascii=False)
        # Aqui se inicializa la API

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        logger.debug("Received POST {}".format(req.uri))

        server = socket.gethostbyname(req.host)
        port = req.port
        method = req.method
        url = req.uri
        logger.info("Received request {} {} {} {}".format(server, port, method, url))
        http_connection = myHTTPConnection(server, port)

        # Make request to controller
        (laddr, lport) = http_connection.getSocketInfo()
        raddr = server
        rport = port

        ctrl_connection = http.client.HTTPConnection(controller, controllerport)
        flow = { 'smac': proxymac,
              'saddr': laddr,
              'daddr': raddr,
              'proto': "HTTP",
              'sport': lport,
              'dport': rport}
        body = { 'proxy': proxymac, 'hostname': server, 'uri': url, 'flow': flow }
        logger.debug("Flow: {}".format(flow))
        logger.debug("body: {}".format(body))

        userpass = user + ":" + passwd
        buserpass = bytes(userpass, encoding="ascii")
        bauth = base64.b64encode(buserpass).decode("ascii")

        ctrl_connection.request('POST', 'http://' + controller + ':' + str(controllerport) + ctrlurl, body.__str__(), {'Authorization' : 'Basic %s' % bauth})
        ctrlresponse = ctrl_connection.getresponse()
        logger.debug("Received controller response: {} {}".format(ctrlresponse.status, ctrlresponse.msg))
        ctrl_connection.close()
        # Continue downloading from origin

        http_connection.connect()
        http_connection.request(method, url)
        response = http_connection.getresponse()
        body = response.read()
        logger.debug("Content provider or cache contacted: {} {}".format(response.status, response.msg))
        resp.status = falcon.get_http_status(response.status)
        resp.body = body
        resp.set_headers({})
        for (hname, hvalue) in response.getheaders():
            if hname == "Transfer-Encoding":
                resp.append_header(hname, "deflate")
            else:
                resp.append_header(hname, hvalue)
        http_connection.close()
        logger.info("End Request {}".format(url))

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
logger.info("Read config: {} {} {} {} {} {}".format(controller, controllerport, proxymac, ctrlurl, user, passwd))
logger.debug("DEBUG OUTPUT ENABLED")

api = application = falcon.API()
# Te creas el objeto que va a responder a una ruta
prefetch_instance = ICNProxy()
# Añades las rutas que quieres, y qué objeto las atenderá.
#api.add_route('/', prefetch_instance)
api.add_sink(prefetch_instance.on_get)
