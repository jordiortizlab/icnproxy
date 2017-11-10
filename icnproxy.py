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



import falcon
import http.client
import json
import socket
import sys
import configparser

global controller
global controllerport
global proxymac
global ctrlurl
global user
global passwd

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class myHTTPConnection(http.client.HTTPConnection):

    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
        super().__init__(host, port, timeout, source_address)
        self.sock = self._create_connection(
            (self.host,self.port), self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def connect(self):
         if self._tunnel_host:
            self._tunnel()

    def getSocketInfo(self):
        (laddr, lport) = self.sock.getsockname()
        (daddr, dport) = self.sock.getpeername()
        return (laddr, lport, daddr, dport)

class ICNProxy(object):

    def on_get(self, req, resp, **kwargs):
        print("Received GET")
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
        eprint('NON IMPLEMENTED PUT')
        # body = {'status':"OK"}
        # resp.body = json.dumps(doc, ensure_ascii=False)
        # Aqui se inicializa la API

    def on_post(self, req: falcon.Request, resp: falcon.Response):
        print("Received POST")
        print("uri: ", req.uri)
        server = socket.gethostbyname(req.host)
        port = req.port
        method = req.method
        url = req.uri
        print("Received request {} {} {} {}".format(server, port, method, url))
        http_connection = myHTTPConnection(server, port)

        # Make request to controller
        (laddr, lport, raddr, rport) = http_connection.getSocketInfo()

        ctrl_connection = myHTTPConnection(controller, controllerport)
        flow = { 'smac': proxymac,
              'saddr': laddr,
              'daddr': raddr,
              'proto': "HTTP",
              'sport': lport,
              'dport': rport}
        body = { 'proxy': proxymac, 'hostname': server, 'uri': url, 'flow': flow }
        ctrl_connection.request('POST', 'http://' + controller + ':' + str(controllerport) + ctrlurl, body.__str__())
        ctrl_connection.close()
        # Continue downloading from origin

        http_connection.request(method, url)
        response = http_connection.getresponse()
        body = response.read().decode('UTF-8')
        print(response.status)
        resp.status = falcon.get_http_status(response.status)
        resp.body = body
        resp.set_headers({})
        for (hname, hvalue) in response.getheaders():
            if hname == "Transfer-Encoding":
                resp.append_header(hname, "deflate")
            else:
                resp.append_header(hname, hvalue)
        # http_connection.connect()
        http_connection.close()
        del http_connection


parser = configparser.ConfigParser()
parser.read('icnproxy.ini')

controller = parser['DEFAULT']['controller']
controllerport = parser['DEFAULT']['controllerport']
proxymac = parser['DEFAULT']['proxymac']
ctrlurl = parser['DEFAULT']['controlurl']
user = parser['DEFAULT']['user']
passwd = parser['DEFAULT']['passwd']
print("Read config: {} {} {} {} {} {}".format(controller, controllerport, proxymac, ctrlurl, user, passwd))

api = application = falcon.API()
# Te creas el objeto que va a responder a una ruta
prefetch_instance = ICNProxy()
# Añades las rutas que quieres, y qué objeto las atenderá.
#api.add_route('/', prefetch_instance)
api.add_sink(prefetch_instance.on_get)