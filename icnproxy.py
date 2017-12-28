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
import datetime
from multiprocessing import get_context

import tornado.httpserver
import tornado.ioloop
import tornado.web
import http.client
import json
import logging.config
import socket
import signal
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

def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

class ICNProxy(tornado.web.RequestHandler):



    def initialize(self, sourceports):
        self.sourceports = sourceports
        super().initialize()

    def get(self, *args, **kwargs):
        global proxyport
        global serviceport
        start = datetime.datetime.now()
        req = self.request

        server = socket.gethostbyname(req.host)
        method = "GET"
        url = req.full_url()
        logger.info("Received request {} {} {} {}".format(server, proxyport, method, url))
        sourceport = self.sourceports.get()
        logger.debug("Assigned sourceport {}".format(sourceport))
        laddr = proxyaddr
        lport = sourceport

        # Make request to controller

        raddr = server
        rport = serviceport

        ctrl_start = datetime.datetime.now()
        ctrl_connection = http.client.HTTPConnection(controller, controllerport)
        flow = { "smac": proxymac,
              "saddr": laddr,
              "daddr": raddr,
              "proto": "'HTTP'",
              "sport": lport,
              "dport": rport}
        body = {"proxy": proxymac, "hostname": server, "uri": url, "flow": flow}

        userpass = user + ":" + passwd
        buserpass = bytes(userpass, encoding="ascii")
        bauth = base64.b64encode(buserpass).decode("ascii")

        logger.debug("Sent Controller Request - {}".format(url))
        ctrl_connection.request('POST', 'http://' + controller + ':' + str(controllerport) + ctrlurl, json.dumps(body), {'Authorization' : 'Basic %s' % bauth})
        ctrlresponse = ctrl_connection.getresponse()
        logger.debug("Received controller response - {} {}".format(url, ctrlresponse.status))
        ctrl_connection.close()
        # Continue downloading from origin
        ctrl_end = datetime.datetime.now()

        http_connection = http.client.HTTPConnection(server, serviceport, source_address=(proxyaddr, sourceport))
        http_connection.connect()
        http_connection.request(method, url)
        response = http_connection.getresponse()
        body = response.read()
        http_connection.close()
        logger.debug("Content provider or cache contacted: {} {}".format(url, response.status))
        self.set_status(response.status)
        self._headers = tornado.httputil.HTTPHeaders()
        for (hname, hvalue) in response.getheaders():
            if hname not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                self.add_header(hname, hvalue)
        self.write(body)
        logger.info("End Request {}".format(url))
        end = datetime.datetime.now()
        logger.info("Controller Request Time: {}".format((ctrl_end-ctrl_start).total_seconds()))
        logger.info("Full Request Time: {}".format((end-start).total_seconds()))
        self.sourceports.put(sourceport)
        self.finish()


def run_proxy(port, sourceports):
    """
    Run proxy on the specified port. If start_ioloop is True (default),
    the tornado IOLoop will be started immediately.
    """

    app = tornado.web.Application([
        (r'.*', ICNProxy, dict(sourceports=sourceports)),
    ])

    server = tornado.httpserver.HTTPServer(app)
    server.bind(port)
    server.start(0)  # autodetect number of cores and fork a process for each
    tornado.ioloop.IOLoop.instance().start()


if __name__ == '__main__':
    logging.config.fileConfig('logging.conf')
    logger = logging.getLogger(__name__)
    handler = logging.FileHandler("icnproxy.log")
    logger.setLevel(logging.DEBUG)
    app_log = logging.getLogger("tornado.application")
    tornado.log.enable_pretty_logging()
    logger.addHandler(handler)

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

    signal.signal(signal.SIGINT, signal_handler)

    # Prepare multi processing
    ctx = get_context('spawn')
    sourceports = ctx.Queue()
    for port in range(32000, 65000):
        sourceports.put(port)

    print ("Starting HTTP proxy on port %d" % proxyport)
    run_proxy(proxyport, sourceports)
