import json, httplib
import base64
username = 'karaf'
password = 'karaf'

def get(controller, prxid, resource, flow):
    host, uri = resource
    body = { 'proxy': prxid, 'hostname': host, 'uri': uri, 'flow': flow }

    auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')

    conn = httplib.HTTPConnection(controller)
    conn.putheader("Authorization", "Basic %s" % auth)
    conn.endheaders()
    conn.request('POST', "/onos/icn/proxyrequest",
        json.dumps(body), { 'content-type': 'application/json' })
    conn.getresponse()
