import json, httplib
import base64
username = 'karaf'
password = 'karaf'

def get(controller, prxid, resource, flow):
    host, uri = resource
    body = { 'proxy': prxid, 'hostname': host, 'uri': uri, 'flow': flow }

    auth = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')

    conn = httplib.HTTP(controller)
    conn.putrequest('POST', "/onos/icn/proxyrequest")

    message = json.dumps(body)
    conn.putheader('content-type', 'application/json')
    conn.putheader("Content-length", "%d" % len(message))
    conn.putheader("Authorization", "Basic %s" % auth)
    conn.endheaders()
    conn.send(message)
    # conn.request('POST', "/onos/icn/proxyrequest",
    #     json.dumps(body), { 'content-type': 'application/json' })
    conn.getreply()
