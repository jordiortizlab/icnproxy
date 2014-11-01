import json, httplib

def get(controller, prxid, resource, flow):
    host, uri = resource
    body = { 'proxy': prxid, 'hostname': host, 'uri': uri, 'flow': flow }
    
    conn = httplib.HTTPConnection(controller)
    conn.request('POST', "/wm/cdnmanager/priv/v1.0/proxyreq",
        json.dumps(body), { 'content-type': 'application/json' })
    conn.getresponse()
