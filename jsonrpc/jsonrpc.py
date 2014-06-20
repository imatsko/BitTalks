#Copyright (c) 2014 Igor Matsko
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in 
#the Software without restriction, including without limitation the rights to use, 
#copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
#the Software, and to permit persons to whom the Software is furnished to do so, 
#subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all 
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR 
#A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
#HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
#OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
#THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 

__author__="rigel92"
__date__ ="$14.03.2014 17:33:52$"


import encoding
import rpc


class JSONRPCMessageFactory(rpc.RPCMessageFactory):
    codec = encoding.JSONCodec()

    def _from_primitive(self, msg_prim):
        if not isinstance(msg_prim, dict):
            raise rpc.MessageParseException("not dict: {}".format(msg_prim))
        
        if "method" in msg_prim:
            req = rpc.RPCRequest()
            try:
                req.rpc_id = msg_prim["id"]
                req.method = msg_prim["method"]
                req.params = msg_prim["params"]
            except KeyError:
                raise rpc.MessageParseError("Cannot parse {}".format(msg_prim))
            return req
        elif "result" in msg_prim:
            res = rpc.RPCResponse()
            try:
                res.rpc_id = msg_prim["id"]
                res.result = msg_prim["result"]
                res.error = msg_prim["error"]
            except KeyError:
                raise rpc.MessageParseError("Cannot parse {}".format(msg_prim))
            return res
        else:
            raise rpc.MessageParseException("neither method nor result fields are found")
    
    
    def fromRaw(self, data):
        d = self.codec.decode(data)
        return self._from_primitive(d)
    
    def _to_primitive(self, msg):
        d = dict()
        if isinstance(msg, rpc.RPCRequest):
            d["id"] = msg.rpc_id
            d["method"] = msg.method
            d["params"] = msg.params
        elif isinstance(msg, rpc.RPCResponse):
            d["id"] = msg.rpc_id
            d["result"] = msg.result
            d["error"] = msg.error
        return d
    
    def toRaw(self, msg):
        d = self._to_primitive(msg)
        return self.codec.encode(d)

    def makeRequest(self, rpc_id=None, method="", params=()):
        return rpc.RPCRequest(rpc_id, method, params)
    
    def makeResponse(self, rpc_id=None, result=None, error=None):
        return rpc.RPCResponse(rpc_id, result, error)
    
    
class JSONRPCServerProtocol(rpc.RPCServerProtocol):
    def __init__(self, rpc_handler):
        rpc.RPCServerProtocol.__init__(self, rpc_handler, msg_factory=JSONRPCMessageFactory())

class JSONRPCClientProtocol(rpc.RPCClientProtocol):
    def __init__(self):
        rpc.RPCClientProtocol.__init__(self, msg_factory=JSONRPCMessageFactory())

class JSONRPCProtocol(JSONRPCServerProtocol, JSONRPCClientProtocol):
    def __init__(self, rpc_handler):
        JSONRPCServerProtocol.__init__(self, rpc_handler)
        JSONRPCClientProtocol.__init__(self)

    def datagramReceived(self, datagram, address):
        JSONRPCServerProtocol.datagramReceived(self, datagram, address)
        JSONRPCClientProtocol.datagramReceived(self, datagram, address)    
