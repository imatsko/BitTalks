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
__date__ ="$15.03.2014 9:40:02$"

import logging
module_logger = logging.getLogger("rpc")
module_logger.setLevel(logging.DEBUG)

from twisted.internet.protocol import DatagramProtocol
from twisted.internet.defer import Deferred
import random
import hashlib

class MessageParseException(Exception):
    pass

class RPCTimeout(Exception):
    pass

class RemoteError(Exception):
    pass

class RPCMessage(object):
    """
    Base class for RPC messages. Requires "id" field in messages.
    """
    def __init__(self, rpc_id=None):
        self.rpc_id = rpc_id

    def __str__(self):
        return "{}: {}".format(self.__class__.__name__, self.__dict__)


class RPCRequest(RPCMessage):
    """
    RPC request message. Has "method" and "params" fields.
    """
    def __init__(self, rpc_id=None, method="", params=()):
        RPCMessage.__init__(self, rpc_id)
        self.method = method
        self.params = params

class RPCResponse(RPCMessage):
    """
    RPC response message. contains "result" and "error" fields.
    """
    def __init__(self, rpc_id=None, result=None, error=None):
        RPCMessage.__init__(self, rpc_id)
        self.result = result
        self.error = error


class RPCMessageFactory(object):
    def fromRaw(self, data):
        raise NotImplementedError("fromRaw")
    
    def toRaw(self):
        raise NotImplementedError("toRaw")
    
    def makeRequest(self, rpc_id=None, method="", params=()):
        raise NotImplementedError("makeRequest")
    
    def makeResponse(self, rpc_id=None, result=None, error=None):
        raise NotImplementedError("makeResponse")

class RPCHandler(object):
    rpc_prefix = "rpc_"
    
    def handleCall(self, msg, address):    
        df = Deferred()
        try:            
            m = getattr(self, self.rpc_prefix + msg.method, None)
            if callable(m):
                module_logger.debug("handling {} from {}".format(msg, address))
                result = m(*msg.params)
                df.callback(result)
            else:
                raise Exception("unknown rpc {}".format(msg.method))
        except Exception as e:
            df.errback(e)
        return df

class RPCServerProtocol(DatagramProtocol):
    def __init__(self, rpc_handler, msg_factory=RPCMessageFactory()):
        self.handler = rpc_handler
        self.msg_factory = msg_factory
    
    def datagramReceived(self, datagram, address):
        msg = self.msg_factory.fromRaw(datagram)

        if isinstance(msg, RPCRequest):
            d = self.handler.handleCall(msg, address)
            if d is None:
                return
            
            def handle_result(result):
                self._send_result(result, msg.rpc_id, address)
            def handle_error(fail):
                self._send_error(fail, msg.rpc_id, address)
            if msg.rpc_id:
                d.addCallbacks(handle_result, handle_error)
    
    def _send_result(self, result, rpc_id, address):
        msg = self.msg_factory.makeResponse(rpc_id, result=result)
        self._send_message(msg, address)

    def _send_error(self, fail, rpc_id, address):
        msg = self.msg_factory.makeResponse(rpc_id, error=str(fail))
        self._send_message(msg, address)
        
    def _send_message(self, msg, address):
        module_logger.debug("sending {} to {}".format(msg, address))
        self.transport.write(self.msg_factory.toRaw(msg), address)


class RPCClientProtocol(DatagramProtocol):
    rpc_timeout = 3
    
    def __init__(self, msg_factory=RPCMessageFactory()):
        self.msg_factory = msg_factory
        self.sent_msg = {}
        
    def callRPC(self, address, method, params=(), responsable=True):
        if responsable:
            id = self._generate_msg_id(address, method, params)
            msg = self.msg_factory.makeRequest(id, method, params)
            self._send_message(msg, address)
            
            df = Deferred()
            from twisted.internet import reactor
            timeout_call = reactor.callLater(self.rpc_timeout, self._msg_timeout, msg.rpc_id)
            self.sent_msg[id] = (df, timeout_call)
            def rm_msg(arg):
                del self.sent_msg[id]
                return arg
            df.addBoth(rm_msg)
            return df
        else:
            id = None
            msg = self.msg_factory.makeRequest(id, method, params)
            self._send_message(msg, address)
            return None
        
    def datagramReceived(self, datagram, address):
        msg = self.msg_factory.fromRaw(datagram)
        
        if isinstance(msg, RPCResponse) and msg.rpc_id in self.sent_msg:
            df, timeout_call = self.sent_msg[msg.rpc_id]
            timeout_call.cancel()
            if msg.error:
                df.errback(RemoteError(msg.error))
            else:
                df.callback(msg.result)
                
        
    def _send_message(self, msg, address):
        self.transport.write(self.msg_factory.toRaw(msg), address)
    
    def _msg_timeout(self, msg_id):
        if msg_id in self.sent_msg:
            df, timeout_call = self.sent_msg[msg_id]
            df.errback(RPCTimeout("timeout of {} for rpc_id {}".format(self.rpc_timeout, msg_id)))

    
    def _generate_msg_id(self, address, method, params):
        id = hashlib.md5()
        id.update(str(address).encode("utf-8"))
        id.update(str(method).encode("utf-8"))
        id.update(str(params).encode("utf-8"))
        id.update(str(random.randint(0, 1000)).encode("utf-8"))
        return id.hexdigest()
    
