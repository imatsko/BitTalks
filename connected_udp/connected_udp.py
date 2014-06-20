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
__date__ ="$22.03.2014 19:34:01$"

import logging
module_logger = logging.getLogger("connected_udp")
module_logger.setLevel(logging.DEBUG)

from twisted.internet.protocol import Protocol, DatagramProtocol, Factory
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
import struct
import time
import random

class WrapAroundCounter(object):
    def __init__(self, limit_value, value=0):
        self.limit_value = limit_value
        self.value = value
    
    def nextValue(self):
        n_val = self.value+1
        if n_val >= self.limit_value:
            n_val = 0
        return n_val
    
    def setValue(self, n_value):
        self.value = n_value % (self.limit_value)
    
    def isValueMoreRecent(self, value):
        return ((value > self.value) and (value - self.value <= self.limit_value/2)
                or (value < self.value) and (self.value - value > self.limit_value/2))



class ConnectedUDPFactory(Factory):
    def __init__(self, protocol):
        self.protocol = protocol
    def startFactory(self):
        pass
    def stopFactory(self):
        pass
    def buildProtocol(self, address):
        return self.protocol()
    
    
#class Protocol(object):
#    def makeConnection(self, transport):
#        self.transport = transport
#        self.connectionMade()
#        
#    def connectionMade(self):
#        pass
#    def dataReceived(self, data):
#        pass
#    def connectionLost(self):
#        pass


class ConnectedUDPPackage(object):
    class NotValidPackage(Exception):
        pass
    
    SYN = 1
    ACK = 2
    FIN = 4
    header_fmt = "!HHHHB"
    header_size = struct.calcsize(header_fmt)
    
    def __init__(self, channel_from=0, channel_to=0, data=""):
        self.channel_from = channel_from
        self.channel_to = channel_to
        self.data = data
        self.pkg_num = 0
        self.ack_num = 0
        self.flags = 0
    
    def __str__(self):
        return self.__repr__()
    
    def __repr__(self):
        return str(self.__dict__)
    
    def pack(self):
        header = struct.pack(self.header_fmt,
            self.channel_from,
            self.channel_to,
            self.pkg_num,
            self.ack_num,
            self.flags)
        result = "\x00{}\x00{}".format(header, self.data)
        return result    
    
    @classmethod
    def unpack(cls, data):
        if len(data) < cls.header_size+2:
            raise cls.NotValidPackage()
        if not (data[0] == "\x00" and data[cls.header_size+1] == "\x00"):
            raise cls.NotValidPackage()
        pkg = ConnectedUDPPackage()
        (pkg.channel_from,
            pkg.channel_to,
            pkg.pkg_num,
            pkg.ack_num,
            pkg.flags) = struct.unpack(cls.header_fmt, data[1:cls.header_size+1])
        pkg.data = data[cls.header_size+2:]
        return pkg


class UDPConnection(object):
    ack_loop_interval = 0.3
    ack_timeout = 0.2
    retr_loop_interval = 0.6
    retr_timeout = 1
    keepalive_loop_interval = 5
    keepalive_timeout = 10
    dead_connection_timeout = 30
    
    # connection states
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_SENT = 4    
    
    def __init__(self, protocol, udp):
        self.protocol = protocol
        self.udp = udp
        
        self.self_channel = None
        self.peer_channel = None
        self.peer_addr = None
        self.peer_port = None
        
        self.pkg_seq = WrapAroundCounter(2**16, 1)
        self.ack_seq = WrapAroundCounter(2**16, 0)
        self.in_progress = list()
        self.received = dict()
        
        self.last_ack_val = self.ack_seq.value
        self.last_ack_time = 0
        
        self.last_activity = 0
        self.last_answer = 0
        
        self.ack_loop = LoopingCall(self._ackLoop)
        self.retr_loop = LoopingCall(self._retransmitLoop)
        self.keepalive_loop = LoopingCall(self._keepaliveLoop)

        self.state = self.CLOSED
        return    
    
#    Public interface
    def initConnection(self, addr, port, self_channel):
        if self.state != self.CLOSED:
            raise Exception("reinit non closed connection")
        
        self.self_channel = self_channel
        self.peer_addr = addr
        self.peer_port = port
        self.pkg_seq.setValue(random.randint(0, self.pkg_seq.limit_value-1))
        self.state = self.SYN_SENT
        self._initTimers()
        self._startTimers()
        self._sendInit()
        return
    
    def receiveConnection(self, init_pkg, self_channel, addr, port):
        if self.state != self.CLOSED:
            raise Exception("reinit non closed connection")

        self.self_channel = self_channel
        self.peer_addr = addr
        self.peer_port = port
        self.peer_channel = init_pkg.channel_from
        self.state = self.SYN_RECEIVED
        self.pkg_seq.setValue(random.randint(0, self.pkg_seq.limit_value-1))
        self.ack_seq.setValue(init_pkg.pkg_num)
        self._initTimers()
        self._startTimers()
        self._sendRecvInit()
        return
    
#   TransportInterface
    def loseConnection(self):
        if self.state == self.ESTABLISHED:
            self._sendFin()
        self._connectionLost()
        return
    
    def write(self, data):
        if self.state != self.ESTABLISHED:
            raise Exception("Connection is not established")

        df = Deferred()
        pkg = ConnectedUDPPackage()
        pkg.channel_from = self.self_channel
        pkg.channel_to = self.peer_channel
        pkg.data = data
        self._sendPackage(pkg, df)
        return df
    
    def writeSequence(self, data):
        df = None
        for d in data:
            df = self.write(d)
        return df
    
    def getPeer(self):
        return (self.peer_addr, self.peer_port, self.peer_channel)
    
    def getHost(self):
        if self.udp.transport:
            host = self.udp.transport.getHost()
        else:
            host = ''
        addr = host.host
        port = host.port
        return (addr, port, self.self_channel)
    
#   Internals
    def packageReceived(self, pkg):
        module_logger.debug("{} received pkg: {}".format(
                self._dbg_id(),
                pkg.__dict__
            ))
            
        self.last_answer = time.time()
        if self.state == self.CLOSED:
            pass
        elif self.state == self.SYN_SENT:
            if (pkg.flags&pkg.ACK) and (pkg.flags&pkg.SYN):
                self.peer_channel = pkg.channel_from
                self.ack_seq.setValue(pkg.pkg_num-1)
                self._processAck(pkg)
                self._processSyn(pkg)
                self.state = self.ESTABLISHED
                
                module_logger.debug("{} on SYN_SENT pkg_seq: {}, ack_seq:{}, pkg:{}".format(
                        self._dbg_id(),
                        self.pkg_seq.value, self.ack_seq.value, pkg.__dict__
                    ))
                    
                self.protocol.makeConnection(self)
                
        elif self.state == self.SYN_RECEIVED:
            if pkg.channel_from != self.peer_channel:
                return
            if pkg.flags & pkg.ACK:
                self._processAck(pkg)
                self.state = self.ESTABLISHED
                self.protocol.makeConnection(self)
            if pkg.flags & pkg.SYN:
                self._processSyn(pkg)
                
        elif self.state == self.ESTABLISHED:
            if pkg.channel_from != self.peer_channel:
                return
            if pkg.flags & pkg.ACK:
                self._processAck(pkg)
            if pkg.flags & pkg.SYN:
                self._processSyn(pkg)
                
            if pkg.flags & pkg.FIN:
                self._connectionLost() 
        return
    
    def _processAck(self, pkg):
        cnt = WrapAroundCounter(2**16, pkg.ack_num)
        for p in self.in_progress[:]:
            if not cnt.isValueMoreRecent(p[0].pkg_num):
                self.in_progress.remove(p)
                p[1].callback(None)
        return

    def _processSyn(self, pkg):
        if not self.ack_seq.isValueMoreRecent(pkg.pkg_num):
            self._sendAck()
        self.received[pkg.pkg_num] = pkg
        self._deliverReceivedPackages()
        return

    def _deliverReceivedPackages(self):
        if len(self.received) != 0:
            k = sorted(self.received.keys())[0]
            if not self.ack_seq.isValueMoreRecent(self.received[k].pkg_num):
                del self.received[k]
            elif self.received[k].pkg_num == self.ack_seq.nextValue():
                self.ack_seq.setValue(self.ack_seq.nextValue())
                if len(self.received[k].data) != 0:
                    self.protocol.dataReceived(self.received[k].data)
                del self.received[k]
                self._deliverReceivedPackages()
    
    def _connectionLost(self):
        self.state = self.CLOSED
        self.udp._removeConnection(self.self_channel)
        self._stopTimers()
        proto = self.protocol
        del self.protocol
        proto.connectionLost()
        return
    
    def _ackLoop(self):
        now = time.time()
        if now-self.last_ack_time > self.ack_timeout and self.last_ack_val != self.ack_seq.value:
            
            module_logger.debug("{} forced ACK".format(
                    self._dbg_id()
                ))

            self._sendAck()
        return
    
    def _retransmitLoop(self):
        now = time.time()
        for p in self.in_progress[:]:
            if now-p[2] > self.retr_timeout:
                    
                module_logger.debug("{} retransmission, pkg:{}".format(
                        self._dbg_id(),
                        p[0].__dict__
                    ))
                
                self.in_progress.remove(p)
                self.in_progress.append((p[0], p[1], now))
                self._sendRawPackage(p[0])
        return
    
    def _keepaliveLoop(self):
        now = time.time()
        if now-self.last_activity > self.keepalive_timeout:
            pkg = ConnectedUDPPackage(self.self_channel, self.peer_channel, "")
            
            module_logger.debug("{} keepalive msg, pkg:{}".format(
                self._dbg_id(),
                pkg.__dict__
            ))
            
            self._sendPackage(pkg, Deferred())
        if now-self.last_answer > self.dead_connection_timeout:
            
            module_logger.debug("{} close connection on dead timeout".format(
                self._dbg_id()
            ))
            
            self._connectionLost()
        return
            
    def _sendInit(self):
        init_pkg = ConnectedUDPPackage(self.self_channel, 0, "")
        
        module_logger.debug("{} send init, pkg:{}".format(
                self._dbg_id(),
                init_pkg.__dict__
            ))

        return self._sendPackage(init_pkg, Deferred())
    
    def _sendRecvInit(self):
        response_pkg = ConnectedUDPPackage(self.self_channel, self.peer_channel, "")
        
        module_logger.debug("{} send recv init, pkg:{}".format(
                self._dbg_id(),
                response_pkg.__dict__
            ))

        return self._sendPackage(response_pkg, Deferred())
    
    def _sendAck(self):
        pkg = ConnectedUDPPackage()
        pkg.channel_from = self.self_channel
        pkg.channel_to = self.peer_channel
        
        module_logger.debug("{} send ACK, pkg:{}".format(
                self._dbg_id(),
                pkg.__dict__
            ))

        return self._sendRawPackage(pkg)
    
    def _sendFin(self):
        pkg = ConnectedUDPPackage()
        pkg.channel_from = self.self_channel
        pkg.channel_to = self.peer_channel
        pkg.flags = pkg.flags | pkg.FIN
        
        module_logger.debug("{} send FIN, pkg:{}".format(
                self._dbg_id(),
                pkg.__dict__
            ))

        
        return self._sendRawPackage(pkg)
    
    def _sendPackage(self, pkg, df):
        pkg.pkg_num = self.pkg_seq.value
        self.pkg_seq.setValue(self.pkg_seq.nextValue())
        pkg.flags = pkg.flags|pkg.SYN
        self.in_progress.append((pkg, df, time.time()))
        return self._sendRawPackage(pkg)
    
    def _sendRawPackage(self, pkg):
        pkg.ack_num = self.ack_seq.value
        pkg.flags = pkg.flags|pkg.ACK
        self.last_ack_val = self.ack_seq.value
        self.last_ack_time = time.time()
        self.last_activity = time.time()
        return self.udp.transport.write(pkg.pack(), (self.peer_addr, self.peer_port))
    
    def _initTimers(self):
        self.last_ack_time = time.time()
        self.last_activity = time.time()
        self.last_answer = time.time()
        return 
    
    def _startTimers(self):
        self.ack_loop.start(self.ack_loop_interval)
        self.retr_loop.start(self.retr_loop_interval)
        self.keepalive_loop.start(self.keepalive_loop_interval)
        return
    
    def _stopTimers(self):
        self.ack_loop.stop()
        self.retr_loop.stop()
        self.keepalive_loop.stop()
        return
    
    def _dbg_id(self):
        dbg_host = self.getHost()
        dbg_peer = self.getPeer()
        return "connection id:{}, self_addr:{}, self_port:{}, self_ch:{} , peer_addr:{} , peer_port:{} , peer_ch: {}".format(
                id(self),
                dbg_host[0],dbg_host[1],dbg_host[2],
                dbg_peer[0],dbg_peer[1],dbg_peer[2]
            )

class ConnectedUDPProtocol(DatagramProtocol):
    class CannotCreateNewConnection(Exception):
        pass
    
    channel_limit = 2**16
    def __init__(self, connected_protocol_factory, common_udp_protocol=None):
        self.common_protocol = common_udp_protocol
        self.connected_factory = connected_protocol_factory
        self.connections = dict()
        return
    
#   DatagramProtocol interface
    def stopProtocol(self):
        self.connected_factory.doStop()
        for channel in self.connections:
            self.connections[channel].loseConnection()
    
    def makeConnection(self, transport):
        DatagramProtocol.makeConnection(self, transport)
        if not self.common_protocol is None:
            self.common_protocol.makeConnection(transport)
        self.connected_factory.doStart()
        return

    def datagramReceived(self, data, (addr, port)):
        try:
            pkg = ConnectedUDPPackage.unpack(data)
        except ConnectedUDPPackage.NotValidPackage:
            module_logger.debug("received not connected package from ({},{}) with data: {}".format(addr, port, repr(data)))
            if not self.common_protocol is None:
                self.common_protocol.datagramReceived(data, (addr, port))
                return
        
        module_logger.debug("received connected package from ({}, {}) : {}".format(addr, port, pkg.__dict__))
        
        if pkg.channel_to == 0 and pkg.channel_from != 0:
            self.receiveConnection(pkg, addr, port)
        elif pkg.channel_to in self.connections:
            conn = self.connections[pkg.channel_to]
            if addr == conn.peer_addr and port == conn.peer_port:
                self.connections[pkg.channel_to].packageReceived(pkg)
        return
    
#   Public interface
    def connect(self, addr, port, protocol):
        channel = self._getFreeStream()
        if not channel is None:
            conn = UDPConnection(protocol, self)
            self.connections[channel] = conn
            conn.initConnection(addr, port, channel)
            module_logger.debug("Created new connection to {}:{} self channel {}".format(addr, port, channel))
        else:
            module_logger.error("Cannot connect to {}:{}. All channels a busy".format(addr, port))
            raise self.CannotCreateNewConnection()
        return

#   Internals
    def receiveConnection(self, init_pkg, addr, port):
        channel = self._getFreeStream()
        if channel is None:
            module_logger.error("Cannot receive connection from {}:{}. All channels a busy".format(addr, port))
            return
        proto = self.connected_factory.buildProtocol((addr, port))
        if proto is None:
            return
        conn = UDPConnection(proto, self)
        self.connections[channel] = conn
        conn.receiveConnection(init_pkg, channel, addr, port)
        return
    
    def _getFreeStream(self):
        for x in range(1, self.channel_limit):
            if not x in self.connections:
                return x
        return
    
    def _removeConnection(self, channel):
        if channel in self.connections:
            c = self.connections[channel]
            del self.connections[channel]
            
#================TESTS=================

class TestProtocol(Protocol):
    def connectionMade(self):
        print id(self), "connection_made in client app"
    def dataReceived(self, data):
        print id(self), " in client app recv:", data
    def connectionLost(self):
        print id(self), "connection lost in client app"
    def write_data(self, data):
        print id(self), "write data in client app", data
        self.transport.write(data)
    def close_connection(self):
        print id(self), "active closing connection"
        self.transport.loseConnection()

class TestDatagram(DatagramProtocol):
    def datagramReceived(self, data, addr):
        print "received on add udp", repr(data), "from", addr

    def send(self, data, address):
        print "send over add udp to", address
        self.transport.write(data, address)

def test_package():
    pkg = ConnectedUDPPackage(10, 20, "ololo")
    p = pkg.pack()
    print "pkg:", pkg.__dict__
    print "packed:", repr(p)
    pkg2 = ConnectedUDPPackage.unpack(p)
    print "unpacked", pkg2.__dict__


def test_udp_message():
    class CommonUDPProto(DatagramProtocol):
        def send(self, data, address):
            print "send over common udp to", address
            self.transport.write(data, address)
        def datagramReceived(self, data, (host, port)):
            print "received %r from %s:%d on common udp" % (data, host, port)
            self.transport.write(data, (host, port))

    add_udp = TestDatagram()
    f = ConnectedUDPFactory(TestProtocol)
    conn_proto = ConnectedUDPProtocol(f, add_udp)
    conn_proto_addr = ("127.0.0.1", 7778)

    cmn_udp = CommonUDPProto()
    cmn_udp_addr = ("127.0.0.1", 8998)

    def send_from_add():
        print "sending from add_udp"
        add_udp.send("hello from add udp", cmn_udp_addr)

    def send_from_cmn():
        print "sending from cmn_udp"
        cmn_udp.send("hello from cmn udp", conn_proto_addr)

    from twisted.internet import reactor

    def stop():
        reactor.stop()

    reactor.listenUDP(conn_proto_addr[1], conn_proto)
    reactor.listenUDP(cmn_udp_addr[1], cmn_udp)

    reactor.callLater(3, send_from_add)
    reactor.callLater(6, send_from_cmn)
    reactor.callLater(10, stop)

    print "prepared for run"
    reactor.run()
    print "stopped"
    return   

def test_connect_to_self():   
    f = ConnectedUDPFactory(TestProtocol)
    conn_proto = ConnectedUDPProtocol(f, TestDatagram())
    conn_proto_addr = ("127.0.0.1", 7778)

    active_proto = TestProtocol()

    def make_connection():
        conn_proto.connect("127.0.0.1", conn_proto_addr[1], active_proto)

    def send_later():
        active_proto.write_data("sent test data")

    def send_much_later():
        active_proto.write_data("sent test data much later")

    def close_connection():
        active_proto.close_connection()

    from twisted.internet import reactor

    def stop():
        reactor.stop()

    reactor.listenUDP(conn_proto_addr[1], conn_proto)

    reactor.callLater(1, make_connection)
    reactor.callLater(5, send_later)
    reactor.callLater(10, send_much_later)
    reactor.callLater(15, close_connection)
    reactor.callLater(20, stop)

    print "prepared for run"
    reactor.run()
    print "stopped"
    return

def test_connect_to_other():
    f1 = ConnectedUDPFactory(TestProtocol)
    conn_proto1 = ConnectedUDPProtocol(f1, TestDatagram())
    conn_proto1_addr = ("127.0.0.1", 7778)
    active_proto1 = TestProtocol()

    f2 = ConnectedUDPFactory(TestProtocol)
    conn_proto2 = ConnectedUDPProtocol(f2, TestDatagram())
    conn_proto2_addr = ("127.0.0.1", 7779)
    active_proto2 = TestProtocol()

    def make_connection1():
        conn_proto1.connect("127.0.0.1", conn_proto2_addr[1], active_proto1)

    def send_later1():
        active_proto1.write_data("sent test data")

    def send_much_later1():
        active_proto1.write_data("sent test data much later")

    def close_connection1():
        active_proto1.close_connection()

    def make_connection2():
        conn_proto2.connect("127.0.0.1", conn_proto1_addr[1], active_proto2)

    def send_later2():
        active_proto2.write_data("sent test data")

    def send_much_later2():
        active_proto2.write_data("sent test data much later")

    def close_connection2():
        active_proto2.close_connection()

    from twisted.internet import reactor

    def stop():
        reactor.stop()

    reactor.listenUDP(conn_proto1_addr[1], conn_proto1)
    reactor.listenUDP(conn_proto2_addr[1], conn_proto2)

    reactor.callLater(1, make_connection1)
    reactor.callLater(5, send_later1)
    reactor.callLater(10, send_much_later1)
    reactor.callLater(15, close_connection1)

    reactor.callLater(20, make_connection2)
    reactor.callLater(25, send_later2)
    reactor.callLater(30, send_much_later2)
    reactor.callLater(35, close_connection2)

    reactor.callLater(40, stop)

    print "prepared for run"
    reactor.run()
    print "stopped"

    return

if __name__ == "__main__":
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    module_logger.addHandler(console)
    
#    test_udp_message()

#    test_connect_to_self()

    test_connect_to_other()

