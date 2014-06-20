# -*- encoding: utf8 -*-
#
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
__date__ ="$12.06.2014 20:28:52$"

from gi.repository import GObject
from gi.repository import Gtk


from twisted.internet.protocol import Protocol, Factory
from twisted.internet.task import LoopingCall

class Protocol(object, Protocol):
    pass

class Factory(object, Factory):
    pass

from dht.protocol import BitTalksDHTNode
from connected_udp.secure_connected_udp import ConnectedUDPProtocol, SecureConnection, PeerChecker

import json
import hashlib
import base64

from hashlib import md5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import StringIO

class ProfileEncrypter(object):
    blocks_per_chunk = 1024
    magic = '!' * AES.block_size
    salt_prefix = 'Salted__'
    
    class DecryptionException(Exception):
        pass
    
    @classmethod
    def derive_key_and_iv(cls, password, salt, key_length, iv_length):
        d = d_i = ''
        while len(d) < key_length + iv_length:
            d_i = md5(d_i + password + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length+iv_length]

    @classmethod
    def encrypt(cls, in_str, out_file, password, key_length=32):
        in_file = StringIO.StringIO(in_str)
        bs = AES.block_size
        salt = Random.new().read(bs - len('Salted__'))
        key, iv = cls.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write('Salted__' + salt)
        out_file.write(cipher.encrypt(cls.magic))
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = bs - (len(chunk) % bs)
                chunk += padding_length * chr(padding_length)
                finished = True
            out_file.write(cipher.encrypt(chunk))
        in_file.close()

    @classmethod
    def decrypt(cls, in_file, password, key_length=32):
        out_file = StringIO.StringIO()
        bs = AES.block_size
        salt = in_file.read(bs)[len('Salted__'):]
        key, iv = cls.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        magic = cipher.decrypt(in_file.read(bs))
        if magic != cls.magic:
            raise DecryptionException("Wrong password")
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = ord(chunk[-1])
                if padding_length < 1 or padding_length > bs:
                   raise ValueError("bad decrypt pad (%d)" % padding_length)
                # all the pad-bytes must be the same
                if chunk[-padding_length:] != (padding_length * chr(padding_length)):
                   # this is similar to the bad decrypt:evp_enc.c from openssl program
                   raise ValueError("bad decrypt")
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(chunk)
        
        out_str = out_file.getvalue()
        out_file.close()
        return out_str
        


class MessengerProtocol(Protocol):
    def __init__(self, buddy=None):
        self.buddy = buddy
        if not buddy is None:
            self.buddy.connection = self
        
    def connectionMade(self):
        if self.buddy:
            self.buddy.on_connection_made()

    def dataReceived(self, data):
        if self.buddy:
            self.buddy.on_message_received(data)
            
    def connectionLost(self):
        if self.buddy:
            self.buddy.on_connection_lost()        

    def write(self, data):
        self.transport.write(data)
    
    def loseConnection(self):
        self.transport.loseConnection()


def compute_pub_der_hash(rsa_pub_der):
    hash = hashlib.sha1()
    hash.update(rsa_pub_der)
    return hash.hexdigest()

def compute_pub_hash(rsa_pub_key):
    rsa_pub_der = rsa_pub_key.exportKey(format='DER')
    hash = hashlib.sha1()
    hash.update(rsa_pub_der)
    return hash.hexdigest()

def compute_prv_hash(rsa_prv_key):
    rsa_pub_der = rsa_prv_key.publickey().exportKey(format='DER')
    hash = hashlib.sha1()
    hash.update(rsa_pub_der)
    return hash.hexdigest()


class Buddy(GObject.GObject):
    __gsignals__ = {
        'connection-info': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, (GObject.TYPE_STRING, )),
        'message-received': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, (GObject.TYPE_STRING, )),
    }
    
    class Status(object):
        CONNECTED = 0
        ONLINE = 1
        OFFLINE = 2
    
    name = GObject.property(type=str)
    key_hash = GObject.property(type=str)
    
    
    status = GObject.property(type=int, default=Status.OFFLINE)
    
    visible_name = GObject.property(type=str)
    
    def __init__(self, profile, name='', status=Status.OFFLINE):
        GObject.GObject.__init__(self)
        self.connect('notify::name', self.on_notify_name)
        
        self.profile = profile
        self.name = name
        self.status = status
        
        self.connection = None

    def set_connection(self, connection):
        self.connection = connection
        self.connection.buddy = self
        self.profile.emit('open-talk', self)
        pass
        
    def on_send_message(self,widget, message):
        if self.status == self.Status.CONNECTED:
            self.connection.write(message)
        else:
            self.emit('connection-info', "Невозможно отправить сообщение, не устанослено соединение")
    
    def on_connection_made(self):
        self.status = self.Status.CONNECTED
        self.emit('connection-info', "Соединение установлено")

    def on_message_received(self, data):
        self.profile.emit('open-talk', self)
        self.emit('message-received', data)
            
    def on_connection_lost(self):
        self.status = self.Status.ONLINE
        self.emit('connection-info', "Соединение закрыто")

    def make_connection(self, widget=None):
        if self.status == self.Status.ONLINE:
            self.emit('connection-info', "Устанавливается соединение...")
            self.profile.connect_to_buddy(self)
#            self.on_connection_made()
            
    def lose_connection(self, widget=None):
        if self.connection:
            self.connection.loseConnection()
            
    def on_notify_name(self, obj, gparamstring):
#        self.visible_name = self.name
        if not self.name:
            self.visible_name = self.key_hash[:10]+"..."
        else:
            self.visible_name = self.name

    def __repr__(self):
        return '%s, %s, %i' % (self.get_property('name'), self.get_property('key_hash'), self.get_property('status'))

    
    def to_primitive(self):
        buddy = dict()
        buddy['name'] = self.name
        buddy['key_hash'] = self.key_hash
        
        return buddy

    @classmethod
    def from_primitive(cls, prim, profile):
        buddy = cls(profile)
        buddy.name = prim['name']
        buddy.key_hash = prim['key_hash']
        
        return buddy



class Profile(GObject.GObject, Factory, PeerChecker):

    class Status(object):
        ONLINE = 0
        OFFLINE = 1
        
    __gsignals__ = {
        'open-talk': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, (Buddy.__gtype__, )),
    }

    
    username = GObject.property(type=str)
    
    status = GObject.property(type=int, default=Status.OFFLINE)
    
#    pub_key = GObject.property(type=str)
#    prv_key = GObject.property(type=str)
    
    update_net_stat_interval = 5
    
    update_buddy_stat_interval = 30
    
    def __init__(self, port=8899, known_nodes=list()):
        GObject.GObject.__init__(self)
#        self.pub_key = ''
        self.prv_key = RSA.generate(2048)
        
        self.username = "new profile"
        self.password = ""
        self.status = Profile.Status.OFFLINE
        
        self.buddy_store = Gtk.ListStore(Buddy.__gtype__)
        
        self.path = 'user.prof'
        
        self.connection = None
        self.dht = None
        self.udp_port = None
        
        self.port = port
        self.known_nodes = known_nodes
        
        self.update_net_stat_loop = LoopingCall(self._update_net_stat_loop)
        self.update_buddy_stat_loop = LoopingCall(self._update_buddy_stat_loop)
#        self.init_network()
   
    def _update_net_stat_loop(self):
        if len(self.dht.routing_table) == 0:
            self.status = Profile.Status.OFFLINE
            self.update_network()
        else:
            if self.status == Profile.Status.OFFLINE:
                self.connect_network()
            self.status = Profile.Status.ONLINE
    
    def _update_buddy_stat_loop(self):
        if self.status != Profile.Status.ONLINE:
            return
        
        buddy_iter = self.buddy_store.get_iter_first()
        while buddy_iter != None:
            buddy = self.buddy_store[buddy_iter][0]
            self.update_buddy_stat(buddy)
            buddy_iter = self.buddy_store.iter_next(buddy_iter)
    
    def _start_loops(self):
        if not self.update_net_stat_loop.running:
            self.update_net_stat_loop.start(self.update_net_stat_interval)
        
        if not self.update_buddy_stat_loop.running:
            self.update_buddy_stat_loop.start(self.update_buddy_stat_interval)
    
    def _stop_loops(self):
        self.update_net_stat_loop.stop()
        self.update_buddy_stat_loop.stop()
    
    def update_buddy_stat(self, buddy):
        def defer_handler(result):
            if len(result) == 0:
                if buddy.status != Buddy.Status.CONNECTED:
                    buddy.status = Buddy.Status.OFFLINE
            else:
                if buddy.status != Buddy.Status.CONNECTED:
                    buddy.status = Buddy.Status.ONLINE
            return result
        def defer_err(f):
            if buddy.status != Buddy.Status.CONNECTED:
                buddy.status = Buddy.Status.OFFLINE
            return f
        df = self.dht.findValue(buddy.key_hash)
        df.addCallbacks(defer_handler, defer_err)
        return df

        pass
    
    def update_network(self):
        print "try connect", self.known_nodes
        return self.dht.joinNetwork(self.known_nodes)
        
    def connect_network(self):
        self._start_loops()
        join_df = self.update_network()
        self._update_buddy_stat_loop()
        def init_publ(arg=None):
            print "connection made"
    #            for key_d in self_keys:
            self.status = Profile.Status.ONLINE
            self.dht.publishKey(self.prv_key)
            return arg
        
        def err_init(arg=None):
            print "connection error", arg
            self.status = Profile.Status.OFFLINE
            
        join_df.addCallbacks(init_publ, err_init)
        return
    
    def disconnect_network(self):
        self._stop_loops()
        self.status = Profile.Status.OFFLINE
        self.dht.published.remove(self.prv_key)
        pass
    
    def init_network(self):
        from twisted.internet import reactor

        def network():
            self.dht = BitTalksDHTNode()
            connected_protocol = ConnectedUDPProtocol(self, self.dht.protocol)
            self.connection = connected_protocol
            self.udp_port = reactor.listenUDP(self.port, connected_protocol)

            self.connect_network()
            

        callID = reactor.callLater(2, network)
    
    def stop_network(self):
        self.status = Profile.Status.OFFLINE
        if self.dht:
            self.dht._stop_loops()
        if self.connection:
            self.connection.stopProtocol()
        if self.udp_port:
            self.udp_port.stopListening()
    
    def buildProtocol(self, address):
        available_priv_keys = [self.prv_key]
        cli_proto = MessengerProtocol()
        sec_proto = SecureConnection(cli_proto)
        sec_proto.initPassive(available_priv_keys, self)
        return sec_proto
    
    def checkPeer(self, addr, port, peer_pub_key, self_pub_key, connection):
        print "Check:", addr, port, repr(peer_pub_key), repr(self_pub_key)
        
        key_hash = compute_pub_der_hash(peer_pub_key)

        buddy_iter = self.buddy_store.get_iter_first()
        while buddy_iter != None:
            buddy = self.buddy_store[buddy_iter][0]
            if buddy.key_hash == key_hash:
                buddy.set_connection(connection.protocol)
                return True
            buddy_iter = self.buddy_store.iter_next(buddy_iter)
        
        buddy_iter = self.add_buddy(self, "", key_hash)
        buddy = self.buddy_store[buddy_iter][0]
        
        buddy.set_connection(connection.protocol)
        
        return True
    
    def connect_to_buddy(self, buddy):
        print "find key by hash", buddy.key_hash
        def defer_handler(result):
            if len(result) == 0:
                print "find error"
                return
            st_data = result.pop()['value']
            print st_data
            ###################################################################
            addr = st_data['addr']
            port = st_data['port']  
            peer_pub_key = RSA.importKey(base64.decodestring(st_data['pub_key']))  
             
            cli_proto = MessengerProtocol(buddy)
            sec_proto = SecureConnection(cli_proto)
            sec_proto.initActive(self.prv_key, peer_pub_key)
            self.connection.connect(addr, port, sec_proto)            
            return
        def defer_err(f):
            print "cannot connect"
            return f
        df = self.dht.findValue(buddy.key_hash)
        df.addCallbacks(defer_handler, defer_err)
        return

    
    def add_buddy(self, name, key_hash):
        buddy = Buddy(self)
        buddy.name = name
        buddy.key_hash = key_hash
        
        iter = self.buddy_store.append([buddy])
        self.save_to_file()
        return iter
    
    def remove_buddy(self, iter):
        result = self.buddy_store.remove(iter)
        self.save_to_file()
        return result
    
    def get_key_hash(self):
        return compute_prv_hash(self.prv_key)
        
    def to_primitive(self):
        profile = dict()
        
        profile['username'] = self.username
        profile['prv_key'] = self.prv_key.exportKey(format='PEM')
        
        buddy_list = list()
        buddy_iter = self.buddy_store.get_iter_first()
        while buddy_iter != None:
            buddy = self.buddy_store[buddy_iter][0]
            buddy_list.append(buddy.to_primitive())
            buddy_iter = self.buddy_store.iter_next(buddy_iter)
        
        profile['buddy_list'] = buddy_list
        
        return profile
    
    @classmethod
    def from_primitive(cls, prim, port=8899, known_nodes=list()):
        profile = cls(port, known_nodes)
        
        profile.username = prim['username']
        profile.prv_key = RSA.importKey(prim['prv_key'])
        
        for buddy_prim in prim['buddy_list']:
            profile.buddy_store.append([Buddy.from_primitive(buddy_prim, profile)])
        
        return profile
    
    def save_to_file(self):
        str_profile = json.dumps(self.to_primitive())
        print str_profile
        with open(self.path, 'w') as file:
            if not self.password:
                file.write(str_profile)
            else:
                ProfileEncrypter.encrypt(str_profile, file, self.password)
    
    
    @classmethod
    def load_from_file(cls, path, password="", port=8899, known_nodes=list()):
        with open(path, 'r') as file:
            if not password:
                str_profile = file.read()
            else:
                str_profile = ProfileEncrypter.decrypt(file, password)
        
        print str_profile
        prof_prim = json.loads(str_profile.strip())
        
        profile = cls.from_primitive(prof_prim, port, known_nodes)
        profile.path = path
        profile.password = password
        
        return profile
        


if __name__ == '__main__':
    
    test_str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Pellentesque congue non metus at tincidunt. Mauris a ligula non urna viverra accumsan. Cras quis lorem nibh. Sed vehicula consectetur elementum. Donec vulputate, sapien sit amet convallis blandit, nunc magna malesuada nibh, vitae faucibus nisi tellus vitae massa. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Ut nisi nisl, molestie et sem a, egestas semper ligula. Vivamus malesuada ut eros id. "
    
    f = open('test.enc', 'w')
    
    ProfileEncrypter.encrypt(test_str, f, "ololoshka")
    
    f.close()
    
    f = open('test.enc', 'r')
    
    print ProfileEncrypter.decrypt( f, "ololoshka")
    
    f.close()
    
    
