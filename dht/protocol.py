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
__date__ ="$15.03.2014 19:42:18$"



from jsonrpc.jsonrpc import JSONRPCMessageFactory, JSONRPCProtocol
from jsonrpc.rpc import RPCHandler, RPCTimeout
from routing import RoutingTable
from contact import Contact, Key
import random
import time
import hashlib
import twisted.internet.reactor as reactor
from twisted.internet.task import LoopingCall
from twisted.internet.defer import Deferred

import base64


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Hash import SHA

class DHTMessageFactory(JSONRPCMessageFactory):
    
    def __init__(self, node_id = None):
        if node_id is None:
            self.node_id = node_id
        else:
            self.node_id = Key(node_id)

    
    def _from_primitive(self, msg_prim):
        msg = JSONRPCMessageFactory._from_primitive(self, msg_prim)
        if 'node_id' in msg_prim:
            if not msg_prim['node_id'] is None:
                node_id = Key(msg_prim['node_id'])
            else:
                node_id = None
        else:
            node_id = None
        msg.node_id = node_id
        return msg
    
    def _to_primitive(self, msg):
        msg_prim = JSONRPCMessageFactory._to_primitive(self, msg)
        if self.node_id is None:
            msg_prim['node_id'] = self.node_id
        else:
            msg_prim['node_id'] = self.node_id.toString()

        return msg_prim


class DHTProtocol(JSONRPCProtocol):
    def __init__(self, rpc_handler, node_id):
        JSONRPCProtocol.__init__(self, rpc_handler)
        self.msg_factory = DHTMessageFactory(node_id)



class DHTNode(RPCHandler):
    heartbeat_interval = 20
    keepalive_timeout = 45
    rpc_prefix = 'rpc_'
    def __init__(self, rpc_protocol=None, routing_table=None, data_storage=None):
        self.node_id = Key.generateID()
        
        if data_storage is None:
            self.data_storage = dict()
        else:
            self.data_storage = data_storage
    
        if rpc_protocol is None:
            self.protocol = DHTProtocol(self, self.node_id)
        else:
            self.protocol = rpc_protocol
        
        if routing_table is None:
            self.routing_table = RoutingTable(self.node_id)
        else:
            self.routing_table = routing_table
        
        self.heartbeat_loop = LoopingCall(self._heartbeatLoop)

    def addContact(self, contact):
        contact.touch()
        self.routing_table.addContact(contact)
        
    def removeContact(self, contact_id):
        self.routing_table.removeContact(contact_id)
    
    def findCloseNodes(self, node_id, size):
        return self.routing_table.findCloseNodes(node_id, size)
    
    def joinNetwork(self, known_nodes=None):
        join_defer = Deferred()
        if known_nodes is None:
            join_defer.errback(Exception("empty list"))
            return join_defer
        known_nodes = known_nodes[:]
        for (address, port) in known_nodes[:]:
            def add_node(node_id):
#               Add node to routing table
                new_contact = Contact(node_id, address, port)
                new_contact.touch()
                self.addContact(new_contact)
                return
            
            def rm_addr(arg):
#               Remove addr from list after processing
                known_nodes.remove((address, port))
#               Run second stage after all address get processed
                if len(known_nodes) == 0:
                    find_self_key()
                return arg
            
            df = self.callGetID(Contact(None, address, port))
            df.addCallback(add_node)
            df.addBoth(rm_addr)
            
            
        def find_self_key():
            if len(self.routing_table) == 0:
                join_defer.errback(Exception("empty routing table"))
            else:
                def return_join(arg):
                    print "find to join"
                    join_defer.callback(None)
                    return
                df = self.findNodes(self.node_id)
                df.addBoth(return_join)
            return
        join_defer.addBoth(self._start_loops)
        return join_defer
    
    def _find(self, key):
        key = Key(key)
        parallel_limit = 3
        find_defer = Deferred()
        init_list = self.findCloseNodes(self.node_id, 8)
        if len(init_list) == 0:
            find_defer.callback(list())
            return find_defer
        
        contacts = dict()
        in_progress = list()
        with_errors = dict()
        
        def get_next_contact():
            """
            Find next contact for processing. 
            """
            k_sorted = sorted(contacts.keys(), key=lambda id: key.distance(id))
            for k in k_sorted:
                if contacts[k]['processed'] == False and not k in in_progress:
                    return contacts[k]['contact']
            return 
        
        def check_stop_condition(chk_range=8):
            """
            If first chk_range elements are processed returns True.
            """
            k_sorted = sorted(contacts.keys(), key=lambda id: key.distance(id))
            k_sorted = k_sorted[:chk_range]
            for k in k_sorted:
                if contacts[k]['processed'] == False:
                    return False
            return True
        
        def make_result():
            """
            Make list of contacts from head of 'contacts'
            """
            expr = (c['contact'] for _, c in sorted(contacts.items(), key=lambda (id, c): key.distance(id))[:8])
            return list(expr)
            
        
        def start_process(node_id):
            """
            Start processing of node with given 'node_id'
            """
            in_progress.append(node_id)
            c = contacts[node_id]['contact']
            
            def stop_process(c_list):
                in_progress.remove(node_id)
                contacts[node_id]['processed'] = True                
                process_new_contacts(c_list)
#                return c_list
                return
            
            def err_process(err):
                in_progress.remove(node_id)
                del contacts[node_id]
                with_errors[node_id] = c
                process_new_contacts()
#                return err
                return
            
            df = self.callFindNode(c, key.toString())
            df.addCallbacks(stop_process, err_process)
            return

        def process_new_contacts(c_list=[]):
#           Add new contacts from given list to 'contacts'
            for c in c_list:
                if c.node_id.toString() in with_errors or c.node_id == self.node_id:
                    continue
                self.addContact(c)
                if not c.node_id.toString() in contacts:
                    contacts[c.node_id.toString()] = {'contact':c, 'processed':False}
            
            if check_stop_condition(8):
                find_defer.callback(make_result())
            else:
                if len(in_progress) <= parallel_limit:
                    n_contact = get_next_contact()
                    if n_contact is None:
                        return
                    start_process(n_contact.node_id.toString())
            return
        
        process_new_contacts(init_list)
        return find_defer
    
    def storeValue(self, key, value):
        store_defer = Deferred()
        node_df = self.findNodes(key)
        def node_callback(l):
            if len(l) == 0:
                store_defer.callback(None)
            for cnt in l[:]:
                def bothback_store(arg, c = cnt):
                    l.remove(c)
                    if len(l) == 0:
                        store_defer.callback(None)
                    return arg
                
                store_df = self.callStore(cnt, key, value)
                store_df.addBoth(bothback_store)
        
        node_df.addCallback(node_callback)
        return store_defer
    
    def findNodes(self, key):
        def err_back(f):
            f.printDetailedTraceback()
            return list()
        df = self._find(key)
        df.addErrback(err_back)
        return df

    
    def findValue(self, key):
        find_defer = Deferred()
        node_df = self.findNodes(key)
        def callback_nodes(l):
            result = list()
            if len(l) == 0:
                find_defer.callback(result)
                
            for cnt in l:
                def callback_val(val, c=cnt):
                    if not val is None:
                        val['contact_id'] = c.node_id.toString()
                        val['contact_addr'] = c.address
                        val['contact_port'] = c.port
                        result.append(val)
                    return
                
                def bothback_val(arg, c=cnt):
                    l.remove(c)
                    if len(l) == 0:
                        find_defer.callback(result)
                    return arg
                
                val_df = self.callGetValue(cnt, key)
                val_df.addCallback(callback_val)
                val_df.addBoth(bothback_val)
            return

        def lookup_in_storage(l):
            if key in self.data_storage:
                l.append({'key':key, 'value': self._getFromStorage(key), 'contact_id': self.node_id.toString(), 'contact_addr':"", 'contact_port':0})
            return l
        node_df.addCallback(callback_nodes)
        find_defer.addCallback(lookup_in_storage)
        return find_defer
        
        
    def handleCall(self, msg, address):
        df = Deferred()
        try:
            c = Contact(msg.node_id, address[0], address[1])
            self.addContact(c)
            
            m = getattr(self, self.rpc_prefix + msg.method, None)
            if callable(m):
                result = m(*msg.params, **{'contact':c})
                df.callback(result)
            else:
                raise Exception("unknown rpc {}".format(msg.method))
        except Exception as e:
            df.errback(e)
        return df
    
    def callRPC(self, contact, method, params=()):
        contact.touch()
        def callback(arg):
            contact.touch()
            return arg
        def errback(f):
            try:
                f.raiseException()
            except RPCTimeout:
                if not contact.node_id is None:
                    self.removeContact(contact.node_id)
                raise 
        self.addContact(contact)
        df = self.protocol.callRPC((contact.address, contact.port), method, params)
        df.addCallbacks(callback, errback)
        return df
    
    def callPing(self, contact):
        return self.callRPC(contact, 'ping')
    
    def rpc_ping(self, contact):
        return 'pong'

    def callGetID(self, contact):
        return self.callRPC(contact, 'get_id')
    
    def rpc_get_id(self, contact):
        return self.node_id.toString()

    def callStore(self, contact, key, value):
        return self.callRPC(contact, 'store', (key, value))
    
    def rpc_store(self, key, value, contact=None):
        self._putToStorage(key, value)
        return 'OK'

    def callFindNode(self, contact, key):
        def make_contact_list(result):
            l = list()
            for node_id, address, port in result:
                c = Contact(node_id, address, port)
                self.addContact(c)
                l.append(c)
            return l
        
        df = self.callRPC(contact, 'find_node', (key,))
        df.addCallback(make_contact_list)
        return df 

    def rpc_find_node(self, key, contact):
        key = Key(key)
        contacts = self.findCloseNodes(key,8)
        if contact in contacts:
            contacts.remove(contact)
        result = list()
        for c in contacts:
            result.append((c.node_id.toString(), c.address, c.port))
        return result
    
    def callGetValue(self, contact, key):
        return self.callRPC(contact, 'find_value', (key,))
    
    def rpc_find_value(self, key, contact):
        if key in self.data_storage:
            return {'key':key, 'value': self._getFromStorage(key)}
        else:
            return None
    
    def _heartbeatLoop(self):
        to_check = self.routing_table.getAllContacts()
        now = time.time()
        for c in to_check:
            if now-c.last_accessed > self.keepalive_timeout:
                self.callPing(c)
        return

    def _putToStorage(self, key, value):
        now = time.time()
        self.data_storage[key] = {'value':value, 'timestamp':now}
    
    def _getFromStorage(self, key):
        return self.data_storage[key]['value']
        
    def _start_loops(self, arg=None):
        if not self.heartbeat_loop.running:
            self.heartbeat_loop.start(self.heartbeat_interval)
        return arg
    
    def _stop_loops(self, arg=None):
        self.heartbeat_loop.stop()
        return arg

    
class BitTalksDHTNode(DHTNode):
    clean_unapproved_timeout = 30
    clean_unapproved_interval = 60
    republish_interval = 60
    clean_storage_timeout = 100
    clean_storage_interval = 120
    
    def __init__(self, rpc_protocol=None, routing_table=None, data_storage=None):
        DHTNode.__init__(self, rpc_protocol, routing_table, data_storage)
        self.wait_approve = dict()
        self.published = list()
        self.clean_unapproved_loop = LoopingCall(self._cleanUnapprovedLoop)
        self.republish_loop = LoopingCall(self._republishLoop)
        self.clean_storage_loop = LoopingCall(self._cleanStorageLoop)
        
    def publishKey(self, rsa_prv):
        publish_df = Deferred()
        if not rsa_prv in self.published:
                self.published.append(rsa_prv)
                    
        def succ_published(arg):
            if not rsa_prv in self.published:
                self.published.append(rsa_prv)
            return arg
        
        rsa_pub_der = rsa_prv.publickey().exportKey(format='DER')
        rsa_decrypter = PKCS1_OAEP.new(rsa_prv)
        
        hash = hashlib.sha1()
        hash.update(rsa_pub_der)
        hex_hash = hash.hexdigest()
        
        node_df = self.findNodes(hex_hash)
        successfully = list()
        
        def find_nodes(l):
            if len(l) == 0:
                publish_df.errback(Exception("cannot find nodes"))
                return
            for cnt in l[:]:
                def callback_publish(arg):
                    successfully.append(cnt)
                    return arg
                def bothback_publish(arg, c = cnt):
                    l.remove(c)
                    if len(l) == 0:
                        if len(successfully):
                            publish_df.callback(None)
                        else:
                            publish_df.errback(Exception("wasnt pubblished"))
                    return arg
                                
                call_pub_df = self.callPublishKey(cnt, rsa_pub_der, rsa_decrypter)
                call_pub_df.addCallback(callback_publish)
                call_pub_df.addBoth(bothback_publish)
        
        node_df.addCallback(find_nodes)
        publish_df.addCallback(succ_published)
        return publish_df
    
    
    def callApproveKey(self, contact, key_hash, token):
        token = base64.encodestring(token)
        df = self.callRPC(contact, 'approve_key', (key_hash,token))
        return df

    def rpc_approve_key(self, key_hash, token, contact):
        token = base64.decodestring(token)
        if key_hash in self.wait_approve and self.wait_approve[key_hash]['token'] == token:
            data = self.wait_approve[key_hash]
            self._putToStorage(key_hash, { 'pub_key':data['pub_key'], 'addr':data['addr'], 'port': data['port']})
            del self.wait_approve[key_hash]
            return 'PUBLISHED'
        return
    
    def callPublishKey(self, contact, rsa_pub_der, rsa_decrypter):
        main_df = Deferred()
        b64_rsa_pub = base64.encodestring(rsa_pub_der)
        pub_df = self.callRPC(contact, 'publish_key', (b64_rsa_pub,))
        decrypter = rsa_decrypter
        
        def approve(result):
            key_hash = result['key_hash']
            enc_token = base64.decodestring(result['enc_token'])
            token = decrypter.decrypt(enc_token)
            app_df = self.callApproveKey(contact, key_hash, token)
            def approve_confirm(result):
                if result == 'PUBLISHED':
                    main_df.callback(None)
                else:
                    main_df.errback(Exception("Wrong peer approve publish answer"))
                return
            def approve_error(err):
                main_df.errback(err)

            app_df.addCallbacks(approve_confirm, approve_error)
        def publish_error(err):
            main_df.errback(err)
            return err
        
        pub_df.addCallbacks(approve, publish_error)
        
        return main_df        
        
    def rpc_publish_key(self, b64_rsa_pub, contact):
        rsa_pub_der = base64.decodestring(b64_rsa_pub)
        rsa_pub = RSA.importKey(rsa_pub_der)
        encrypter = PKCS1_OAEP.new(rsa_pub)
        hash = hashlib.sha1()
        hash.update(rsa_pub_der)
        hex_hash = hash.hexdigest()
        token = Random.new().read(32)
        self.wait_approve[hex_hash] = {'token':token,
            'timestamp':time.time(),
            'pub_key':base64.encodestring(rsa_pub_der),
            'addr':contact.address,
            'port': contact.port}
        enc_token = encrypter.encrypt(token)
        return {'key_hash':hex_hash, 'enc_token':base64.encodestring(enc_token)}


    def _cleanUnapprovedLoop(self):
        now = time.time()
        for key, val in self.wait_approve.items():
            if now-val['timestamp'] > self.clean_unapprove_timeout:
                del self.wait_approve[key]
        return
    
    def _cleanStorageLoop(self):
        now = time.time()
        for k, s_item in self.data_storage.items():
            if now-s_item['timestamp'] > self.clean_storage_timeout:
                del self.data_storage[k]        
        return
    
    def _republishLoop(self):
        for rsa_prv in self.published:
            self.publishKey(rsa_prv)
        return

    def _start_loops(self, arg=None):
        DHTNode._start_loops(self)
        if not self.clean_unapproved_loop.running:
            self.clean_unapproved_loop.start(self.clean_unapproved_interval)
        
        if not self.republish_loop.running:
            self.republish_loop.start(self.republish_interval)

        if not self.clean_storage_loop.running:
            self.clean_storage_loop.start(self.clean_storage_interval)
        return arg
    
    def _stop_loops(self, arg=None):
        DHTNode._stop_loops(self)
        self.clean_unapproved_loop.stop()
        self.republish_loop.stop()
        self.clean_storage_loop.stop()
        return arg
