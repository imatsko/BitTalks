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
__date__ ="$29.03.2014 21:33:23$"

import logging
module_logger = logging.getLogger("secure_connection")
module_logger.setLevel(logging.DEBUG)

import struct

from twisted.internet.protocol import Protocol, Factory
from connected_udp import ConnectedUDPProtocol

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS

from Crypto.Cipher import AES
from Crypto import Random

from Crypto.Hash import SHA

class InvalidProtocolMagic(Exception):
    pass

class DecryptionError(Exception):
    pass

def xorstr(s1, s2):
    def xorchars(c1, c2):
        if c1 is None:
            c1 = "\x00"
        if c2 is None:
            c2 = "\x00"
        return chr(ord(c1) ^ ord(c2)) 
    
    return "".join(map(xorchars, s1, s2))

BLOCK_SIZE = AES.block_size
BLOCK_INIT_KEY_SIZE = 32
BLOCK_KEY_SIZE = 32
SECRET_SIZE = BLOCK_KEY_SIZE
ASYMM_ENC_SIZE = 256

class BasePackage(object):
    INIT_PKG = 1
    PEER_INFO_PKG = 2
    FIN_HELLO_PKG = 3
    VERIFY_PKG = 4
    
    DATA_PKG = 5
    
    PROTOCOL_MAGIC = 0xDEADBEEF

    __fmt = "!IB"
    __fmt_size = struct.calcsize(__fmt)
    
    def __init__(self, pkg_type, data):
        self.pkg_type = pkg_type
        self.data = data
    
    @classmethod
    def pack(cls, pkg_type, data):
        head = struct.pack(cls.__fmt, cls.PROTOCOL_MAGIC, pkg_type)
        return head + data
    
    @classmethod
    def unpack(cls, raw_pkg):
        (magic, pkg_type,) = struct.unpack(cls.__fmt, raw_pkg[:cls.__fmt_size])
        if magic != cls.PROTOCOL_MAGIC:
            raise InvalidProtocolMagic()
        body = raw_pkg[cls.__fmt_size:]
        pkg = BasePackage(pkg_type, body)
        return pkg

class InitKeyPackage(object):
    DECRYPT_MAGIC = 123
    __fmt = "!B"
    __fmt_size = struct.calcsize(__fmt)
    
    @classmethod
    def pack(cls, init_key, enc_cipher):
        head = struct.pack(cls.__fmt, cls.DECRYPT_MAGIC)
        content = head + init_key
        return enc_cipher.encrypt(content) 
    
    @classmethod
    def unpackUnknown(cls, raw_pkg, dec_ciphers):        
        for c in dec_ciphers:
            try:
                dec = c.decrypt(raw_pkg)
                (magic,) = struct.unpack(cls.__fmt, dec[:cls.__fmt_size])
                body = dec[cls.__fmt_size:]
                if magic == cls.DECRYPT_MAGIC:
                    return (body, c)
            except ValueError:
                pass
        raise DecryptionError()
    
    @classmethod
    def unpack(cls, raw_pkg, dec_cipher):        
        dec = dec_cipher.decrypt(raw_pkg)
        (magic,) = struct.unpack(cls.__fmt, dec[:cls.__fmt_size])
        body = dec[cls.__fmt_size:]
        if magic == cls.DECRYPT_MAGIC:
            return body
        raise DecryptionError()
    
    
class BlockEncryptedPackage(object):
    __fmt = "!B"
    __fmt_size = struct.calcsize(__fmt)
    
    @classmethod
    def pack(cls, block_size, block_cipher, data):
        padding_len = (block_size - (len(data)+cls.__fmt_size)%block_size) % block_size
        padding = ""
        if padding_len:
            padding = Random.new().read(padding_len)
        head = struct.pack(cls.__fmt, padding_len)
        with_padding = head + padding + data
        return block_cipher.encrypt(with_padding)
    
    @classmethod
    def unpack(cls, block_cipher, raw_pkg):
        decrypted = block_cipher.decrypt(raw_pkg)
        head, body = decrypted[:cls.__fmt_size], decrypted[cls.__fmt_size:]
        (padding_len,) = struct.unpack(cls.__fmt, head)
        result = body[padding_len:]
        return result
    

class PeerInfoPackage(object):
    __init_vect_size = BLOCK_SIZE
    __secret_size = SECRET_SIZE
    
    __fmt = "{}s{}s".format(__init_vect_size, __secret_size)
    __fmt_size = struct.calcsize(__fmt)
    def __init__(self, init_vect, pub_key_der, secret):
        self.init_vect = init_vect
        self.pub_key_der = pub_key_der
        self.secret = secret
    
    @classmethod
    def pack(cls, init_vect, pub_key_der, secret):
        head = struct.pack(cls.__fmt, init_vect, secret)
        return head + pub_key_der
    
    @classmethod
    def unpack(cls, raw_pkg):
        head, body = raw_pkg[:cls.__fmt_size], raw_pkg[cls.__fmt_size:]
        (init_vect, secret) = struct.unpack(cls.__fmt, head)
        result = PeerInfoPackage(init_vect, body, secret)
        return result
    
class VerifyPackage(object):
    def __init__(self, sign):
        self.sign = sign
    
    @classmethod
    def pack(cls, sign):
        return sign
    
    @classmethod
    def unpack(cls, raw_pkg):
        result = VerifyPackage(raw_pkg)
        return result
    
        
class PeerChecker(object):
    def checkPeer(self, addr, port, peer_pub_key, self_pub_key, connection):
        return True
        pass
  

class SecureConnection(Protocol):
    
    CLOSED = 0
    WAIT_INIT = 1
    WAIT_PEER_INFO = 2
    WAIT_VERIFY = 3
    WAIT_FIN_HELLO = 4
    ESTABLISHED = 5
            
    def __init__(self, protocol):
        self.active = None
        self.protocol = protocol
        self.random = Random.new()
        self.state = self.CLOSED
        self.active_connection = False
        self.available_self_priv_keys = None
        self.self_peer_checker = None
        
        self.self_prv_key = None
        self.peer_pub_key = None
        
        self.self_asym_decrypter = None
        self.peer_asym_encrypter = None
        
        self.self_signer = None
        self.peer_verifier = None
        
        self.self_init_key = self.random.read(BLOCK_KEY_SIZE)
        self.peer_init_key = None
        
        self.self_init_cipher = AES.new(self.self_init_key, AES.MODE_CFB, "\x00"*BLOCK_SIZE)
        self.peer_init_cipher = None
        
        self.self_secret = self.random.read(SECRET_SIZE)
        self.peer_secret = None
        
        self.self_init_vect_half = self.random.read(BLOCK_SIZE)
        self.peer_init_vect_half = None
        self.shared_key = None
        self.shared_init_vect = None
        self.shared_cipher = None
    
#   Public interface
    def initPassive(self, available_priv_keys, peer_checker):
        self.active = False
        self.available_self_priv_keys = available_priv_keys
        self.self_peer_checker = peer_checker
        return self
    
    def initActive(self, self_prv_key, peer_pub_key):
        self.active = True
        
        self.self_prv_key = self_prv_key
        self.peer_pub_key = peer_pub_key
        
        self.self_asym_decrypter = PKCS1_OAEP.new(self.self_prv_key)
        self.peer_asym_encrypter = PKCS1_OAEP.new(self.peer_pub_key)
        
        self.self_signer = PKCS1_PSS.new(self.self_prv_key)
        self.peer_verifier = PKCS1_PSS.new(self.peer_pub_key)             
        return self
        
#   Transport interface
    def getPeer(self):
        (addr, port, channel) = self.transport.getPeer()
        peer_pub_key_der = "" if self.peer_pub_key is None else self.peer_pub_key.exportKey(format="DER")
        return (addr, port, channel, peer_pub_key_der)
    
    def getHost(self):
        (addr, port, channel) = self.transport.getHost()
        self_pub_key_der = "" if self.self_prv_key is None else self.self_prv_key.publickey().exportKey(format="DER")
        return (addr, port, channel, self_pub_key_der)
    
    def loseConnection(self):
        self.state = self.CLOSED
        self.transport.loseConnection()
        return
    
    def write(self, user_data):
        if self.state != self.ESTABLISHED:
            return
        enc = self._codeData(user_data)
        pkg = BasePackage.pack(BasePackage.DATA_PKG, enc)
        #return deferred
        return self.transport.write(pkg)
    
    def writeSequence(self, data):
        df = None
        for d in data:
            df = self.write(d)
        return df

#   Protocol interface
    def connectionMade(self):
                        
        module_logger.debug("{} connection made active:{}".format(
                self._dbg_id(),
                self.active
            ))

        if self.active is None:
            raise Exception("Not initialised secure protocol")
        elif self.active:
            self._sendInit()
            self._sendPeerInfo()
            
            module_logger.debug("{} active sending PEER_INFO".format(
                self._dbg_id()
                ))
                
            self.state = self.WAIT_INIT
        else:
            self.state = self.WAIT_INIT

    def connectionLost(self):
        proto = self.protocol
        proto.connectionLost()        
        del self.protocol
        del self.transport
        return
        
    def dataReceived(self, data):
        
        module_logger.debug("{} recv data:{}".format(
                self._dbg_id(),
                repr(data)
            ))

        try:
            base_pkg = BasePackage.unpack(data)
        except InvalidProtocolMagic:
            return
        
        if self.state == self.ESTABLISHED:
            if base_pkg.pkg_type == BasePackage.DATA_PKG:
                user_data = self._decodeData(base_pkg.data)
                self.protocol.dataReceived(user_data)
        elif self.active:
            self._procActiveStates(base_pkg)
        else:
            self._procPassiveStates(base_pkg)
        return
        
#   Internals
    def _procActiveStates(self, base_pkg):
        if self.state == self.WAIT_INIT:
            
            module_logger.debug("{} active waiting INIT".format(
                self._dbg_id()
                ))

            if base_pkg.pkg_type == BasePackage.INIT_PKG:
                try:
                    self._recvInit(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self.state = self.WAIT_PEER_INFO
        elif self.state == self.WAIT_PEER_INFO:
                        
            module_logger.debug("{} active waiting PEER_INFO".format(
                self._dbg_id()
                ))

            if base_pkg.pkg_type == BasePackage.PEER_INFO_PKG:
                try:
                    self._recvPeerInfo(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self.shared_key = xorstr(self.self_secret, self.peer_secret)
                self.shared_init_vect = xorstr(self.self_init_vect_half, self.peer_init_vect_half)
                self.shared_cipher = AES.new(self.shared_key,
                    AES.MODE_CFB,
                    self.shared_init_vect)

                self._sendVerify()
                            
                module_logger.debug("{} active sending FIN_HELLO".format(
                    self._dbg_id()
                    ))

                self.state = self.WAIT_VERIFY
        elif self.state == self.WAIT_VERIFY:
            if base_pkg.pkg_type == BasePackage.VERIFY_PKG:
                try:
                    self._recvVerify(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self._sendFinHello()
                self.state = self.WAIT_FIN_HELLO
        elif self.state == self.WAIT_FIN_HELLO:
                        
            module_logger.debug("{} active waiting FIN_HELLO".format(
                self._dbg_id()
                ))

            if base_pkg.pkg_type == BasePackage.FIN_HELLO_PKG:
                try:
                    self._recvFinHello(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self._establish()
        return
    def _procPassiveStates(self, base_pkg):
        if self.state == self.WAIT_INIT:
                        
            module_logger.debug("{} passive waiting INIT".format(
                self._dbg_id()
                ))

            if base_pkg.pkg_type == BasePackage.INIT_PKG:
                try:
                    self._recvUnknownKeyInit(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self.state = self.WAIT_PEER_INFO
        elif self.state == self.WAIT_PEER_INFO:
                        
            module_logger.debug("{} passive waiting PEER_INFO, pkg: {}".format(
                self._dbg_id(),
                base_pkg.__dict__
                ))

            if base_pkg.pkg_type == BasePackage.PEER_INFO_PKG:
                                        
                module_logger.debug("{} passive getting PEER_INFO, pkg: {}".format(
                    self._dbg_id(),
                    repr(base_pkg.data)
                    ))
                    
                try:
                    self._recvPeerInfo(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self.shared_key = xorstr(self.self_secret, self.peer_secret)
                self.shared_init_vect = xorstr(self.self_init_vect_half, self.peer_init_vect_half)
                self.shared_cipher = AES.new(self.shared_key,
                    AES.MODE_CFB,
                    self.shared_init_vect)

                (peer_addr,
                    peer_port,
                    peer_channel,
                    peer_pub_key) = self.getPeer()
                self_pub_key = self.self_prv_key.publickey().exportKey(format="DER")
                if not self.self_peer_checker.checkPeer(peer_addr,
                                                        peer_port,
                                                        peer_pub_key, 
                                                        self_pub_key,
                                                        self):
                    self.loseConnection()
                    return
                self._sendInit()
                self._sendPeerInfo()
                self.state = self.WAIT_VERIFY
        elif self.state == self.WAIT_VERIFY:
            if base_pkg.pkg_type == BasePackage.VERIFY_PKG:
                try:
                    self._recvVerify(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self._sendVerify()
                self.state = self.WAIT_FIN_HELLO
        elif self.state == self.WAIT_FIN_HELLO:
            module_logger.debug("{} passive wait FIN_HELLO".format(
                self._dbg_id()
            ))

            if base_pkg.pkg_type == BasePackage.FIN_HELLO_PKG:
                try:
                    self._recvFinHello(base_pkg.data)
                except DecryptionError:
                    self.loseConnection()
                    return
                self._sendFinHello()
                self._establish()
        return

    def _sendInit(self):
#        used in both
        module_logger.debug("{} send init self_init_key: {}".format(
                self._dbg_id(),
                repr(self.self_init_key),
            ))
            
        data = InitKeyPackage.pack(self.self_init_key, self.peer_asym_encrypter)
        package = BasePackage.pack(BasePackage.INIT_PKG, data)
        self.transport.write(package)
        return
    
    def _sendPeerInfo(self):
    #        used in active
        self_pub = self.self_prv_key.publickey()
        self_pub_der = self_pub.exportKey(format="DER")

        body = PeerInfoPackage.pack(self.self_init_vect_half, self_pub_der, self.self_secret)
        encrypted = BlockEncryptedPackage.pack(BLOCK_SIZE, self.self_init_cipher, body)
        package = BasePackage.pack(BasePackage.PEER_INFO_PKG, encrypted)
        self.transport.write(package)
        return
    
    def _recvInit(self, pkg_data):
#        used in active
        self.peer_init_key = InitKeyPackage.unpack(pkg_data, self.self_asym_decrypter)
        self.peer_init_cipher = AES.new(self.peer_init_key, AES.MODE_CFB, "\x00"*BLOCK_SIZE)
    
    def _recvUnknownKeyInit(self, pkg_data):
#        used in passive
        ciphers = [PKCS1_OAEP.new(key) for key in self.available_self_priv_keys]
        try:
            (self.peer_init_key, c) = InitKeyPackage.unpackUnknown(pkg_data, ciphers)
        except DecryptionError as e:
            raise e
        c_ind = ciphers.index(c)
        self.self_prv_key = self.available_self_priv_keys[c_ind]
        self.self_asym_decrypter = c
        self.self_signer = PKCS1_PSS.new(self.self_prv_key)
        self.peer_init_cipher = AES.new(self.peer_init_key, AES.MODE_CFB, "\x00"*BLOCK_SIZE)
        return

        
    def _recvPeerInfo(self, pkg_data):
#        used in passive
        body = BlockEncryptedPackage.unpack(self.peer_init_cipher, pkg_data)
        pkg = PeerInfoPackage.unpack(body)

        self.peer_pub_key = RSA.importKey(pkg.pub_key_der)
        self.peer_asym_encrypter = PKCS1_OAEP.new(self.peer_pub_key)
        self.peer_verifier = PKCS1_PSS.new(self.peer_pub_key)
        
        self.peer_init_vect_half = pkg.init_vect
        self.peer_secret = pkg.secret
        return
    
    def _sendFinHello(self):
        encrypted = BlockEncryptedPackage.pack(BLOCK_SIZE, self.self_init_cipher, self.self_init_key)
        package = BasePackage.pack(BasePackage.FIN_HELLO_PKG, encrypted)
        self.transport.write(package)
        return
    
    def _recvFinHello(self, pkg_data):
        pkg_init_key = BlockEncryptedPackage.unpack(self.peer_init_cipher, pkg_data)
        if pkg_init_key != self.peer_init_key:
            raise DecryptionError()
        return
    
    def _sendVerify(self):        
        self_pub = self.self_prv_key.publickey()
        self_pub_der = self_pub.exportKey(format="DER")
        peer_pub_der = self.peer_pub_key.exportKey(format="DER")
        
        sign_hash = SHA.new()
        sign_hash.update(self_pub_der)
        sign_hash.update(peer_pub_der)
        sign_hash.update(self.shared_key)
        
        sign = self.self_signer.sign(sign_hash)
        encrypted = BlockEncryptedPackage.pack(BLOCK_SIZE, self.self_init_cipher, sign)
        package = BasePackage.pack(BasePackage.VERIFY_PKG, encrypted)
        self.transport.write(package)
        return
    
    def _recvVerify(self, pkg_data):
        dec_sign = BlockEncryptedPackage.unpack(self.peer_init_cipher, pkg_data)
        
        self_pub = self.self_prv_key.publickey()
        self_pub_der = self_pub.exportKey(format="DER")
        peer_pub_der = self.peer_pub_key.exportKey(format="DER")
        
        sign_hash = SHA.new()
        sign_hash.update(peer_pub_der)
        sign_hash.update(self_pub_der)
        sign_hash.update(self.shared_key)
        
        if not self.peer_verifier.verify(sign_hash, dec_sign):
            raise DecryptionError()
        return
    
    
    def _codeData(self, user_data):
#        used in both
        block_enc = BlockEncryptedPackage.pack(BLOCK_SIZE, self.shared_cipher, user_data)
        return block_enc
    
    def _decodeData(self, body):
#        used in both
        user_data = BlockEncryptedPackage.unpack(self.shared_cipher, body)
        return user_data
    
    def _establish(self):
#        used in both
        module_logger.debug("{} connection established".format(
                self._dbg_id()
            ))
            
        self.state = self.ESTABLISHED
        self.protocol.makeConnection(self)
    
    def _dbg_id(self):
        dbg_host = self.getHost()
        host_pub_hash = SHA.new()
        host_pub_hash.update(dbg_host[3])
        host_pub_hash_hex = host_pub_hash.hexdigest()
        
        dbg_peer = self.getPeer()
        peer_pub_hash = SHA.new()
        peer_pub_hash.update(dbg_peer[3])
        peer_pub_hash_hex = peer_pub_hash.hexdigest()
        
        
        return "sec_connection id:{}, self_addr:{}, self_port:{}, self_pub_hash:{} , peer_addr:{} , peer_port:{} , peer_pub_hash: {}".format(
                id(self),
                dbg_host[0],dbg_host[1],host_pub_hash_hex,
                dbg_peer[0],dbg_peer[1],peer_pub_hash_hex
            )
       
class ProtocolTransportAdapter(Protocol):
    def __init__(self, protocol):
        self.protocol = protocol

#   Protocol interface
    def connectionMade(self):
        self.protocol.makeConnection(self)
        return

    def connectionLost(self):
        self.protocol.connectionLost()
        return
        
    def dataReceived(self, data):
        self.protocol.dataReceived(data)
        return

# Transport interface
    def loseConnection(self):
        self.transport.loseConnection()
        return
    
    def write(self, data):
        return self.transport.write(data)
    
    def writeSequence(self, data):
        df = None
        for d in data:
            df = self.write(d)
        return df
    
    def getPeer(self):
        return self.transport.getPeer()
    
    def getHost(self):
        return self.transport.getHost()

class ActiveSecureConnection(ProtocolTransportAdapter):
    SECURE_CONNECTION_START_MAGIC = "START_SECURE_CONNECTION"
    def __init__(self, cli_proto, self_prv_key, peer_pub_key):
        proto = SecureConnection(cli_proto)
        proto.initActive(self_prv_key, peer_pub_key)
        ProtocolTransportAdapter.__init__(self, proto)

#   Protocol interface
#    def connectionMade(self):
#        self.transport.write(self.SECURE_CONNECTION_START_MAGIC)
#        ProtocolTransportAdapter.connectionMade(self)
#        return

class PassiveSecureConnection(ProtocolTransportAdapter):
    def __init__(self, cli_proto, available_priv_keys, peer_checker):
        sec_proto = SecureConnection(cli_proto)
        sec_proto.initPassive(available_priv_keys, peer_checker)
        ProtocolTransportAdapter.__init__(self, sec_proto)
    
        
class PassiveCombinedConnection(ProtocolTransportAdapter):
    def __init__(self, address, secure_factory, common_factory):
        self.address = address
        self.secure_factory = secure_factory
        self.common_factory = common_factory
        ProtocolTransportAdapter.__init__(self, None)

#   Protocol interface
    def connectionMade(self):
        return

    def connectionLost(self):
        if not self.protocol is None:
            ProtocolTransportAdapter.connectionLost(self)
        return
        
    def dataReceived(self, data):
        if self.protocol is None:
            if data == ActiveSecureConnection.SECURE_CONNECTION_START_MAGIC:
                self.protocol = self.secure_factory.buildProtocol(self.address)
                if self.protocol is None:
                    self.loseConnection()
                    return
                ProtocolTransportAdapter.connectionMade(self)
            else:
                self.protocol = self.common_factory.buildProtocol(self.address)
                if self.protocol is None:
                    self.loseConnection()
                    return
                ProtocolTransportAdapter.connectionMade(self)
                ProtocolTransportAdapter.dataReceived(self, data)
        else:
            ProtocolTransportAdapter.dataReceived(self, data)
        return
    

class CombinedFactory(Factory):
    def __init__(self, secure_factory, common_factory):
        self.secure_factory = secure_factory
        self.common_factory = common_factory
        pass
            
    def buildProtocol(self, address):
        return PassiveCombinedConnection(address, self.secure_factory, self.common_factory)


#==================TESTS=====================
def init_keys():
    key_one = RSA.generate(2048)
    key_two = RSA.generate(2048)
    key_three = RSA.generate(2048)
    with open('key_one.der','w') as key_one_file:
        key_one_file.write(key_one.exportKey(format="DER"))
    with open('key_two.der','w') as key_two_file:
        key_two_file.write(key_two.exportKey(format="DER"))
    with open('key_three.der','w') as key_three_file:
        key_three_file.write(key_three.exportKey(format="DER"))
    return (key_one, key_two, key_three)

def load_keys():
    with open('key_one.der') as key_one_file:
        key_one_der = key_one_file.read()
        print "load key one: ", repr(key_one_der)
        key_one = RSA.importKey(key_one_der)
    with open('key_two.der') as key_two_file:
        key_two_der = key_two_file.read()
        print "load key two: ", repr(key_two_der)
        key_two = RSA.importKey(key_two_der)
    with open('key_three.der') as key_three_file:
        key_three_der = key_three_file.read()
        print "load key three: ", repr(key_three_der)
        key_three = RSA.importKey(key_three_der)
    return (key_one, key_two, key_three)


class TestBaseProtocol(Protocol):
    title = "default title"

#    def __init__(self, title="default title"):
#        self.title = title

    def connectionMade(self):
        print "{} {}: connection made".format(self.title, id(self))

    def dataReceived(self, data):
        print "{} {}: receives '{}'".format(self.title, id(self), repr(data))

    def connectionLost(self):
        print "{} {}: connection lost".format(self.title, id(self))

    def write_data(self, data):
        print "{} {}: sends '{}'".format(self.title, id(self), repr(data))
        self.transport.write("echo: "+data)
    

class TestEchoProtocol(TestBaseProtocol):
    def dataReceived(self, data):
        print "{} {}: receives '{}' and echoes".format(self.title, id(self), repr(data))
        self.write_data(data)

class TestPeerChecker(PeerChecker):
    def checkPeer(self, addr, port, peer_pub_key, self_pub_key, connection):
        peer_pub_key_hash = SHA.new()
        peer_pub_key_hash.update(peer_pub_key)
        self_pub_key_hash = SHA.new()
        self_pub_key_hash.update(self_pub_key)

        print "Checking: addr:{}, port:{}, peer_pub_key_hash:{}, self_pub_key_hash:{}".format(
            addr, port, peer_pub_key_hash.hexdigest(), self_pub_key_hash.hexdigest())
        return True

def test_sec_connection():
    class PassiveSecureConnectionFactory(Factory):
        def __init__(self, protocol, available_priv_keys, peer_checker):
            self.available_priv_keys = available_priv_keys
            self.peer_checker = peer_checker
            self.protocol = protocol
            
        def buildProtocol(self, address):
            cli_proto = self.protocol()
            return PassiveSecureConnection(cli_proto, self.available_priv_keys, self.peer_checker)
    
    def sec_connect(conn_proto, addr, port, cli_proto, self_prv_key, peer_pub_key):
        conn_proto.connect(addr, port, ActiveSecureConnection(cli_proto, self_prv_key, peer_pub_key))

    from twisted.internet import reactor
    
    cli_prv_key, srv1_prv_key, srv2_prv_key = load_keys()
    cli_pub_key = cli_prv_key.publickey()
    srv1_pub_key = srv1_prv_key.publickey()
    srv2_pub_key = srv2_prv_key.publickey()

    checker = TestPeerChecker()
    
    class SecureEchoServer(TestEchoProtocol):
        title = "secure echo server"
    
    class SecureClient(TestBaseProtocol):
        title = "secure client"
    
    passive_factory = PassiveSecureConnectionFactory(SecureEchoServer, [srv1_prv_key, srv2_prv_key], checker)
    
    conn_proto = ConnectedUDPProtocol(passive_factory, None)
    conn_proto_addr = ("127.0.0.1", 7778)

    p_sec1 = SecureClient()     
    def conn_sec1():
        sec_connect(conn_proto, conn_proto_addr[0], conn_proto_addr[1], p_sec1, cli_prv_key, srv1_pub_key)

    def send_sec11():
        p_sec1.write_data("sent sec1 data")
        
    def send_sec12():
        p_sec1.write_data("sent more sec1 data")
    
    def close_sec1():
        print "close sec1"
        p_sec1.transport.loseConnection()
    
    p_sec2 = SecureClient()    
    def conn_sec2():
        print "conn_sec2 connect"
        sec_connect(conn_proto, conn_proto_addr[0], conn_proto_addr[1], p_sec2, cli_prv_key, srv2_pub_key)
    
    def send_sec21():
        p_sec2.write_data("sent sec2 data")
        
    def send_sec22():
        p_sec2.write_data("sent more sec2 data")
    
    def close_sec2():
        print "close sec2"
        p_sec2.transport.loseConnection()
        
    def stop():
        reactor.stop()

    reactor.listenUDP(conn_proto_addr[1], conn_proto)
    
    reactor.callLater(5, conn_sec1)
    reactor.callLater(6, send_sec11)
    reactor.callLater(7, send_sec12)
    reactor.callLater(8, close_sec1)
    
    reactor.callLater(20, conn_sec2)
    reactor.callLater(22, send_sec21)
    reactor.callLater(23, send_sec22)
    reactor.callLater(24, close_sec2)
    
    reactor.callLater(30, stop)
    
    print "prepared for run"
    reactor.run()
    print "stopped"
    return


if __name__ == "__main__":
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    module_logger.addHandler(console)
        
    test_sec_connection()


