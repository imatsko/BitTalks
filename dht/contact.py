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
__date__ ="$15.03.2014 19:29:28$"

import random, time, hashlib


class IDOutOfBoundary(Exception):
    pass

class Key(object):
    """
    Represents keys
    """
    max_id = 2**160 - 1
    min_id = 0
    def __init__(self, val):
        """
        @param val: Value to make Key
        @type val: C{str} or C{unicode} or C{int} or C{long} or C{Key}
        """
        if isinstance(val, str) or isinstance(val, unicode):
            self.id = self._str_to_num(val)
        elif isinstance(val, int) or isinstance(val, long):
            self.id = val
        elif isinstance(val, Key):
            self.id = val.id
        else:
            raise TypeError("Incorrect Key init value type")
        
        if not self.min_id <= self.id <= self.max_id:
            raise IDOutOfBoundary("Incorrect id value")
    
    def toString(self):
        return self._num_to_str(self.id)
    
    def toNumber(self):
        return self.id
    
    def distance(self, other):
        other = Key(other)
        return self.id ^ other.id

    def __eq__(self, other):
        try:
            other = Key(other)
            return self.id == other.id
        except:
            return False
        
    def __ne__(self, other):
        return not self.__eq__(other)
    
    def __lt__(self, other):
        try:
            other = Key(other)
            return self.id < other.id
        except:
            return False
    
    def __ge__(self, other):
        return not self.__lt__(other)
    
    def __gt__(self, other):
        try:
            other = Key(other)
            return self.id > other.id
        except:
            return False
    
    def __le__(self, other):
        return not self.__gt__(other)
    
    def __repr__(self):
        return self.toString()
    
    def __str__(self):
        return self.__repr__()
    
    def __hash__(self):
        return self.id

    @classmethod
    def _str_to_num(cls, s):
        return long(s, 16)

    @classmethod
    def _num_to_str(cls, num):
        return "{:0>40x}".format(num)
    
    @classmethod
    def generateID(cls):
        hash = hashlib.sha1()
        hash.update(str(random.getrandbits(1024)))
        return Key(hash.hexdigest())
    
class Contact(object):
    
    def __init__(self, node_id, ip_address, udp_port):
        if node_id is None:
            self.node_id = None
        else:
            self.node_id = Key(node_id)
        self.address = ip_address
        self.port = udp_port
        self.last_accessed = 0
    
    def touch(self):
        self.last_accessed = time.time()

    
    def __str__(self):
        return "Contact: #{0} at {1}:{2}".format(self.node_id, self.address, self.port)
    
    def __repr__(self):
        return "<obj_id:{} {}>".format(id(self), self.__str__())
    
    def __eq__(self, other):
        if self.node_id is None:
            return False
        if isinstance(other, Contact):
            if other.node_id is None:
                return False
            return self.node_id == other.node_id
        else:
            return self.node_id == other
    
    def __ne__(self, other):
        if self.node_id is None:
            return False
        if isinstance(other, Contact):
            if other.node_id is None:
                return False
            return self.node_id != other.node_id
        else:
            return self.node_id != other
