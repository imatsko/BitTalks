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
__date__ ="$16.03.2014 7:58:10$"

from contact import Contact
from contact import Key

class BucketFull(Exception):
    pass

class Bucket(object):
    max_size = 20
    def __init__(self):
        self.contacts = list()

    def addContact(self, contact):
        if contact.node_id is None:
            raise ValueError("Cannot store contacts with None id")
        if contact in self.contacts:
            self.removeContact(contact.node_id)
            self.contacts.append(contact)
        elif len(self.contacts) < self.max_size:
            self.contacts.append(contact)
        else:
            raise BucketFull("Bucket is already full")

    def getContact(self, contact_id):
        index = self.contacts.index(contact_id)
        return self.contacts[index]

    def getContacts(self, count=-1):
        if count < 0:
            return list(self.contacts)
        else:
            return self.contacts[-count:]

    def removeContact(self, contact_id):
        index = self.contacts.index(contact_id)
        del self.contacts[index]

    def __len__(self):
        return len(self.contacts)


class KBucket(Bucket):
    max_size = 8
    
    def __init__(self, range_min, range_max):
        Bucket.__init__(self)
        self.range_min = range_min
        self.range_max = range_max

    def keyInRange(self, key):
        key = Key(key)
        return self.range_min <= key.id < self.range_max
    
    def splitBucket(self):
        if self.range_max-self.range_min == 1:
            return (self,)
        else:
            mid = (self.range_min + self.range_max)/2
            buck_a = KBucket(self.range_min, mid)
            buck_b = KBucket(mid, self.range_max)
            
            for contact in self.contacts:
                if buck_a.keyInRange(contact.node_id):
                    buck_a.addContact(contact)
                else:
                    buck_b.addContact(contact)
                    
            return (buck_a, buck_b)

class RoutingTable(object):
    def __init__(self, node_id):
        self.buckets = [KBucket(range_min=0, range_max=2**160+1)]
        self.node_id = Key(node_id)
    
    def __len__(self):
        l = 0
        for bucket in self.buckets:
            l += len(bucket)
        return l

    def getContact(self, contact_id):
        bucket = self._get_kbucket(contact_id)
        try:
            contact = bucket.getContact(contact_id)
        except ValueError:
            raise
        else:
            return contact

    def removeContact(self, contact_id):
        bucket = self._get_kbucket(contact_id)
        try:
            bucket.removeContact(contact_id)
        except ValueError:
            return 

    def addContact(self, contact):
        if contact.node_id == self.node_id or contact.node_id is None:
            return
        
        targ_kbucket = self._get_kbucket(contact.node_id)
        try:
            targ_kbucket.addContact(contact)
        except BucketFull:
            if targ_kbucket.keyInRange(self.node_id):
                i = self.buckets.index(targ_kbucket)
                self.buckets[i:i] = targ_kbucket.splitBucket()
                self.addContact(contact)
            
    def findCloseNodes(self, key, count):
        bucket = self._get_kbucket(key)
        size = count
        bucket_ind = self.buckets.index(bucket)
        closest_nodes = []
        search_list = [t[1] for t in sorted(enumerate(self.buckets), key=lambda t: abs(t[0] - bucket_ind))]
        for b in search_list:
            closest_nodes.extend(b.getContacts(size - len(closest_nodes)))
            if len(closest_nodes) >= size:
                return closest_nodes
        return closest_nodes
    
    def _get_kbucket(self, key):
        for bucket in self.buckets:
            if bucket.keyInRange(key):
                return bucket
        return
    
    def printTable(self):
        for bucket in self.buckets:
            print "bucket from {} to {}".format(bucket.range_min, bucket.range_max)
            for c in bucket.contacts:
                print "\t {}".format(c)
                
    def getAllContacts(self):
        result = list()
        for bucket in self.buckets:
            result.extend(bucket.getContacts())
        return result

