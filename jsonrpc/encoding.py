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
__date__ ="$14.03.2014 17:00:12$"

import json

class Codec(object):
    """
    Abstract base codec converting primitive objects (dicts, lists, strings, numbers)
    to some form, like JSON or XML
    """
    def encode(self, data):
        """
        Converts some data primitive to another representation
        """
        raise NotImplementedError("encode")
        return
    
    def decode(self, data):
        """
        Converts some representation to data primitive
        """
        raise NotImplementedError("decode")
        return

class JSONCodec(Codec):
    """
    Converts data primitives to JSON strings 
    """
    def encode(self, obj):
        return json.dumps(obj)
    
    def decode(self, data):
        return json.loads(data)

