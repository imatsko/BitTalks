#!/usr/bin/env python
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
__date__ ="$13.06.2014 19:49:28$"


from twisted.internet import gtk3reactor
gtk3reactor.install()

from gui.core import *

from twisted.internet import reactor

def start(port, known_nodes):    
    app = BitTalksApp(udp_port, known_nodes)
    
    reactor.registerGApplication(app)
    reactor.run()


if __name__ == '__main__':
    import logging

    from jsonrpc.rpc  import module_logger as rpc_logger

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    rpc_logger.addHandler(console)
    
    args = sys.argv[1:]
    
    try:
        udp_port = int(args.pop(0))
    except:
        print "set default port 8899"
        udp_port = 8899
    
    known_nodes = list()

    while args:
        try:
            addr = args.pop(0)
            port = int(args.pop(0))
            known_nodes.append((addr, port))
        except :
            break

    start(udp_port, known_nodes)

