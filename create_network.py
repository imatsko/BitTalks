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

import sys
import time
import socket
import subprocess

def destroyNetwork(nodes):
    print 'Destroying network...'
    for node in nodes:
        node.kill()
    return

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage:\n%s AMOUNT_OF_NODES [START_PORT [EXTERNAL_IP_ADDRESS]]' % sys.argv[0]
        sys.exit(1)
    amount = int(sys.argv[1])
    start_port = 4000
    if len(sys.argv) >= 3:
        start_port = int(sys.argv[2])
        
    external_ip = socket.gethostbyname(socket.gethostname())
    if len(sys.argv) == 4:
        external_ip = sys.argv[3]
    
    
    port = start_port+1
    nodes = []
    print 'Creating network...'
    try:
        nodes.append(subprocess.Popen(['python', 'start_node.py', str(start_port)]))
        for port in range(start_port+1, start_port+amount-1):
            time.sleep(0.2)
            print "start: node at port {} connect to {}:{}".format(port, external_ip, start_port)
            nodes.append(subprocess.Popen(['python', 'start_node.py', str(port), external_ip, str(start_port)]))
    except KeyboardInterrupt:
        '\nNetwork creation cancelled.'
        destroyNetwork(nodes)
        sys.exit(1)
    
    print '\n\n---------------\nNetwork running\n---------------\n'
    try:
        while 1:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        destroyNetwork(nodes)
    


