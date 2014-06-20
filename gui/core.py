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


from gi.repository import Gtk
from gi.repository import GObject

from gui.interface import *
from gui.profile import *

class BitTalksApp(Gtk.Application):    
    def __init__(self, port, known_nodes):
        Gtk.Application.__init__(self,
                                 flags=Gio.ApplicationFlags.FLAGS_NONE)
        self.connect('activate', self.on_activate)
        
        self.port = port
        self.known_nodes = known_nodes
        
    def on_activate(self, data=None):
#        profile = Profile("new user")
                
        window = MainWindow(None)
        window.port = self.port
        window.known_nodes = self.known_nodes
        
    
#        window.connect("delete-event", self.on_close)
        window.connect('destroy', self.on_close)

        self.add_window(window)
        window.show_all()
        return
    
    def on_close(self, *args):
        from twisted.internet import reactor
        reactor.stop()
        
