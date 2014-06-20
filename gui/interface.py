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
__date__ ="$08.06.2014 21:32:29$"

from gi.repository import Gtk
from gi.repository import Gdk
from gi.repository import Gio
from gi.repository import GObject
from gi.repository import Pango
import sys
    
#from profile import Buddy
#from profile import Profile

from profile import *


class TalkWidget(Gtk.Box):
    __gsignals__ = {
        'send-clicked': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, (GObject.TYPE_STRING, )),
        'connect-clicked': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, ()),
        'disconnect-clicked': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, ()),
        
    }
    def __init__(self, buddy, profile):
        Gtk.Box.__init__(self)
        self.set_orientation(Gtk.Orientation.VERTICAL)
        self.set_spacing(5)

        self.profile = profile
        
        self.buddy = buddy
        buddy.connect('notify::visible_name', self.on_notify_visible_name)
        buddy.connect('notify::status', self.on_notify_status)
        buddy.connect('notify::status', self.on_notify_connection_status)
        
        buddy.connect('message-received', self.on_message_received)
        buddy.connect('connection-info', self.on_connection_info)
        
        self.connect('send-clicked', buddy.on_send_message)
        self.connect('connect-clicked', buddy.make_connection)
        self.connect('disconnect-clicked', buddy.lose_connection)
        
        
        hbox = Gtk.HBox(False, 5)
        hbox.set_size_request(-1, 30)
        hbox.set_border_width(7)
        
        self.icon = Gtk.Image()
        self._update_icon()
        
        hbox.pack_start(self.icon, False, False, 0)
        
        self.name_label = Gtk.Label()
        self.name_label.set_markup('<b>%s</b>' % buddy.visible_name)
        hbox.pack_start(self.name_label, False, False, 0)
        
        self.connect_button = Gtk.Button()
        self.connection_button_icon = Gtk.Image()
        self._update_connection_button_icon()
        self.connect_button.set_image(self.connection_button_icon)
        
        self.connect_button.set_always_show_image(True)
#        self.connect_button.set_label("Connect")
        hbox.pack_end(self.connect_button, False, False, 0)
        
        self.pack_start(hbox, False, False, 0)
        
        scr_win1 = Gtk.ScrolledWindow()
        scr_win1.set_shadow_type(Gtk.ShadowType.IN)
        self.history_buffer = Gtk.TextBuffer()
        self.history_widget = Gtk.TextView.new_with_buffer(self.history_buffer)
        self.history_widget.set_property('editable', False)
        self.history_widget.set_property('wrap-mode', Gtk.WrapMode.WORD_CHAR)        
        scr_win1.add_with_viewport(self.history_widget)
        self.pack_start(scr_win1, True, True, 0)

        h_box = Gtk.HBox(False, 5)
        scr_win2 = Gtk.ScrolledWindow()
        scr_win2.set_shadow_type(Gtk.ShadowType.IN)
        self.message_buffer = Gtk.TextBuffer()
        self.message_widget = Gtk.TextView.new_with_buffer(self.message_buffer)
        self.message_widget.set_property('wrap-mode', Gtk.WrapMode.WORD_CHAR)
        scr_win2.add_with_viewport(self.message_widget)   
        h_box.pack_start(scr_win2, True, True, 0)
        
        self.send_button = Gtk.Button()
        self.send_button.set_label("Отправить")
        h_box.pack_end(self.send_button, False, False, 0)
        self.pack_start(h_box, False, False, 0)
        
        self.send_button.connect('clicked', self.send_clicked)
        self.connect_button.connect('clicked', self.connect_clicked)
                
        self.show_all()

    def on_message_received(self, obj, message):
        message = message.strip()
        end_h = self.history_buffer.get_end_iter()
        self.history_buffer.insert(end_h, "\n{}:\n{}\n".format(self.buddy.visible_name, message))
    
    def on_connection_info(self, buddy, info):
        end_h = self.history_buffer.get_end_iter()
        self.history_buffer.insert(end_h, "\n{}\n".format(info))
    
    def send_clicked(self, button, data=None):
        start, end = self.message_buffer.get_bounds()
        message = self.message_buffer.get_text(start, end, True)
        message = message.strip()
        
        self.message_buffer.set_text("")
        end_h = self.history_buffer.get_end_iter()
        self.history_buffer.insert(end_h, "\n{}:\n{}\n".format(self.profile.username, message))
        
        self.emit('send-clicked', message)
        
    def connect_clicked(self, button, data=None):
        if self.buddy.status == Buddy.Status.CONNECTED:
            self.emit('disconnect-clicked')
        elif self.buddy.status == Buddy.Status.ONLINE:
            self.emit('connect-clicked')


    def _update_icon(self):
        if self.buddy.status == Buddy.Status.OFFLINE:
            self.icon.set_from_stock(Gtk.STOCK_NO, Gtk.IconSize.MENU)
        elif self.buddy.status == Buddy.Status.ONLINE:
            self.icon.set_from_stock(Gtk.STOCK_DISCONNECT, Gtk.IconSize.MENU)
        elif self.buddy.status == Buddy.Status.CONNECTED:
            self.icon.set_from_stock(Gtk.STOCK_CONNECT, Gtk.IconSize.MENU)


    def _update_connection_button_icon(self):
        
        if self.buddy.status == Buddy.Status.OFFLINE:
            self.connection_button_icon.set_from_stock(Gtk.STOCK_DISCONNECT, Gtk.IconSize.MENU)
            self.connect_button.set_sensitive(False)
        elif self.buddy.status == Buddy.Status.ONLINE:
            self.connection_button_icon.set_from_stock(Gtk.STOCK_DISCONNECT, Gtk.IconSize.MENU)
            self.connect_button.set_sensitive(True)
        elif self.buddy.status == Buddy.Status.CONNECTED:
            self.connection_button_icon.set_from_stock(Gtk.STOCK_CONNECT, Gtk.IconSize.MENU)
            self.connect_button.set_sensitive(True)

        self.connect_button.set_image(self.connection_button_icon)

    def on_notify_visible_name(self, obj, gparamstring):
        self.name_label.set_text(self.buddy.visible_name)
        self.show_all()
    
    def on_notify_status(self, obj, gparamstring):
        self._update_icon()
        self.show_all()

    def on_notify_connection_status(self, obj, gparamstring):
        print "notify"
        self._update_connection_button_icon()
        
        self.show_all()



class TabLabel(Gtk.Box):
    __gsignals__ = {
        'close-clicked': (GObject.SIGNAL_RUN_FIRST, GObject.TYPE_NONE, ()),
    }
    def __init__(self, label_text, icon=None, closable=True):
        Gtk.Box.__init__(self)
        self.set_orientation(Gtk.Orientation.HORIZONTAL)
        self.set_spacing(5) 
        
        self.icon = icon
        # icon
        if not icon is None:
            self.pack_start(icon, False, False, 0)
        
        # label 
        self.label = Gtk.Label(label_text)
        self.pack_start(self.label, True, True, 0)
        
        if closable:
            # close button
            self.close_button = Gtk.Button()
            self.close_button.set_relief(Gtk.ReliefStyle.NONE)
            self.close_button.set_focus_on_click(False)
            self.close_button.add(Gtk.Image.new_from_stock(Gtk.STOCK_CLOSE, Gtk.IconSize.MENU))
            self.close_button.connect('clicked', self.close_clicked)
            data =  '.button {\n' \
                    '-GtkButton-default-border : 0px;\n' \
                    '-GtkButton-default-outside-border : 0px;\n' \
                    '-GtkButton-inner-border: 0px;\n' \
                    '-GtkWidget-focus-line-width : 0px;\n' \
                    '-GtkWidget-focus-padding : 0px;\n' \
                    'padding: 0px;\n' \
                    '}'
            provider = Gtk.CssProvider()
            provider.load_from_data(data)
            # 600 = GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
            self.close_button.get_style_context().add_provider(provider, 600) 
            self.pack_end(self.close_button, False, False, 0)
        
        self.show_all()
    
    def close_clicked(self, button, data=None):
        self.emit('close-clicked')
        
class TalkTabLabel(TabLabel):
    def __init__(self, buddy):
        self.buddy = buddy
        buddy.connect('notify::visible_name', self.on_notify_visible_name)
        buddy.connect('notify::status', self.on_notify_status)
        
        self.icon = Gtk.Image()
        self._update_icon()
        TabLabel.__init__(self, buddy.visible_name, self.icon)
        
    def _update_icon(self):
        if self.buddy.status == Buddy.Status.OFFLINE:
            self.icon.set_from_stock(Gtk.STOCK_NO, Gtk.IconSize.MENU)
        elif self.buddy.status == Buddy.Status.ONLINE:
            self.icon.set_from_stock(Gtk.STOCK_DISCONNECT, Gtk.IconSize.MENU)
        elif self.buddy.status == Buddy.Status.CONNECTED:
            self.icon.set_from_stock(Gtk.STOCK_CONNECT, Gtk.IconSize.MENU)
        
    def on_notify_visible_name(self, obj, gparamstring):
        self.label.set_text(self.buddy.visible_name)
        self.show_all()
    
    def on_notify_status(self, obj, gparamstring):
        self._update_icon()
        self.show_all()

class TalksNotebook(Gtk.Notebook):
    def __init__(self):
        Gtk.Notebook.__init__(self)
        self.set_property('show-tabs', True)
        self.set_border_width(3)
        self.set_scrollable(True)
        
    def new_talk(self, buddy):
        
        talk = TalkWidget(buddy, buddy.profile)
        
        label = TalkTabLabel(buddy)
        label.connect('close-clicked', self.close_tab, talk)        

        pg_num = self.append_page(talk, label)

        self.set_current_page(pg_num)
        talk.show_all()

    def close_tab(self, widget, child):
        pagenum = self.page_num(child)
        if pagenum != -1:
            self.remove_page(pagenum)
            child.destroy()


class DeleteBuddyDialog(Gtk.Dialog):
    
    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "Подтвердите удаление", parent, 0,
             (Gtk.STOCK_YES, Gtk.ResponseType.YES,
             Gtk.STOCK_NO, Gtk.ResponseType.NO))

        confirmation_label = Gtk.Label("Вы уверены что хотите удалить контакт?")
        
        box = self.get_content_area()
        box.add(confirmation_label)
        
        self.show_all()


class AddBuddyDialog(Gtk.Dialog):
    
    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "Добавить контакт", parent, 0,
             (Gtk.STOCK_OK, Gtk.ResponseType.OK,
             Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        self.set_default_size(150, 100)

        name_label = Gtk.Label("Имя:")
        self.name_entry  = Gtk.Entry()
        self.name_entry.set_text("")
        self.name_error_label = Gtk.Label()
        
        
        key_hash_label = Gtk.Label("Ключ:")
        self.key_hash_entry  = Gtk.Entry()
        self.key_hash_entry.set_text("")
        self.key_hash_error_label = Gtk.Label()
        
        grid = Gtk.Grid()
        box = self.get_content_area()
        box.add(grid)
        
        grid.set_border_width(10)
        grid.set_row_spacing(5)
        grid.set_column_spacing(5)

        grid.attach(name_label, 0, 0, 1, 1)
        grid.attach_next_to(self.name_entry, name_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.name_error_label, self.name_entry, Gtk.PositionType.RIGHT, 1, 1)
        
        
        grid.attach(key_hash_label, 0, 1, 1, 1)
        grid.attach_next_to(self.key_hash_entry, key_hash_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.key_hash_error_label, self.key_hash_entry, Gtk.PositionType.RIGHT, 1, 1)
        
        self.show_all()

    def convert_key(self, val):
        id = long(val, 16)
#        if not 0 <= self.id <= 2**160 - 1:
#            raise ValueError("Incorrect id value")
#        
        return id

    def do_response(self, response):
        self.name = self.name_entry.get_text()
        self.key_hash = self.key_hash_entry.get_text()
        self.correct_result = False
        
        if response == Gtk.ResponseType.OK:
            err = False
            if not self.name_entry.get_text():
                err = True
                self.name_error_label.set_text("Имя не может быть пустым")
            else:
                self.name_error_label.set_text("")
            
            try:
                k = self.convert_key(self.key_hash)
            except Exception as e:
                
                self.key_hash_error_label.set_text("Некорректный ключ")
                err = True
            else:
                self.key_hash_error_label.set_text("")
            
            if not err:
                self.correct_result = True
                self.destroy()
        else:
            self.destroy()
        
        
        return response


class EditBuddyDialog(AddBuddyDialog):
    def __init__(self, parent, name, key_hash):
        AddBuddyDialog.__init__(self, parent)
        self.name_entry.set_text(name)
        self.key_hash_entry.set_text(key_hash)
        self.set_title("Редактировать контакт")
        self.show_all()



class NewProfileDialog(Gtk.Dialog):
    def __init__(self, parent):
        Gtk.Dialog.__init__(self, "Новый профиль", parent, 0,
             (Gtk.STOCK_OK, Gtk.ResponseType.OK,
             Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))
            
        
        self.set_default_size(150, 100)

        grid = Gtk.Grid()
        box = self.get_content_area()
        box.add(grid)
        
        grid.set_border_width(10)
        grid.set_row_spacing(5)
        grid.set_column_spacing(5)

        username_label = Gtk.Label("Имя:")
        self.username_entry  = Gtk.Entry()
        self.username_entry.set_text("")
        self.username_error_label = Gtk.Label()
        grid.attach(username_label, 0, 0, 1, 1)
        grid.attach_next_to(self.username_entry, username_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.username_error_label, self.username_entry, Gtk.PositionType.RIGHT, 1, 1)
  
  

        password_label = Gtk.Label("Пароль:")
        self.password_entry = Gtk.Entry()
        self.password_entry.set_text("")
        self.password_entry.set_visibility(False)
        self.password_error_label = Gtk.Label()
        grid.attach(password_label, 0, 2, 1, 1)
        grid.attach_next_to(self.password_entry, password_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.password_error_label, self.password_entry, Gtk.PositionType.RIGHT, 1, 1)

        confirm_password_label = Gtk.Label("Подтвердите пароль:")
        self.confirm_password_entry  = Gtk.Entry()
        self.confirm_password_entry.set_text("")
        self.confirm_password_entry.set_visibility(False)
        self.confirm_password_error_label = Gtk.Label()
        grid.attach(confirm_password_label, 0, 3, 1, 1)
        grid.attach_next_to(self.confirm_password_entry, confirm_password_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.confirm_password_error_label, self.confirm_password_entry, Gtk.PositionType.RIGHT, 1, 1)
  
        encrypted_label = Gtk.Label("Использовать шифрование:")
        self.check_encrypted = Gtk.CheckButton()
        self.check_encrypted.connect('toggled', self.on_encrypted_toggled)
        self.check_encrypted.set_active(True)
        self.encrypted_error_label = Gtk.Label()
        grid.attach(encrypted_label, 0, 1, 1, 1)
        grid.attach_next_to(self.check_encrypted, encrypted_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.username_error_label, self.check_encrypted, Gtk.PositionType.RIGHT, 1, 1)


        
        save_as_label = Gtk.Label("Сохранить профиль как:")
        self.save_as_button = Gtk.FileChooserButton("Сохранить профиль как", Gtk.FileChooserAction.SAVE )
        self.save_as_button.connect('file-set', self.file_selected)        
        
        self.save_as_error_label = Gtk.Label()
        grid.attach(save_as_label, 0, 4, 1, 1)
        grid.attach_next_to(self.save_as_button, save_as_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.save_as_error_label, self.save_as_button, Gtk.PositionType.RIGHT, 1, 1)
  
  
  
        self.show_all()

    def on_encrypted_toggled(self, widget):
        ch = self.check_encrypted.get_active()
        self.password_entry.set_sensitive(ch)
        self.confirm_password_entry.set_sensitive(ch)
    
    def do_response(self, response):  
        self.username = self.username_entry.get_text()
        self.encrypted = self.check_encrypted.get_active()
        self.password = self.password_entry.get_text()
        self.path = self.save_as_button.get_filename()
        self.correct_result = False
        
        if response == Gtk.ResponseType.OK:
            flag = False
            if not self.username_entry.get_text():
                self.username_error_label.set_text("Имя не может быть пустым")
                flag = True
            else:
                self.username_error_label.set_text("")
            
            if self.check_encrypted.get_active():
                if not self.password_entry.get_text():
                    self.password_error_label.set_text("пароль не может быть пустым")
                    flag = True
                else:
                    self.password_error_label.set_text("")
                if self.password_entry.get_text() != self.confirm_password_entry.get_text():
                    self.confirm_password_error_label.set_text("Подтверждение не совпадает с паролем")
                    flag = True
                else:
                    self.confirm_password_error_label.set_text("")
            
            if not flag:
                path = self.save_as_button.get_filename()
                try:
                    file = open(path, 'w')
                except IOException:
                    flag = True
                    self.save_as_error_label.set_text("Невозможно открыть файл")
            if not flag:
                self.correct_result = True
                self.destroy()    
                    
        else:
            self.destroy()

        return response
#        Gtk.Dialog.do_response(self, id)

    def file_selected(self, widget):
#        widget.set_title(widget.get_filename())
        print "Selected filepath: %s" % widget.get_filename()



class OpenProfileDialog(Gtk.Dialog):
    def __init__(self, parent, port, nodes, profile):
        Gtk.Dialog.__init__(self, "Открыть профиль", parent, 0,
             (Gtk.STOCK_OK, Gtk.ResponseType.OK,
             Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        self.set_default_size(150, 100)

        self.prnt = parent
        self.port = port
        self.known_nodes = nodes
        self.profile = profile

        grid = Gtk.Grid()
        box = self.get_content_area()
        box.add(grid)
        
        grid.set_border_width(10)
        grid.set_row_spacing(5)
        grid.set_column_spacing(5)

        open_label = Gtk.Label("Файл профиля:")
        self.open_button = Gtk.FileChooserButton("Открыть профиль", Gtk.FileChooserAction.OPEN)
        self.open_error_label = Gtk.Label()
        grid.attach(open_label, 0, 0, 1, 1)
        grid.attach_next_to(self.open_button, open_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.open_error_label, self.open_button, Gtk.PositionType.RIGHT, 1, 1)
  
        password_label = Gtk.Label("Пароль:")
        self.password_entry = Gtk.Entry()
        self.password_entry.set_text("")
        self.password_entry.set_visibility(False)
        self.password_error_label = Gtk.Label()
        grid.attach(password_label, 0, 1, 1, 1)
        grid.attach_next_to(self.password_entry, password_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.password_error_label, self.password_entry, Gtk.PositionType.RIGHT, 1, 1)
  
        self.show_all()
        
    def do_response(self, response):
        if response == Gtk.ResponseType.OK:
            path = self.open_button.get_filename()
            password = self.password_entry.get_text()
            
            try:
                profile = Profile.load_from_file(path, password)
            except ProfileEncrypter.DecryptionException as e:
                self.password_error_label.set_text("Неправильный пароль")
            except Exception as e:
                self.open_error_label.set_text("Некорректный файл или пароль")
            else:
                if not self.profile is None:
                    self.profile.stop_network()
                profile.port = self.port
                profile.known_nodes = self.known_nodes
                profile.init_network()
                self.prnt.set_profile(profile)
                self.destroy()
        else:
            self.destroy()
        
        return response



class EditProfileDialog(Gtk.Dialog):
    def __init__(self, username, key_hash, parent):
        Gtk.Dialog.__init__(self, "Редактировать профиль", parent, 0,
             (Gtk.STOCK_OK, Gtk.ResponseType.OK,
             Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL))

        self.set_default_size(150, 100)

        grid = Gtk.Grid()
        box = self.get_content_area()
        box.add(grid)
        
        grid.set_border_width(10)
        grid.set_row_spacing(5)
        grid.set_column_spacing(5)
        
        
        username_label = Gtk.Label("Имя:")
        self.username_entry  = Gtk.Entry()
        self.username_entry.set_text(username)
        self.username_error_label = Gtk.Label()
        grid.attach(username_label, 0, 0, 1, 1)
        grid.attach_next_to(self.username_entry, username_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.username_error_label, self.username_entry, Gtk.PositionType.RIGHT, 1, 1)
  
  
        key_hash_label = Gtk.Label("Ключ:")
        self.key_hash_entry  = Gtk.Entry()
        self.key_hash_entry.set_text(key_hash)
        self.key_hash_entry.set_editable(False)
        self.key_hash_error_label = Gtk.Label()
        grid.attach(key_hash_label, 0, 1, 1, 1)
        grid.attach_next_to(self.key_hash_entry, key_hash_label, Gtk.PositionType.RIGHT, 1, 1)
        grid.attach_next_to(self.key_hash_error_label, self.key_hash_entry, Gtk.PositionType.RIGHT, 1, 1)
  
        self.show_all()
        
    def do_response(self, response):
        
        self.username = self.username_entry.get_text()
        self.correct_result = False
        
        if response == Gtk.ResponseType.OK:
            flag = False
            if not self.username_entry.get_text():
                self.username_error_label.set_text("Имя не может быть пустым")
                flag = True
            else:
                self.username_error_label.set_text("")
            
            if not flag:
                self.correct_result = True
                self.destroy()
        else:
            self.destroy()   

        return response


class MainWindow(Gtk.Window):
    MENU = """
    <ui>
        <menubar name='MenuBar'>
            <menu action='ProfileMenu'>
                <menuitem action='ProfileNew' />
                <menuitem action='ProfileOpen' />
                <menuitem action='ProfileEdit' />
                <separator />
                <menuitem action='ProfileQuit' />
            </menu>
            <menu action='BuddyMenu'>
                <menuitem action='BuddyRefresh' />
                <menuitem action='BuddyNew' />
                <menuitem action='BuddyEdit' />
                <menuitem action='BuddyDelete' />
            </menu>
            <menuitem action='Preferences'/>
            <menu action='HelpMenu'>
                <menuitem action='HelpAbout' />
            </menu>
        </menubar>
        <popup name='BuddyPopup'>
            <menuitem action='EditBuddy' />
            <menuitem action='DeleteBuddy' />
        </popup>
    </ui>
    """
    
    
    def __init__(self, profile=None):
        Gtk.Window.__init__(self, Gtk.WindowType.TOPLEVEL)
        self.set_title("BitTalks")
        self.set_default_size(500, 200)
        
        self.profile = None
        
        
        self.port = 8899
        self.known_nodes = [('127.0.0.1', 10000)]
        
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.add(vbox)

        #####################Creating Menu######################################   
        action_group = Gtk.ActionGroup('my_actions')
        self.add_profile_menu_actions(action_group)
        self.add_buddy_menu_actions(action_group)
        self.add_preferences_menu_actions(action_group)
        self.add_help_menu_actions(action_group)
        
        self.add_buddy_popup_actions(action_group)
        
        uimanager = self.create_ui_manager()
        uimanager.insert_action_group(action_group)
        
        self.menubar = uimanager.get_widget('/MenuBar')
        vbox.pack_start(self.menubar, False, False, 0)
        
        self.buddy_popup = uimanager.get_widget('/BuddyPopup')
        
        paned = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        
        #####################Left panel######################################   
        
        left_panel = Gtk.Box()
        left_panel.set_orientation(Gtk.Orientation.VERTICAL)
        left_panel.set_border_width(3)
        
        acc_frame = Gtk.Frame()
        hbox = Gtk.Box(Gtk.Orientation.HORIZONTAL)
        hbox.set_border_width(7)
        
        self.username_label = Gtk.Label()
        hbox.pack_start(self.username_label, False, False, 10)
        
        self.userstatus_icon = Gtk.Image()
        
        self.connect_profile_button = Gtk.Button()
        self.connect_profile_button.add(self.userstatus_icon)
        data =  '.button {\n' \
                '-GtkButton-default-border : 0px;\n' \
                '-GtkButton-default-outside-border : 0px;\n' \
                '-GtkButton-inner-border: 3px;\n' \
                '-GtkWidget-focus-line-width : 0px;\n' \
                '-GtkWidget-focus-padding : 0px;\n' \
                'padding: 0px;\n' \
                '}'
        provider = Gtk.CssProvider()
        provider.load_from_data(data)
        # 600 = GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
        self.connect_profile_button.get_style_context().add_provider(provider, 600) 
        hbox.pack_end(self.connect_profile_button, False, False, 5)
        
        self._update_userstatus_icon()
        
        self.connect_profile_button.connect('clicked', self.profile_connect_clicked)
        
        
        acc_frame.add(hbox)
        
        left_panel.pack_start(acc_frame, False, False, 4)
        
        scr_win = Gtk.ScrolledWindow()
        scr_win.set_shadow_type(Gtk.ShadowType.IN)
        
        
        self.buddy_treeview = Gtk.TreeView()
        self.buddy_treeview.set_headers_visible(False)
        self.buddy_treeview.connect('button_press_event', self.on_button_treeview)
        
        renderer_text = Gtk.CellRendererText()
        renderer_text.set_property('ellipsize', Pango.EllipsizeMode.END)
        column_text = Gtk.TreeViewColumn("Имя", renderer_text)
        column_text.set_cell_data_func(renderer_text, self.get_name_for_list)
        column_text.set_expand(True)
        self.buddy_treeview.append_column(column_text)

        renderer_pixbuf = Gtk.CellRendererPixbuf()
        column_pixbuf = Gtk.TreeViewColumn("Статус", renderer_pixbuf)
        column_pixbuf.set_cell_data_func(renderer_pixbuf, self.get_icon_for_list)
        column_pixbuf.set_expand(False)
        self.buddy_treeview.append_column(column_pixbuf)
        
        scr_win.add_with_viewport(self.buddy_treeview)
        left_panel.pack_start(scr_win, True, True, 0)
        
        btn_box = Gtk.Box(Gtk.Orientation.HORIZONTAL)
        btn_box.set_border_width(3)
        btn_box.set_spacing(3)
         
        self.add_buddy_button = Gtk.Button()
        self.add_buddy_button.add(Gtk.Image.new_from_stock(Gtk.STOCK_ADD, Gtk.IconSize.LARGE_TOOLBAR))
        data =  '.button {\n' \
                '-GtkButton-default-border : 0px;\n' \
                '-GtkButton-default-outside-border : 0px;\n' \
                '-GtkButton-inner-border: 0px;\n' \
                '-GtkWidget-focus-line-width : 0px;\n' \
                '-GtkWidget-focus-padding : 0px;\n' \
                'padding: 0px;\n' \
                '}'
        provider = Gtk.CssProvider()
        provider.load_from_data(data)
        # 600 = GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
        self.add_buddy_button.get_style_context().add_provider(provider, 600) 
        btn_box.pack_end(self.add_buddy_button, False, False, 0)
        
        self.refresh_button = Gtk.Button()
        self.refresh_button.add(Gtk.Image.new_from_stock(Gtk.STOCK_REFRESH, Gtk.IconSize.LARGE_TOOLBAR))
        data =  '.button {\n' \
                '-GtkButton-default-border : 0px;\n' \
                '-GtkButton-default-outside-border : 0px;\n' \
                '-GtkButton-inner-border: 0px;\n' \
                '-GtkWidget-focus-line-width : 0px;\n' \
                '-GtkWidget-focus-padding : 0px;\n' \
                'padding: 0px;\n' \
                '}'
        provider = Gtk.CssProvider()
        provider.load_from_data(data)
        # 600 = GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
        self.refresh_button.get_style_context().add_provider(provider, 600) 
        btn_box.pack_end(self.refresh_button, False, False, 0)
        
        self.preferences_button = Gtk.Button()
        self.preferences_button.add(Gtk.Image.new_from_stock(Gtk.STOCK_PREFERENCES, Gtk.IconSize.LARGE_TOOLBAR))
        data =  '.button {\n' \
                '-GtkButton-default-border : 0px;\n' \
                '-GtkButton-default-outside-border : 0px;\n' \
                '-GtkButton-inner-border: 0px;\n' \
                '-GtkWidget-focus-line-width : 0px;\n' \
                '-GtkWidget-focus-padding : 0px;\n' \
                'padding: 0px;\n' \
                '}'
        provider = Gtk.CssProvider()
        provider.load_from_data(data)
        # 600 = GTK_STYLE_PROVIDER_PRIORITY_APPLICATION
        self.preferences_button.get_style_context().add_provider(provider, 600) 
        btn_box.pack_start(self.preferences_button, False, False, 0)
        
        left_panel.pack_start(btn_box, False, False, 0)
        
        self.refresh_button.connect('clicked', self.on_menu_buddy_refresh)
        self.add_buddy_button.connect('clicked', self.on_menu_buddy_new)
        self.preferences_button.connect('clicked', self.on_menu_preferences)
        
        
        paned.pack1(left_panel, False, False)
        
        ##################### talks notebook ###################################   

        self.talks_notebook = TalksNotebook()
        paned.pack2(self.talks_notebook, True, False)
        
        vbox.pack_start(paned, True, True, 0)
        
        self.set_profile(profile)
        
        self.show_all()
    
    def set_profile(self, profile):
        self.profile = profile
        if not self.profile is None:
            self._update_userstatus_icon()
    
            self.username_label.set_markup("<b>%s</b>"% self.profile.username)
            self.buddy_treeview.set_model(self.profile.buddy_store)
            self.profile.connect('notify::username', self.on_notify_username)
            self.profile.connect('notify::status', self.on_notify_status)
            
            self.profile.connect('open-talk', self.on_open_talk)
        else:
            self.username_label.set_markup("<b>%s</b>"% "")
            self.buddy_treeview.set_model(Gtk.ListStore(Buddy.__gtype__))
            
        
    def on_button_treeview(self, treeview,event):
        x = int(event.x)
        y = int(event.y)
        time = event.time
        model = self.buddy_treeview.get_model()

        pthinfo = treeview.get_path_at_pos(x, y)
        if pthinfo is not None and pthinfo[0]:
            path, col, cellx, celly = pthinfo
            
            treeview.grab_focus()
            treeview.set_cursor( path, col, 0)
            
            if event.button == Gdk.BUTTON_PRIMARY and event.type == Gdk.EventType.DOUBLE_BUTTON_PRESS:            
                self.on_treeview_doubleclick(treeview)
            
            if event.button == Gdk.BUTTON_SECONDARY and event.type == Gdk.EventType.BUTTON_PRESS:            
                self.buddy_popup.popup(None, None, None, None, event.button, time)

        return True

    
    def open_talk(self, buddy):
        
        for page_num in range(self.talks_notebook.get_n_pages()):
            page = self.talks_notebook.get_nth_page(page_num)
            if page.buddy == buddy:
                self.talks_notebook.set_current_page(page_num)
                return
        
        self.talks_notebook.new_talk(buddy)
    
    def on_open_talk(self, obj, buddy):
        self.open_talk(buddy)
    
    def on_treeview_doubleclick(self, treeview):
        sel = self.buddy_treeview.get_selection()
        iter = sel.get_selected()[1]
        if not self.profile is None:
            buddy = self.profile.buddy_store[iter][0]

            self.open_talk(buddy)
    
    def profile_connect_clicked(self, widget):
        if not self.profile:
            return
        
        if self.profile.status == Profile.Status.ONLINE:
            self.profile.disconnect_network()
        elif self.profile.status == Profile.Status.OFFLINE:
            self.profile.connect_network()
        
    def get_icon_for_list(self, column, cell, model, iter, data):
        if self.profile is None:
            return
        status = self.profile.buddy_store.get_value(iter, 0).status
        if status == Buddy.Status.OFFLINE:
            cell.set_property('stock_id', Gtk.STOCK_NO)
        elif status == Buddy.Status.ONLINE:
            cell.set_property('stock_id', Gtk.STOCK_DISCONNECT)
        elif status == Buddy.Status.CONNECTED:
            cell.set_property('stock_id', Gtk.STOCK_CONNECT)
            
    def get_name_for_list(self, column, cell, model, iter, data):
        if self.profile is None:
            return
        cell.set_property('text', self.profile.buddy_store.get_value(iter, 0).visible_name)

    def add_profile_menu_actions(self, action_group):
        action_group.add_actions([
            ('ProfileMenu', Gtk.STOCK_ORIENTATION_PORTRAIT, "Профиль"),
            ('ProfileNew', Gtk.STOCK_NEW, "Новый", None, None,
                self.on_menu_profile_new),
            ('ProfileOpen', Gtk.STOCK_OPEN, "Открыть", None, None,
                self.on_menu_profile_open),
            ('ProfileEdit', Gtk.STOCK_EDIT, "Редактировать", None, None,
                self.on_menu_profile_edit),
            ('ProfileQuit', Gtk.STOCK_QUIT, None, None, None,
                self.on_menu_profile_quit)
        ])
    

    def add_buddy_menu_actions(self, action_group):
        action_group.add_actions([
            ('BuddyMenu', None, "Контакты"),
            ('BuddyRefresh', Gtk.STOCK_REFRESH, "Обновить статус", None, None,
             self.on_menu_buddy_refresh),
            ('BuddyNew', Gtk.STOCK_NEW, "Новый контакт", None, None,
             self.on_menu_buddy_new),
            ('BuddyEdit', Gtk.STOCK_EDIT, "Редактировать контакт", None, None,
             self.on_menu_buddy_edit),
            ('BuddyDelete', Gtk.STOCK_DELETE, "Удалить контакт", None, None,
             self.on_menu_buddy_delete)
        ])
        
    def add_help_menu_actions(self, action_group):
        action_group.add_actions([
            ('HelpMenu', Gtk.STOCK_HELP, None),
            ('HelpAbout', Gtk.STOCK_ABOUT, None, None, None,
                self.on_menu_help_about),
        ])
    
        
    def add_buddy_popup_actions(self, action_group):
        action_group.add_actions([
            ('EditBuddy', Gtk.STOCK_EDIT, None, None, None,
             self.on_menu_buddy_edit),
            ('DeleteBuddy', Gtk.STOCK_DELETE, None, None, None,
             self.on_menu_buddy_delete),
        ])
    
    
    def add_preferences_menu_actions(self, action_group):
        act = Gtk.Action('Preferences', None, None, Gtk.STOCK_PREFERENCES)
        act.connect('activate', self.on_menu_preferences)
        action_group.add_action(act)
    
    
    
    def create_ui_manager(self):
        uimanager = Gtk.UIManager()

        # Throws exception if something went wrong
        uimanager.add_ui_from_string(self.MENU)

        # Add the accelerator group to the toplevel window
        accelgroup = uimanager.get_accel_group()
        self.add_accel_group(accelgroup)
        return uimanager


    def on_menu_help_about(self, widget):
        about_dialog = Gtk.AboutDialog()
        about_dialog.set_license_type(Gtk.License.MIT_X11)
        about_dialog.set_copyright("Copyright (c) 2014 Igor Matsko")
        about_dialog.set_program_name("BitTalks")
        about_dialog.set_authors(["Igor Matsko"])
        about_dialog.set_version("0.3")
        about_dialog.set_wrap_license(False)
        about_dialog.run()
        about_dialog.destroy()
        pass

    def on_menu_profile_new(self, widget):
        new_prof_dialog = NewProfileDialog(self)
        response = new_prof_dialog.run()
        if response == Gtk.ResponseType.OK and new_prof_dialog.correct_result:
            path = new_prof_dialog.path
            username = new_prof_dialog.username

            if not self.profile is None:
                self.profile.stop_network()

            if not new_prof_dialog.encrypted:
                profile = Profile(self.port, self.known_nodes)
                profile.username = username
                profile.path = path
                profile.save_to_file()

            else:
                password = new_prof_dialog.password
                profile = Profile(self.port, self.known_nodes)
                profile.username = username
                profile.path = path
                profile.password = password
                profile.save_to_file()
            
            profile.init_network()
            self.set_profile(profile)
        return
        
    def on_menu_profile_open(self, widget):
        open_prof_dialog = OpenProfileDialog(self, self.port, self.known_nodes, self.profile)
        response = open_prof_dialog.run()
 
 
    def on_menu_profile_edit(self, widget):
        if self.profile is None:
            return
        
        edit_prof_dialog = EditProfileDialog(self.profile.username, self.profile.get_key_hash(), self)
        response = edit_prof_dialog.run()
        
        if response == Gtk.ResponseType.OK and edit_prof_dialog.correct_result:
            print "response",  response
            if edit_prof_dialog.username:
                self.profile.username = edit_prof_dialog.username
#                self.profile.key_hash = edit_prof_dialog.key_hash
            self.profile.save_to_file()
    
    def on_menu_profile_quit(self, widget):
        self.destroy()

    def on_menu_buddy_refresh(self, widget):
        if self.profile is None:
            return
        
        self.profile._update_buddy_stat_loop()

    
    def on_menu_buddy_edit(self, widget):
        if self.profile is None:
            return
        
        sel = self.buddy_treeview.get_selection()
        iter = sel.get_selected()[1]
        
        buddy = self.profile.buddy_store[iter][0]
        
        edit_dialog = EditBuddyDialog(self, buddy.name, buddy.key_hash)
    
        response = edit_dialog.run()
        
        if response == Gtk.ResponseType.OK and edit_dialog.correct_result:
            if edit_dialog.name:
                buddy.name = edit_dialog.name
                buddy.key_hash = edit_dialog.key_hash
                self.profile.save_to_file()
        
        
        
    def on_menu_buddy_delete(self, widget):
        if self.profile is None:
            return
        
        sel = self.buddy_treeview.get_selection()
        iter = sel.get_selected()[1]
        delete_dialog = DeleteBuddyDialog(self)
        response = delete_dialog.run()
        if response == Gtk.ResponseType.YES:
            self.profile.remove_buddy(iter)
            self.profile.save_to_file()
        delete_dialog.destroy()
        
    
    def on_menu_buddy_new(self, widget):
        if self.profile is None:
            return
        
        add_dialog = AddBuddyDialog(self)
        response = add_dialog.run()
        
        if response == Gtk.ResponseType.OK:
            if add_dialog.name:
                self.profile.add_buddy(add_dialog.name, add_dialog.key_hash)
                self.profile.save_to_file()
            
            
    def on_menu_preferences(self, widget):
        print "PREFERENCES"
        pass
    

    def _update_userstatus_icon(self):
        if self.profile is None:
            self.connect_profile_button.hide()
            return
        
        self.connect_profile_button.show()
        if self.profile.status == Profile.Status.ONLINE:
            self.userstatus_icon.set_from_stock(Gtk.STOCK_CONNECT, Gtk.IconSize.LARGE_TOOLBAR)
        else:
            self.userstatus_icon.set_from_stock(Gtk.STOCK_DISCONNECT, Gtk.IconSize.LARGE_TOOLBAR)

    def on_notify_username(self, obj, gparamstring):
        if self.profile is None:
            return
        
        self.username_label.set_markup("<b>%s</b>"% self.profile.username)
        self.show_all()
        
    def on_notify_status(self, obj, gparamstring):
        print "status notify"
        self._update_userstatus_icon()
        self.show_all()
        
        
            
def on_destroy(win):
    Gtk.main_quit()

def on_delete_event(widget, event):
    Gtk.main_quit()    

if __name__ == '__main__':
    path = 'test.prof'
    profile = Profile.load_from_file(path)
    print dir(profile)
    window = MainWindow(profile)
    window.connect('destroy', on_destroy)
    window.connect('delete-event', on_delete_event)
    window.show_all()
    Gtk.main()
    sys.exit(0)
