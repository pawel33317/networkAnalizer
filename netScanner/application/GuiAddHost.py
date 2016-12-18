#!/usr/bin/python
# -*- coding: utf-8 -*-
import wx,os
from Host import *

class GuiAddHost(wx.Frame):
    def __init__(self, parent, add):
        self.parent = parent
        self.add = add
        self.selected = parent.selected-1
        
        title = 'Nowy Host' if add else 'Edycja hosta nr: '+str(self.selected)
        wx.Frame.__init__(self, None, size=(230,280), title=title)
        self.pannel = wx.Panel(self)
        
        self.ip = wx.StaticText(self.pannel, label='Adres IP:', pos=(10, 10))
        self.mac = wx.StaticText(self.pannel, label='Adres MAC:', pos=(10, 40))
        self.name = wx.StaticText(self.pannel, label='Nazwa:', pos=(10, 70))
        self.desc = wx.StaticText(self.pannel, label='Opis:', pos=(10, 100))
        self.ports = wx.StaticText(self.pannel, label='Otwarte Porty:', pos=(10, 130))
        self.netbios = wx.StaticText(self.pannel, label='NetBios:', pos=(10, 160))
        self.live = wx.StaticText(self.pannel, label='Online:', pos=(10, 192))
        
        self.ipValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].ip, pos=(100, 10),size = (120,20))
        self.macValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].mac, pos=(100, 40),size = (120,20))
        self.nameValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].name, pos=(100, 70),size = (120,20))
        self.descValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].desc, pos=(100, 100),size = (120,20))
        self.portsValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].ports, pos=(100, 130),size = (120,20))
        self.netBiosValue = wx.TextCtrl(self.pannel,value='' if add else self.parent.hosts[self.selected].netbios, pos=(100, 160),size = (120,20))
        
        
        options = ["Tak","Nie"]
        self.liveValue = wx.ComboBox(self.pannel, pos=(100, 190), size = (120,25), choices=options, style=wx.CB_READONLY)
        self.buttonAdd = wx.Button(self.pannel,-1, pos=(10,230), label='Dodaj do listy')
        self.buttonCancel = wx.Button(self.pannel,-1, pos=(100,230), label='Anuluj')
        self.Bind(wx.EVT_BUTTON, self.onButtonAdd, self.buttonAdd)
        self.Bind(wx.EVT_BUTTON, self.onButtonCancel, self.buttonCancel)

    def onButtonAdd(self, evt):
        ip = self.ipValue.GetValue()
        mac = self.macValue.GetValue()
        name = self.nameValue.GetValue()
        desc = self.descValue.GetValue()
        ports = self.portsValue.GetValue()
        live = self.liveValue.GetStringSelection()
        netbios = self.netBiosValue.GetValue()
        if self.add:
            if existHostWithMac(self.parent.hosts,mac) == -1:
                self.parent.hosts.append(Host(ip, mac, name, desc, ports, live, netbios, False))
                wx.MessageBox('Dodano do listy.', 'Info', wx.OK | wx.ICON_INFORMATION)
                self.Destroy()
            else:
                wx.MessageBox('Nie można dodać hosta o podanym adresie MAC ponieważ już taki istnieje, nr: '+str(existHostWithMac(self.parent.hosts,mac))+'.', 'Info', wx.OK | wx.ICON_INFORMATION)
        else:
            self.parent.hosts[self.selected].ip = ip
            self.parent.hosts[self.selected].mac = mac
            self.parent.hosts[self.selected].name = name
            self.parent.hosts[self.selected].desc = desc
            self.parent.hosts[self.selected].ports = ports
            self.parent.hosts[self.selected].netbios = netbios
            
        self.parent.fillHostList()
        
    def onButtonCancel(self, evt):
        self.Destroy()