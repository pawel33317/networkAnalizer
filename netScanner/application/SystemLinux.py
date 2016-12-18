#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
from Gui import *
class SystemLinux(object):

    def __init__(self,wxApp):
        self.wxApp = wxApp
        self.routerIP = ""
        
    def getNetmask(self):
        try:
            netMask = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f4 | cut -d" " -f1').read().strip()
        except:
            netMask = ""
        self.wxApp.setMyMask(netMask)
    
    def getMyIP(self):
        try:
            ipAddress = os.popen('ifconfig eth0 | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1').read().strip()
        except:
            ipAddress = ""
        self.wxApp.setMyIpAddress(ipAddress)
    
    def getMyMac(self):
        try:
            macAddress = os.popen('ifconfig eth0 | grep -Eo ..\(\:..\){5}').read().strip()
        except:
            macAddress = ""
        self.wxApp.setMyMac(macAddress)
        
    def getRouterIP(self):
        try:
            self.routerIP = os.popen("route -n | grep 'UG[ \t]' | awk '{print $2}'").read().strip()
        except:
            self.routerIP = ""
        self.wxApp.setRouterIpAddress(self.routerIP)
        
    def getRouterMac(self):
        try:
            routerMac = os.popen('arp -a | grep \('+self.routerIP+'\) |  cut -d\) -f2 |  cut -d" " -f3').read().strip()
        except:
            routerMac = ""
        self.wxApp.setRouterMacAddress(routerMac)
        
    def clearIptables(self):
        try:
            os.system('iptables -F -t nat')
            os.system('iptables -X -t nat')
            os.system('iptables -F -t filter')
            os.system('iptables -X -t filter')
            os.system('iptables -P INPUT ACCEPT')
            os.system('iptables -P OUTPUT ACCEPT')
            os.system('iptables -P FORWARD ACCEPT')
            return "Iptables wyczyszczone - domyślna polityka accept"
        except:
            return "Czyszczenie iptables nie powiodło się "
            
    def setKernelForwarding(self):  
        try:
            currentForwardingState = str(os.popen('cat /proc/sys/net/ipv4/ip_forward').read().strip())
            if currentForwardingState == str(1):
                os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
                return "Forwarding pakietów w jądrze został wyłączony"
            else:
                os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
                return "Forwarding pakietów w jądrze został włączony"
        except:
            return "Zmiana forwardingu pakietów w kernelu nie udana"
            
    def startEttercap(self):
        os.system('gnome-terminal -e \'ettercap -T -q\' &')
            
            
            
                
    def forwardPortToPort(self,port,portTo):
        try:#
            print os.popen('iptables -t nat -A PREROUTING -p tcp --dport '+str(port)+' -j REDIRECT --to-port '+str(portTo)).read().strip()
            return "Przekierowanie ruchu z portu "+port+" na port "+portTo+" udane"
        except:
            return "Przekierowanie ruchu z portu "+port+" na port "+portTo+" nieudane"
          
    def forwardPortToIP(self,port,ip):
        try:
            #os.system('iptables -A FORWARD --in-interface eth0 -j ACCEPT')
            #os.system('iptables -t nat --append POSTROUTING --out-interface eth0 -j MASQUERADE')
            print os.popen('iptables -t nat -A PREROUTING -p tcp --dport '+str(port)+' --jump DNAT --to-destination '+str(ip)).read().strip()
            return "Przekierowanie ruchu z portu "+port+" na adres "+ip+" udane"
        except:
            return "Przekierowanie ruchu z portu "+port+" na adres "+ip+" nieudane"
        
        
        
        