#!/usr/bin/python
# -*- coding: utf-8 -*-
import nmap
from Host import *
from pprint import pprint
class Scanner(object):

    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def getNetworkHosts(self, ip, netmask, myMac):
        allHosts = []
        nm = self.nm
        nm.scan(hosts=ip+'/'+str(netmask), arguments='-n -sP -PE -PA21,23,80,3389')
        print ip+'/'+str(netmask)
        for ipAddress in nm.all_hosts():
            print nm[ipAddress]
            ip = ipAddress
            
            remote = True
            try:
                if str(nm[ipAddress]['status']['reason']).startswith('local'):
                    remote = False;
            except:
                pass
                
            try:
                mac = nm[ipAddress]['addresses']['mac']
            except:
                mac = ""
            
            desc = ""
            ports = ""
            netbios = ""
            live = "Tak"   
    
            try:
                name = nm[ipAddress]['vendor'][str(mac)]
            except:
                name=""
                
            if remote == False:
                mac = myMac
            allHosts.append(Host(ip, mac, name, desc, ports, live, netbios, remote))
        return allHosts
    
    
    def getHostOpenPorts(self, ip, netmask):
        nm = self.nm
        nm.scan(hosts=ip, arguments='-n --top-ports 100')
        try:
            openedPorts = []
            for item in nm[ip]['tcp']:
                if nm[ip]['tcp'][item]['state'] == 'open':
                    openedPorts.append(item)
            return ', '.join(str(x) for x in openedPorts)
        except:
            print "error in scanning host ports"
            return ""
        
    def getIsAlive(self, ip):
        self.nm.scan(hosts=ip, arguments='-n -sP -PE -PA21,23,80,3389')
        if len(self.nm.all_hosts()) > 0:
            return True
        else:
            return False
        
    def getNetbiosName(self,ip):
        try:
            nm = self.nm
            nm.scan(hosts=ip, arguments='-sU --script nbstat.nse -p137')
            pprint(nm[ip]['hostscript'])
            output = nm[ip]['hostscript'][0]['output']
            return output[output.find('NetBIOS name: ')+14:output.rfind(', NetBIOS user:')]
        except:
            return ""
        
'''
for x in allHosts:
    nm.scan(hosts=x.ip, arguments='-n --top-ports 100')
    try:
        x.openedPorts = []
        for item in nm[x.ip]['tcp']:
            if nm[x.ip]['tcp'][item]['state'] == 'open':
                print item
                x.openedPorts.append(item)
        print nm[x.ip]
        print vars(x)
        print x.openedPorts
    except:
        print "Brak otwartych portów"
'''