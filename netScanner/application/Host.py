#!/usr/bin/python
# -*- coding: utf-8 -*-
def getNetmaskBits(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])

def existHostWithMac(hosts, mac):
    for i in range(len(hosts)):
        if hosts[i].mac == mac:
            return i
    return -1
def existHostWithIp(hosts, ip):
    for host in hosts:
        if host.ip == ip:
            return True
    return False       

def mergeCurrentHostAndDbHosts(cHosts, dbHosts):
    for dbHost in dbHosts:
        hostIndex = existHostWithMac(cHosts, dbHost.mac)
            
        if hostIndex != -1:
            #czy się nie zmienił np adres ip
            #if len(cHosts[hostIndex].ip) > 0:
            #    if cHosts[hostIndex].ip != dbHost.ip:
            #        cHosts[hostIndex].ip = "**"+cHosts[hostIndex].ip+"** poprzedni ->"+dbHost.ip
            
            #dodać kolejne na tej zasadzie i przy zapisie listy do bazy wywalić ** oraz topisek o poprzednim
            
            #host już istniał wcześniej i mógł mieć opis i porty a aktualny nie ma i trzeba skopiować
            if len(cHosts[hostIndex].desc) == 0:
                cHosts[hostIndex].desc = dbHost.desc
            if len(cHosts[hostIndex].ports) == 0:
                cHosts[hostIndex].ports = dbHost.ports
            if len(cHosts[hostIndex].name) == 0:
                cHosts[hostIndex].name = dbHost.name
            if len(cHosts[hostIndex].netbios) == 0:
                cHosts[hostIndex].netbios = dbHost.netbios
#         elif existHostWithIp(cHosts, dbHost.ip) == True:
#             #znaczy, że ktoś zajął już to ip i w bazie jest nieaktualne
#             pass
        else:
            #aktualnie nie ma już tego hosta ale jest w bazie
            cHosts.append(dbHost)
    return cHosts

class Host(object):
    
    def __init__(self, ip, mac, name, desc, ports, live, netbios="none", remote="True"):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.live = live
        self.ports = ports
        self.desc = desc
        self.netbios = netbios
    def setOpenPorts(self, ports):
        self.ports = ports
        
    def setDescription(self, desc):
        self.desc = desc

    def setNetbios(self, netbios):
        self.netbios = netbios
        
    def setIsAlive(self, alive):
        if alive == True:
            self.live = "Tak"
        else:
            self.live = "Nie"
    
    def startArpSpoofing(self):
        pass
    
