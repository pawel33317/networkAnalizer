import sqlite3
import os.path, os
from Host import *
class SqlHandler(object):

    def __init__(self):
        self.dbName = 'netAnalizer.db'
        if os.path.isfile(self.dbName):
            print "Baza istnieje"
            self.connection = sqlite3.connect(self.dbName)
            self.executor = self.connection.cursor()
        else:
            print "Baza nie istnieje. Utworzona nowa"
            self.connection = sqlite3.connect(self.dbName)
            self.executor  = self.connection.cursor()
            self.executor .execute('''CREATE TABLE host 
            (ip text, 
            mac text, 
            name text, 
            live text, 
            ports text, 
            desc text,
            netbios text)''')
            
    def updateHosts(self, hosts):
        if len(hosts) == 0:
            self.executor.execute('DELETE FROM host')
        else:
            self.executor.execute('DELETE FROM host')
            for host in hosts:
                hostIP = host.ip
                #if "**" in host.ip:
                #    hostIP = hostIP[hostIP.find('**')+2:hostIP.rfind('**')]
                    
                    
                self.executor.execute('INSERT INTO host VALUES ("'+hostIP+'","'+host.mac+'","'+host.name+'","'+host.live+'","'+host.ports+'","'+host.desc+'","'+host.netbios+'")')
                self.connection.commit()
#         for host in hosts:
#             newDesc = host.desc
#             result = self.executor.execute('SELECT desc FROM host WHERE mac = "'+host.mac+'"')
#             alll = result.fetchall()
#             if len(alll) > 0 and len(newDesc) == 0:
#                 newDesc = alll[0][0]   
#                
#             ports = host.ports
#             result2 = self.executor.execute('SELECT ports FROM host WHERE mac = "'+host.mac+'"')
#             alll2 = result.fetchall()
#             if len(host.ports) == 0 and len(alll) > 0 :
#                 ports = alll2[0][0]   
#             
#             alll = result2.fetchall()
#             
#             
#             self.executor.execute('DELETE FROM host WHERE ip = "'+host.ip+'" or mac = "'+host.mac+'"')
#             self.executor.execute('INSERT INTO host VALUES ("'+host.ip+'","'+host.mac+'","'+host.name+'","'+host.live+'","'+ports+'","'+newDesc+'")')
#             self.connection.commit()
            
    def getAllHosts(self):
        hostsResult = self.executor.execute('SELECT ip, mac, name, ports, desc, netbios FROM host')
        hosts = []
        for host in hostsResult:
            hosts.append(Host(host[0], host[1], host[2], host[4], host[3], "Nie", host[5],True))
        return hosts
                
            
            
            
            
            
            
            
            
            
            
            
            
