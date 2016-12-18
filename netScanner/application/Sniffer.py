#!/usr/bin/python
# -*- coding: utf-8 -*-
import collections
import wx
import pyshark

def runSniffer(ip,resultLabel):
    sniffer = Sniffer(ip,resultLabel)
    sniffer.startCheckSafety()


class Sniffer(object):
    def __init__(self, ip, resultLabel):
        self.resultLabel = resultLabel.safetyResult
        self.ip = ip
        wx.CallAfter(self.resultLabel.SetLabel,'Trwa sprawdzanie')
        
    def startCheckSafety(self):
        capturedPackets = pyshark.LiveCapture(interface='eth0', bpf_filter='dst '+self.ip+' and arp')
        capturedPackets.sniff(timeout=11)
        
        arpReplaySrcList = []
        print "Ilosc pakietow: "+str(len(capturedPackets))
        if len(capturedPackets) == 0:
            wx.CallAfter(self.resultLabel.SetLabel,'Nie wykryto ataków ARP')
        else:
            print "Iteruje po pakietach"
            for i in range(len(capturedPackets)):
                #print "iii"
                print capturedPackets[i]
                if "Opcode: reply" not in str(capturedPackets[i]):
                    print "OK request only"
                else:
                    for line in str(capturedPackets[i]).split("\n"):
                        if "Sender MAC address: " in line:
                            print "znaleziono MAC nadawcy"
                            arpReplaySrcList.append(str(line))
            counterOfDoublePackets=collections.Counter(arpReplaySrcList)
            safety = True
            for value in counterOfDoublePackets.values():
                print "obliczono ilości pakietów"
                if value > 2:
                    print "niebezpieczna ilość pakietów ARP replay skierowanych od jednej osoby"
                    safety = False
                    wx.CallAfter(self.resultLabel.SetLabel,'Możliwy atak ARP')
                    break
            if safety == True:
                wx.CallAfter(self.resultLabel.SetLabel,'Nie wykryto ataków ARP')
                
        '''
        #zamiast na bibliotecy pyshark operuje na tsharku samodzielnie
        
        import os,re,time
        import subprocess,shlex

        DEVNULL = open(os.devnull, 'wb')
        
        bashCommand = "killall tshark"
        processKill = subprocess.Popen(bashCommand.split())
        time.sleep(1)
        processKill.kill()
        
        print "Tshark start"
        bashCommand = 'tshark -i eth0 -w tshark_arp.pcap -f "dst '+self.ip+' and arp"'
        args = shlex.split(bashCommand)
        #process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=DEVNULL)#bez outputu
        #out, err = process.communicate()
        process = subprocess.Popen(args) 
        time.sleep(11)#czas na złapanie pakietów
        process.kill()
        print "Tshark stop"
        
        bashCommand = "tshark -V -r tshark_arp.pcap"
        processOutput = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE, stderr=DEVNULL).communicate()[0]
        capturedPacketList = re.compile('Frame \d+: \d+ bytes on wire').split(processOutput)
        capturedPacketList = filter(None, capturedPacketList)
        print "Ilość przechwyconych pakietów ARP replay sierowanych do Ciebie: "+str(len(capturedPacketList))
        #print processOutput
        
        arpReplaySrcList = []
        if len(capturedPacketList) == 0:
            wx.CallAfter(self.resultLabel.SetLabel,'Nie wykryto ataków ARP')
        else:
            for packet in capturedPacketList:
                if "Address Resolution Protocol (reply)" not in packet:
                    print "OK request only"
                else:
                    for line in packet.split("\n"):
                        if "Sender MAC address: " in line:
                            print "znaleziono MAC nadawcy"
                            arpReplaySrcList.append(str(line)) 
            counterOfDoublePackets=collections.Counter(arpReplaySrcList)
            safety = True
            for value in counterOfDoublePackets.values():
                print "obliczono ilości pakietów"
                if value > 2:
                    print "niebezpieczna ilość pakietów ARP replay skierowanych od jednej osoby"
                    safety = False
                    wx.CallAfter(self.resultLabel.SetLabel,'Możliwy atak ARP')
                    break
            if safety == True:
                wx.CallAfter(self.resultLabel.SetLabel,'Nie wykryto ataków ARP')
        '''      