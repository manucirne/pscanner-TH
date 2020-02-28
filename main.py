import socket
import json
import tkinter.scrolledtext as tkst
from tkinter import Tk, Label, Button, Frame, Entry, ttk,  IntVar, Checkbutton
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings
from scapy.all import *

with open('PS.json', 'r') as f:
    imp_ports = json.load(f)

class PortScanner(Frame):
    def __init__(self, master):
        
        self.master = master
        self.master.title("PortScanner")
        self.master.geometry("600x500")
        

        self.label = Label(self.master, text="IP:")
        self.label.place(x=20, y=20)
        self.ip = Entry(self.master)
        self.ip.place(x=70, y=20)
        
        self.udp = IntVar()
        Checkbutton(self.master, text="UDP", variable=self.udp).place(x=240, y=20)
        self.tcp = IntVar()
        Checkbutton(self.master, text="TCP", variable=self.tcp).place(x=300, y=20)

        self.inter = Label(self.master, text="ports:")
        self.inter.place(x=20, y=50)
        self.interval = Entry(self.master)
        self.interval.place(x=70, y=50)
        
        self.labelT = Label(self.master, text="TimeOut:")
        self.labelT.place(x=240, y=50)
        self.timeO = Entry(self.master)
        self.timeO.place(x=310, y=50)
        self.labelR = Label(self.master, text="recomended: 20 - 70")
        self.labelR.place(x=240, y=80)
        
        self.labelErr = Label(self.master, text="")
        self.labelErr.place(x=240, y=120)

        self.find_button = Button(self.master, text="Find Ports", command=self.res_scannP)
        self.find_button.place(x=20, y=90)
        
        self.net_button = Button(self.master, text="Scan Net", command=self.scanN)
        self.net_button.place(x=120, y=90)

        self.close_button = Button(self.master, text="Close", command=self.master.quit)
        self.close_button.place(x=420, y=460)

        self.resposta = tkst.ScrolledText(self.master, wrap='word')
        self.resposta.place(x = 20, y = 150, height=300, width=550)
        self.resposta.configure(font='Bodoni 10', bg='white')


    #https://www.thepythoncode.com/article/building-network-scanner-using-scapy
    def scanN(self):
        target_ip = self.ip.get()
        tout = int(self.timeO.get())
        arp = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=tout, verbose=0)[0]
        clients = []

        for sent, received in result:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        for client in clients:
            self.resposta.insert('insert', 'IP --> {} ||| MAC --> {}\n'.format(client['ip'], client['mac']))
                                   
    def tcp_connect_scan(self,dst_ip,dst_port):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((dst_ip, dst_port))
        if result == 0:
            sock.close()
            return True
        else:
            sock.close()
            return False
        
    #https://resources.infosecinstitute.com/port-scanning-using-scapy/#gref
    def udp_scan(self,dst_ip,dst_port,dst_timeout):
        udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
        if (str(type(udp_scan_resp))=="<class 'NoneType'>"):
            retrans = []
            for count in range(0,3):
                retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
            for item in retrans:
                if (str(type(item))!="<class 'NoneType'>"):
                    self.udp_scan(dst_ip,dst_port,dst_timeout)
            return "Filtered | Open"
        elif (udp_scan_resp.haslayer(UDP)):
            return "Open"
        elif(udp_scan_resp.haslayer(ICMP)):
            if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
                return "Closed"
            elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
                return "Filtered"
        else:
            return "CHECK"

    def pscan(self, port):
        
        target = self.ip.get()
        test = target.replace("."," ")
        test = test.split()
        if len(test) != 4:
            self.labelErr = Label(self.master, text="Err: Wrong format in IP address")
            self.labelErr.place(x=240, y=120)
            raise Exception("Wrong format in IP address")
        try: 
            num = int(test[0])
            num = int(test[1])
            num = int(test[2])
            num = int(test[3])
        except:
            self.labelErr = Label(self.master, text="Err: Wrong format in IP address")
            self.labelErr.place(x=240, y=120)
            raise Exception("Wrong format in IP address")
        tout = int(self.timeO.get())
        resudp = False
        tcppres = False
        strtcp = "Closed"
        udpres = "Closed"
        if self.udp.get():
            udpres = self.udp_scan(target,port,tout)
            if(udpres == "Open"):
                resudp = True
            elif(udpres == "Filtered | Open"):
                resudp = True
            elif(udpres == "Filtered"):
                resudp = True
        if self.tcp.get():
            tcppres = self.tcp_connect_scan(target,port)
            if(tcppres):
                strtcp = "Open"
        return tcppres, strtcp, resudp, udpres


    def res_scannP(self):
        self.resposta.delete("1.0","end")
        port_dirty = self.interval.get()
        port_dirty = port_dirty.replace("-", " ")
        port_dirty = port_dirty.split()
        port_init = port_dirty[0]
        port_end = port_dirty[1]
        try:
            t = int(port_init)
            t2 = int(port_end)
            if t2 < t:
                self.labelErr = Label(self.master, text="Err: wrong format - Port interval (ex: 10-20)")
                self.labelErr.place(x=240, y=120)
            try:
                t3 = int(port_dirty[2])
                self.labelErr = Label(self.master, text="Err: wrong format - Port interval (ex: 10-20)")
                self.labelErr.place(x=240, y=120)
            except:
                pass
        except:
            self.labelErr = Label(self.master, text="Err: wrong format - Port interval (ex: 10-20)")
            self.labelErr.place(x=240, y=120)
            raise Exception("wrong format - Port interval")
           
        for x in range(int(port_init),int(port_end)+1):
            res = self.pscan(x)
            if res[0]:
                serv = ""
                if (str(x)+"/tcp") in imp_ports:
                    serv = "Service: {}".format(imp_ports[str(x)+"/tcp"])
                self.resposta.insert('insert', '(TCP)Port {} is {}  --  {}\n'.format(x,res[1], serv))
            if res[2]:
                serv = ""
                if (str(x)+"/udp") in imp_ports:
                    serv = "Service: {}".format(imp_ports[str(x)+"/udp"])
                self.resposta.insert('insert', '(UDP)Port {} is {}  --  {}\n'.format(x,res[3], serv))
                


root = Tk()
my_gui = PortScanner(root)
root.mainloop()
	  
