# -*- coding: utf-8 -*-
from scapy.all import *

def tcp_analysis(packet_list):    
    os.system("clear")
    rcv = 0
    snt = 0
    https_sent = 0
    http_sent = 0
    ftp_sent = 0
    ssh_sent = 0
    https_rcv = 0
    http_rcv = 0
    ftp_rcv = 0
    ssh_rcv = 0
    bad_tcp = 0
    
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):        
            bad_tcp += 1
    
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):       
            if ((packet_list[i].dport == 'https') or (packet_list[i].dport == 443)):        
                snt += 1
                https_sent += 1
            elif ((packet_list[i].dport == 80) or (packet_list[i].dport == 8080)):      
                snt += 1
                http_sent += 1
            elif ((packet_list[i].dport == 21) or (packet_list[i].dport == 20)):       
                snt += 1
                ftp_sent += 1
            elif ((packet_list[i].dport == 22)):        
                snt += 1
                ssh_sent += 1
            if ((packet_list[i].sport == 'https') or (packet_list[i].sport == 443)):       
                rcv += 1
                https_rcv += 1
            elif ((packet_list[i].sport == 80) or (packet_list[i].sport == 8080)):     
                rcv += 1
                http_rcv += 1
            elif ((packet_list[i].sport == 21) or (packet_list[i].sport == 20)):       
                rcv += 1
                ftp_rcv += 1
            elif ((packet_list[i].sport == 22)):       
                rcv += 1
                ssh_rcv += 1

    print('-------------------------------------------------------------------')
    print('[*] Existem %i pacotes não importantes' %(bad_tcp - (snt + rcv)))     

    if (rcv > snt):    
        print('-------------------------------------------------------------------')
        print('[*] Foram enviados %i pacotes UDP!' %snt)        
        print('[*] Foram recebidos %i pacotes UDP!' %rcv)       
        print('[*] Esse IP é um Downloader!!!')
        print('-------------------------------------------------------------------')
        print('[*] Foram enviados %i pacotes https e foram recebidos %i' %(https_sent, https_rcv))       
        print('[*] Foram enviados %i pacotes http e foram recebidos %i' %(http_sent, http_rcv))     
        print('[*] Foram enviados %i pacotes ftp e foram recebidos %i' %(ftp_sent, ftp_rcv))     
        print('[*] Foram enviados %i pacotes ssh e foram recebidos %i' %(ssh_sent, ssh_rcv))    
        print('-------------------------------------------------------------------')
    else:      
        print('-------------------------------------------------------------------')
        print('[*] Foram enviados %i pacotes UDP!' %snt)        
        print('[*] Foram recebidos %i pacotes UDP!' %rcv)       
        print('[*] Esse IP é um Uploader!!!')
        print('-------------------------------------------------------------------')
        print('[*] Foram enviados %i pacotes https e foram recebidos %i' %(https_sent, https_rcv))       
        print('[*] Foram enviados %i pacotes http e foram recebidos %i' %(http_sent, http_rcv))     
        print('[*] Foram enviados %i pacotes ftp e foram recebidos %i' %(ftp_sent, ftp_rcv))     
        print('[*] Foram enviados %i pacotes ssh e foram recebidos %i' %(ssh_sent, ssh_rcv))    
        print('-------------------------------------------------------------------')