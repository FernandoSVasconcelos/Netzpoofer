# -*- coding: utf-8 -*-
from scapy.all import *
import os

def multiU_analysis(packet_list):  
    os.system("clear")    
    connection_src = []     
    connection_dst = []    
    network_src = []
    network_dst = [] 
    mostly_updloader = []       

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):  
            if packet_list[i].haslayer(IP):     
                connection_src.append(packet_list[i][IP].src)      
                connection_dst.append(packet_list[i][IP].dst)       
    connection_src = list(dict.fromkeys(connection_src))        
    connection_dst = list(dict.fromkeys(connection_dst))  

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):
            if packet_list[i].haslayer(IP):
                if ('192.168' in packet_list[i][IP].src):
                    network_src.append(packet_list[i][IP].src)
                elif('192.168' in packet_list[i][IP].dst):
                    network_dst.append(packet_list[i][IP].dst)
    network_src = list(dict.fromkeys(network_src))
    network_dst = list(dict.fromkeys(network_dst))

    x = len(connection_dst)    
    y = len(connection_src)    

    print('-------------------------------------------------------------------')
    print('[*] Há %i IPs fonte!!!' %y)       
    print(connection_src)     
    print('-------------------------------------------------------------------')
    print('[*] Há %i IPs destino!!!' %x)      
    print(connection_dst)     
    print('-------------------------------------------------------------------')
    print('[*] Análise de Upload/Download')

    connection_array = connection_dst      
    for i in range(y):
        connection_array.append(connection_src[i])         
    connection_array = list(dict.fromkeys(connection_array))

    network_con = network_src
    for i in range(len(network_dst)):
        network_con.append(network_dst[i])
    network_con = list(dict.fromkeys(network_con))

    for i in range(len(network_con)):
        print('-------------------------------------------------------------------')
        for j in range(len(connection_array)):
            flagsrc = 0
            flagdst = 0
            for k in range(len(packet_list)):
                if packet_list[k].haslayer(UDP):
                    if packet_list[k].haslayer(IP):
                        if packet_list[k][IP].src == network_con[i] and packet_list[k][IP].dst == connection_array[j]:
                            flagsrc += 1
                        elif packet_list[k][IP].dst == network_con[i] and packet_list[k][IP].src == connection_array[j]:
                            flagdst += 1
            if(flagsrc != 0 or flagdst != 0):
                print('[*] O IP %s enviou %i e recebeu %i pacotes para o IP %s' %(network_con[i], flagsrc, flagdst, connection_array[j])) 
            if(flagsrc > flagdst):
                mostly_updloader.append(network_con[i])  

    print('-------------------------------------------------------------------')
    mostly_updloader = list(dict.fromkeys(mostly_updloader))
    if(len(mostly_updloader) > 1):
        print('[*] Há %i IPs que enviaram mais do que receberam!!!' %len(mostly_updloader))      
        for i in range(len(mostly_updloader)):
            print('=> %s' %mostly_updloader[i])    
        print('-------------------------------------------------------------------') 
    else:
        print('[*] Há %i IP que enviou mais do que recebeu!!!' %len(mostly_updloader))      
        for i in range(len(mostly_updloader)):
            print('=> %s' %mostly_updloader[i])    
        print('-------------------------------------------------------------------') 