# -*- coding: utf-8 -*-
from scapy.all import *
import os

def uip_analysis(packet_list):  
    os.system("clear")    
    connection_src = []     
    connection_dst = []     
    print('-------------------------------------------------------------------') 
    mostly_updloader = []       

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):  
            if packet_list[i].haslayer(IP):     
                connection_src.append(packet_list[i][IP].src)      
                connection_dst.append(packet_list[i][IP].dst)       
    connection_src = list(dict.fromkeys(connection_src))        
    connection_dst = list(dict.fromkeys(connection_dst))             
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

    for i in range(len(connection_array)):
        flagsrc = 0
        flagdst = 0
        for j in range(len(packet_list)):
            if packet_list[j].haslayer(UDP): 
                if packet_list[j].haslayer(IP):     
                    if packet_list[j][IP].src == connection_array[i]:      
                        flagsrc += 1
                    elif packet_list[j][IP].dst == connection_array[i]:    
                        flagdst += 1
        print('-------------------------------------------------------------------')
        print('[*] Os IPs interceptados enviaram %i e receberam %i pacotes do IP %s!!!' %(flagsrc, flagdst, connection_array[i]))  
        if(flagsrc > flagdst):     
            mostly_updloader.append(connection_array[i])      

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