# -*- coding: utf-8 -*-
from scapy.all import *
import os

def ip_analysis(packet_list):    
    os.system("clear")  
    connection_src = []    
    connection_dst = []
    print('-------------------------------------------------------------------')
    print('Excluir o IP do alvo da análise?')
    tg = input('[Y/N]')
    if(tg == 'Y'):
        target_ip = input('Digite o IP do alvo: ')
    else:
        target_ip = '192.168.0.101' 
    mostly_updloader = []      

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):       
            connection_src.append(packet_list[i][IP].src)      
            connection_dst.append(packet_list[i][IP].dst)      
    connection_src = list(dict.fromkeys(connection_src))        
    connection_dst = list(dict.fromkeys(connection_dst))        
    try:
        connection_src.remove(target_ip)       
    except:
        print('[*] %s não está na lista de IPs fonte de pacote' %target_ip)    
    try:
        connection_dst.remove(target_ip)      
    except:
        print('[*] %s não está na lista de IPs destino de pacote' %target_ip)       
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
            if packet_list[j].haslayer(TCP):        
                if packet_list[j][IP].src == connection_array[i]:      
                    flagsrc += 1
                elif packet_list[j][IP].dst == connection_array[i]:   
                    flagdst += 1
        print('-------------------------------------------------------------------')
        print('[*] O IP %s upou %i e baixou %i pacotes do IP %s!!!' %(target_ip, flagsrc, flagdst, connection_array[i]))   
        if(flagsrc > flagdst):     
            mostly_updloader.append(connection_array[i])     

    print('-------------------------------------------------------------------')
    print('[*] Há %i IPs que uparam mais do que baixaram!!!' %len(mostly_updloader))     
    for i in range(len(mostly_updloader)):
        print('=> %s' %mostly_updloader[i])         
    print('-------------------------------------------------------------------') 