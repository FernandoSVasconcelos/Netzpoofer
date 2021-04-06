# -*- coding: utf-8 -*-
from scapy.all import rdpcap
from scapy.all import *
from tcpAnalyser import tcp_analysis
from ipAnalyser import ip_analysis
from udpAnalyser import udp_analysis
from uipAnalyser import uip_analysis
from MultiUAnalyser import multiU_analysis
from MultiTAnalyser import multiT_analysis
import os

def pcapreter():
    os.system("clear")
    print(' _____     ___     _____   _____   _____   ______  _______  ______  _____  ')
    print('(_____)  _(___)_  (_____) (_____) (_____) (______)(__ _ __)(______)(_____)   ')
    print('(_)__(_)(_)   (_)(_)___(_)(_)__(_)(_)__(_)(_)__      (_)   (_)__   (_)__(_)')
    print('(_____) (_)    _ (_______)(_____) (_____) (____)     (_)   (____)  (_____) ')
    print('(_)     (_)___(_)(_)   (_)(_)     ( ) ( ) (_)____    (_)   (_)____ ( ) ( ) ')
    print('(_)       (___)  (_)   (_)(_)     (_)  (_)(______)   (_)   (______)(_)  (_)') 

    print('')
    print('[*] Todos os arquivos pcap: ')
    os.system("ls ./Files/")
    print('-------------------------------------------------------------------')
    pcap_filename = input('Nome do arquivo pcap: ')        
    os.system("clear")
    print(pcap_filename)
    packet_list = rdpcap("Files/" + pcap_filename)         

    print('[*] Há %i pacotes.' %len(packet_list))
    print('Packet Content: ')
    print(packet_list)      

    while True:         
        print('1 - Conteúdo de um pacote específico')
        print('2 - Conteúdo de todos os pacotes')
        print('3 - Todos os pacotes TCP')
        print('4 - Todos os pacotes UDP')
        print('5 - Análise TCP')
        print('6 - Análise TCP/IP')
        print('7 - Análise UDP')
        print('8 - Análise UDP/IP')
        print('9 - Análise UDP de multiplos IPs')
        print('10 - Análise TCP de multiplos IPs')
        print('0 - Sair')

        menu = int(input('Selecione: '))
        if(menu == 1):
            espec_packet(packet_list)       
        elif(menu == 2):
            full_packet(packet_list)        
        elif(menu == 3):
            tcp_packet(packet_list)       
        elif(menu == 4):
            udp_packet(packet_list)        
        elif(menu == 5):
            tcp_analysis(packet_list)       
        elif(menu == 6):
            ip_analysis(packet_list)        
        elif(menu == 7):
            udp_analysis(packet_list)       
        elif(menu == 8):
            uip_analysis(packet_list)    
        elif(menu == 9):
            multiU_analysis(packet_list)  
        elif(menu == 10):
            multiT_analysis(packet_list)
        else:
            break
    
def espec_packet(packet_list):
    os.system("clear")     
    print('Digite o número do pacote que deseja analisar')
    packet_number = int(input('Número do pacote: '))       
    packet_list[packet_number].show()      

def full_packet(packet_list):   
    os.system("clear")  
    for i in range(len(packet_list)):
        packet_list[i].show()      

def tcp_packet(packet_list):    
    os.system("clear")    
    flag = 0
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):        
            packet_list[i].show()   
            flag += 1
    if(flag == 0):
        print("Há 0 pacotes TCP")   

def udp_packet(packet_list):  
    os.system("clear")    
    flag = 0  
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):        
            packet_list[i].show()  
            flag += 1
    if(flag == 0):
        print("Há 0 pacotes UDP")     