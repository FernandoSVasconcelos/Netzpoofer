from struct import pack
from scapy.all import rdpcap
from scapy.all import *

def main():
    print(' _____     ___     _____   _____   _____   ______  _______  ______  _____  ')
    print('(_____)  _(___)_  (_____) (_____) (_____) (______)(__ _ __)(______)(_____)   ')
    print('(_)__(_)(_)   (_)(_)___(_)(_)__(_)(_)__(_)(_)__      (_)   (_)__   (_)__(_)')
    print('(_____) (_)    _ (_______)(_____) (_____) (____)     (_)   (____)  (_____) ')
    print('(_)     (_)___(_)(_)   (_)(_)     ( ) ( ) (_)____    (_)   (_)____ ( ) ( ) ')
    print('(_)       (___)  (_)   (_)(_)     (_)  (_)(______)   (_)   (______)(_)  (_)') 

    pcap_filename = input('Pcap Filename: ')
    print(pcap_filename)
    packet_list = rdpcap(pcap_filename)   

    print('[*] There is %i packets.' %len(packet_list))
    print('Packet Content: ')
    print(packet_list)

    while True:
        print('1 - Especific Packet Content')
        print('2 - All Packet Content')
        print('3 - All TCP Packets')
        print('4 - All UDP Packets')
        print('5 - HTTP Analysis')
        print('0 - to Break')
        menu = int(input('Selection: '))
        if(menu == 1):
            espec_packet(packet_list)
            print('1 - Check more packets')
            print('2 - Quit')
            espec_menu = int(input('Selection: '))
            if(espec_menu == 2):
                break
        elif(menu == 2):
            full_packet(packet_list)
        elif(menu == 3):
            tcp_packet(packet_list)
        elif(menu == 4):
            udp_packet(packet_list)
        elif(menu == 5):
            http_analysis(packet_list)
        else:
            break
    
def espec_packet(packet_list):
    print('Type the number of the packet to analyse')
    packet_number = int(input('Packet Number: '))
    packet_list[packet_number].show()

def full_packet(packet_list):
    for i in range(len(packet_list)):
        packet_list[i].show()

def tcp_packet(packet_list):
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):
            packet_list[i].show()

def udp_packet(packet_list):
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):
            packet_list[i].show()

def http_analysis(packet_list):
    rcv = 0
    snt = 0
    https_sent = 0
    http_sent = 0
    ftp_sent = 0
    https_rcv = 0
    http_rcv = 0
    ftp_rcv = 0
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):
            if ((packet_list[i].dport == 'https') or (packet_list[i].dport == 443)):
                snt += 1
                https_sent += 1
            elif ((packet_list[i].dport == 80) or (packet_list[i].dport == 8080)):
                snt += 1
                http_sent += 1
            elif ((packet_list[i].dport == 21)):
                snt += 1
                ftp_sent += 1
            if ((packet_list[i].sport == 'https') or (packet_list[i].sport == 443)):
                rcv += 1
                https_rcv += 1
            elif ((packet_list[i].sport == 80) or (packet_list[i].sport == 8080)):
                rcv += 1
                http_rcv += 1
            elif ((packet_list[i].sport == 21)):
                rcv += 1
                ftp_rcv += 1
    if (rcv > snt):
        print('-------------------------------------------------------------------')
        print('[*] There was %d packets sent!' %snt)
        print('[*] There was %i packets received!' %rcv)
        print('[*] This User is a Mostly Downloader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))
        print('-------------------------------------------------------------------')
    else:
        print('-------------------------------------------------------------------')
        print('[*] There was %d packets sent!' %snt)
        print('[*] There was %i packets received!' %rcv)
        print('[*] This User is a Mostly Uploader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))
        print('-------------------------------------------------------------------')
            

main()