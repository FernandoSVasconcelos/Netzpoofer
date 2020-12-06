from struct import pack
from scapy.all import rdpcap
from scapy.all import *

def udp_analysis(packet_list):
    rcv = 0
    snt = 0
    https_sent = 0
    http_sent = 0
    ftp_sent = 0
    https_rcv = 0
    http_rcv = 0
    ftp_rcv = 0
    
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):
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