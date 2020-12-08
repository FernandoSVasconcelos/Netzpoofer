from scapy.all import *

def udp_analysis(packet_list):          #Função de análise UDP
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
    bad_udp = 0

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):        #Conta os pacotes UDP
            bad_udp += 1
    
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):        #Verifica se o pacote tem cabeçalho UDP
            if ((packet_list[i].dport == 'https') or (packet_list[i].dport == 443)):        #Verifica se o pacote enviado é HTTPS
                snt += 1
                https_sent += 1
            elif ((packet_list[i].dport == 80) or (packet_list[i].dport == 8080)):          #Verifica se o pacote enviado é HTTP
                snt += 1
                http_sent += 1
            elif ((packet_list[i].dport == 21) or (packet_list[i].dport == 20)):        #Verifica se o pacote enviado é FTP
                snt += 1
                ftp_sent += 1
            elif ((packet_list[i].dport == 22)):        #Verifica se o pacote enviado é SSH
                snt += 1
                ssh_sent += 1
            if ((packet_list[i].sport == 'https') or (packet_list[i].sport == 443)):        #Verifica se o pacote recebido é HTTPS
                rcv += 1
                https_rcv += 1
            elif ((packet_list[i].sport == 80) or (packet_list[i].sport == 8080)):      #Verifica se o pacote recebido é HTTP
                rcv += 1
                http_rcv += 1
            elif ((packet_list[i].sport == 21) or (packet_list[i].sport == 20)):        #Verifica se o pacote recebido é FTP
                rcv += 1
                ftp_rcv += 1
            elif ((packet_list[i].sport == 22)):        #Verifica se o pacote recebido é SSH
                rcv += 1
                ssh_rcv += 1
    print('-------------------------------------------------------------------')
    print('[*] There was %i non important packets' %(bad_udp - (snt + rcv)))    #Mostra a quantidade de pacotes UDP irrelevantes

    if (rcv > snt):     #Verifica se o alvo do sniffing é um downloader
        print('-------------------------------------------------------------------')
        print('[*] There was %i UDP packets sent!' %snt)        #Mostra a quantidade de pacotes UDP enviados
        print('[*] There was %i UDP packets received!' %rcv)        #Mostra a quantidade de pacotes UDP recebidos
        print('[*] This User is a Mostly Downloader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))       #Mostra a quantidade de pacotes HTTPS enviados e recebidos
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))      #Mostra a quantidade de pacotes HTTP enviados e recebidos
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))     #Mostra a quantidade de pacotes FTP enviados e recebidos
        print('[*] There was %i ssh packets sent and %i received' %(ssh_sent, ssh_rcv))     #Mostra a quantidade de pacotes SSH enviados e recebidos
        print('-------------------------------------------------------------------')
    else:       #Verifica se o alvo do sniffing é um uploader
        print('-------------------------------------------------------------------')
        print('[*] There was %i UDP packets sent!' %snt)        #Mostra a quantidade de pacotes UDP enviados
        print('[*] There was %i UDP packets received!' %rcv)        #Mostra a quantidade de pacotes UDP recebidos
        print('[*] This User is a Mostly Uploader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))       #Mostra a quantidade de pacotes HTTPS enviados e recebidos
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))      #Mostra a quantidade de pacotes HTTP enviados e recebidos
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))     #Mostra a quantidade de pacotes FTP enviados e recebidos
        print('[*] There was %i ssh packets sent and %i received' %(ssh_sent, ssh_rcv))     #Mostra a quantidade de pacotes SSH enviados e recebidos
        print('-------------------------------------------------------------------')