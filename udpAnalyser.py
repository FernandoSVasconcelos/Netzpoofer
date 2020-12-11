from scapy.all import *

def udp_analysis(packet_list):          
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
        if packet_list[i].haslayer(UDP):       
            bad_udp += 1
    
    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):        
            if ((packet_list[i].dport == 'https') or (packet_list[i].dport == 443)):        
                snt += 1
                https_sent += 1
            elif ((packet_list[i].dport == 80) or (packet_list[i].dport == 8080)):         
                snt += 1
                http_sent += 1
            elif ((packet_list[i].dport == 21) or (packet_list[i].dport == 20)):      
                snt += 1
                ftp_sent += 1
            elif ((packet_list[i].dport == 22)):       
                snt += 1
                ssh_sent += 1
            if ((packet_list[i].sport == 'https') or (packet_list[i].sport == 443)):       
                rcv += 1
                https_rcv += 1
            elif ((packet_list[i].sport == 80) or (packet_list[i].sport == 8080)):      
                rcv += 1
                http_rcv += 1
            elif ((packet_list[i].sport == 21) or (packet_list[i].sport == 20)):       
                rcv += 1
                ftp_rcv += 1
            elif ((packet_list[i].sport == 22)):       
                rcv += 1
                ssh_rcv += 1
    print('-------------------------------------------------------------------')
    print('[*] There was %i non important packets' %(bad_udp - (snt + rcv)))   

    if (rcv > snt):    
        print('-------------------------------------------------------------------')
        print('[*] There was %i UDP packets sent!' %snt)        
        print('[*] There was %i UDP packets received!' %rcv)       
        print('[*] This User is a Mostly Downloader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))       
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))     
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))     
        print('[*] There was %i ssh packets sent and %i received' %(ssh_sent, ssh_rcv))    
        print('-------------------------------------------------------------------')
    else:      
        print('-------------------------------------------------------------------')
        print('[*] There was %i UDP packets sent!' %snt)        
        print('[*] There was %i UDP packets received!' %rcv)       
        print('[*] This User is a Mostly Uploader!!!')
        print('-------------------------------------------------------------------')
        print('[*] There was %i https packets sent and %i received' %(https_sent, https_rcv))    
        print('[*] There was %i http packets sent and %i received' %(http_sent, http_rcv))     
        print('[*] There was %i ftp packets sent and %i received' %(ftp_sent, ftp_rcv))     
        print('[*] There was %i ssh packets sent and %i received' %(ssh_sent, ssh_rcv))    
        print('-------------------------------------------------------------------')