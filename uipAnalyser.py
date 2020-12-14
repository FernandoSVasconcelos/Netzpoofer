from scapy.all import *

def uip_analysis(packet_list):      
    connection_src = []     
    connection_dst = []     
    print('-------------------------------------------------------------------')
    print('Exclude target IP from the analysis?')
    tg = input('[Y/N]')
    if(tg == 'Y'):
        target_ip = input('Type the target IP for a better analysis: ')
    else:
        target_ip = '192.168.0.101'   
    mostly_updloader = []       

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(UDP):       
            connection_src.append(packet_list[i][IP].src)      
            connection_dst.append(packet_list[i][IP].dst)       
    connection_src = list(dict.fromkeys(connection_src))        
    connection_dst = list(dict.fromkeys(connection_dst))        
    try:
        connection_src.remove(target_ip)        
    except:
        print('[*] %s is not on the source list' %target_ip)       
    try:
        connection_dst.remove(target_ip)        
    except:
        print('[*] %s is not on the destination list' %target_ip)       
    x = len(connection_dst)    
    y = len(connection_src)    

    print('-------------------------------------------------------------------')
    print('[*] There are %i source IP!!!' %y)       
    print(connection_src)     
    print('-------------------------------------------------------------------')
    print('[*] There are %i destination IP!!!' %x)      
    print(connection_dst)     
    print('-------------------------------------------------------------------')
    print('[*] Upload/Download analysis')

    connection_array = connection_dst      
    for i in range(y):
        connection_array.append(connection_src[i])         
    connection_array = list(dict.fromkeys(connection_array))      

    for i in range(len(connection_array)):
        flagsrc = 0
        flagdst = 0
        for j in range(len(packet_list)):
            if packet_list[j].haslayer(UDP):      
                if packet_list[j][IP].src == connection_array[i]:      
                    flagsrc += 1
                elif packet_list[j][IP].dst == connection_array[i]:    
                    flagdst += 1
        print('-------------------------------------------------------------------')
        print('[*] The IP %s uploaded %i and downloaded %i packets!!!' %(connection_array[i], flagsrc, flagdst))  
        if(flagsrc > flagdst):     
            mostly_updloader.append(connection_array[i])      

    print('-------------------------------------------------------------------')
    print('[*] There are %i IP that upload more than download!!!' %len(mostly_updloader))      
    for i in range(len(mostly_updloader)):
        print('=> %s' %mostly_updloader[i])    
    print('-------------------------------------------------------------------') 