from scapy.all import *

def ip_analysis(packet_list):       #Função de análise TCP/IP
    connection_src = []     #Inicia a lista de IP fonte
    connection_dst = []     #Inicia a lista de IP destino
    target_ip = input('Type the target IP for a better analysis: ')     #Seta o IP alvo, para remove-lo das listas de IP
    mostly_updloader = []       #Inicia a lista de uploaders

    for i in range(len(packet_list)):
        if packet_list[i].haslayer(TCP):        #Verifica se o pacote tem cabeçalho TCP
            connection_src.append(packet_list[i][IP].src)       #Adiciona o IP fonte a lista de IP fonte
            connection_dst.append(packet_list[i][IP].dst)       #Adiciona o IP destino a lista de IP destino
    connection_src = list(dict.fromkeys(connection_src))        #Exclui elementos repetidos da lista de IP fonte
    connection_dst = list(dict.fromkeys(connection_dst))        #Exclui elementos repetidos da lista de IP destino
    try:
        connection_src.remove(target_ip)        #Tenta remover o IP alvo da lista de IP fonte
    except:
        print('[*] %s is not on the source list' %target_ip)        #Falha em remover o IP alvo da lista de IP fonte
    try:
        connection_dst.remove(target_ip)        #Tenta remover o IP alvo da lista de IP destino
    except:
        print('[*] %s is not on the destination list' %target_ip)       #Falha em remover o IP alvo da lista de IP destino
    x = len(connection_dst)     #Seta a variável X com o tamanho da lista de IP fonte
    y = len(connection_src)     #Seta a variável Y com o tamanho da lista de IP destino

    print('-------------------------------------------------------------------')
    print('[*] There are %i source IP!!!' %y)       #Mostra a quantidade de IPs fonte
    print(connection_src)       #Mostra todos os IPs fonte
    print('-------------------------------------------------------------------')
    print('[*] There are %i destination IP!!!' %x)      #Mostra a quantidade de IPs destino
    print(connection_dst)       #Mostra todos os IPs destino
    print('-------------------------------------------------------------------')
    print('[*] Upload/Download analysis')

    connection_array = connection_dst       #Seta connection_array como uma cópia da lista de IP destino
    for i in range(y):
        connection_array.append(connection_src[i])      #Copia a lista de IP fonte para connection_array
    connection_array = list(dict.fromkeys(connection_array))        #Remove elementos repetidos de connection_array

    for i in range(len(connection_array)):
        flagsrc = 0
        flagdst = 0
        for j in range(len(packet_list)):
            if packet_list[j].haslayer(TCP):        #Verifica se o pacote tem cabeçalho TCP
                if packet_list[j][IP].src == connection_array[i]:       #Verifica se o IP fez upload
                    flagsrc += 1
                elif packet_list[j][IP].dst == connection_array[i]:     #Verifica se o IP fez download
                    flagdst += 1
        print('-------------------------------------------------------------------')
        print('[*] The IP %s uploaded %i and downloaded %i packets!!!' %(connection_array[i], flagsrc, flagdst))    #Mostra a quantidade de uploads/downloads do IP
        if(flagsrc > flagdst):      #Verifica se o IP é um uploader
            mostly_updloader.append(connection_array[i])        #Adiciona o IP a lista de uploaders

    print('-------------------------------------------------------------------')
    print('[*] There are %i IP that upload more than download!!!' %len(mostly_updloader))       #Mostra a quantidade de uploaders
    for i in range(len(mostly_updloader)):
        print('=> %s' %mostly_updloader[i])         #Mostra todos os IPs dos uploaders
    print('-------------------------------------------------------------------') 