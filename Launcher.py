# -*- coding: utf-8 -*-
from PcaPreter import pcapreter
from Netzpoofer import netzpoofer

def main():
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('[*]                                                                           [*]')
    print('[*] Ferramenta para auxílio em perícia forense e análise de tráfego em redes  [*]')
    print('[*] Criado por: Fernando de Souza Vasconcelos                                 [*]')
    print('[*] Orientador: Douglas Fabiano de Sousa Nunes                                [*]')
    print('[*] Versão: 1.0.0                                                             [*]')
    print('[*] Github: @Default37                                                        [*]')
    print('[*]                                                                           [*]')
    print('[*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*][*]')
    print('')
    menu()
    
def menu():
    print('[*] SELECIONE UMA OPÇÃO PARA CONTINUAR')
    print('[1] Netzpoofer')
    print('[2] Pcapreter')
    print('[3] Sair')
    print('[?] Ajuda')
    print('-------------------------------------------------------------------')
    menu = raw_input('Seleção: ')
    if(menu == '1'):
        netzpoofer()
    elif(menu == '2'):
        pcapreter()
    else:
        help()

def help():
    print('-------------------------------------------------------------------')
    print('[1] O Netzpoofer é uma ferramenta que auxilia o usuário na captura do tráfego da rede')
    print('[2] O Pcapreter auxilia o usuário a interpretar arquivos .pcap')
    print('-------------------------------------------------------------------')
    menu()


main()