#Não executável pelo Jupyter

'''
Nome: Davi Francisco da Silva   RA: 2215112577
Nome: Guilherme Bueno Martins   RA: 915126805
Nome: Guilherme Souza Alvez     RA: 915120882
Nome: Jessé Levandovski         RA: 915122452
Nome: Pedro Henrique Artur Soma RA: 415111375
'''

import socket

#The public network interface
HOST ='127.0.0.1'  #socket.gethostbyname(socket.gethostname())

#create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind((HOST, 0))

#Include IP headers
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)


#receive a package
while True:
    data = s.recvfrom(61655)
    print('Packet: ', data[0])
    print('\nOrigem: ', data[-1])
    #Creating an web page
    file = open('sniffing.html', 'wt')
    file.write('<html> \n')
    file.write('<head><title>Sniffing</title></head>\n')
    file.write('<body><h2> Sniffing receving packets: </h2>\n')
    file.write('<br><br><p><b>Packet:</b></p>\n')
    file.write('<p>'+str(s.recvfrom(61565,)[0])+'</p>\n')
    file.write('<br><br><p><b>Source:</b> '+str(s.recvfrom(65565)[-1])+'</p>\n')
    file.write('</body>\n</html>')
    #Saving the page
    file.close()
   

print('Exiting...\n')

#Fonts:
# https://docs.python.org/3.6/library/socket.html
# https://stackoverflow.com/questions/462439/packet-sniffing-in-python-windows
