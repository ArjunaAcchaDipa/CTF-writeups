from pwn import *

host = "server.challenge.ctf.thefewchosen.com"
port = 1342

secret = 0xaabbccddaabbccdd

# s = process("./secret")
s = remote(host, port)

print(s.recvline())
s.sendline(p64(secret))
print(s.recvall().decode())

s.close()