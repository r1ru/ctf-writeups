from pwn import *
import base64

def run(cmd):
    io.sendlineafter(b'$ ', cmd.encode())
    io.recvline()

with open(sys.argv[1], "rb") as f:
    payload = base64.b64encode(f.read()).decode()

io = remote("kbuf.beginners.seccon.games", 9999)

cmd = io.recvline()
print(cmd)
io.sendlineafter(b':', input().encode())

run('cd /tmp')

log.info("uploading...")

for i in range(0, len(payload), 512):
    print(f"uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')

io.interactive()