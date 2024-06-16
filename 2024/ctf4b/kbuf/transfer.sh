#!/bin/sh -eux
musl-gcc exploit.c -o exploit -static
strip exploit
mv exploit mount/exploit

cd mount; find -print0 | cpio -o --null --format=newc --owner=root > ../rootfs_update.cpio
cd ..

qemu-system-x86_64 \
     -m 64M \
     -nographic \
     -kernel bzImage \
     -initrd rootfs_update.cpio \
     -drive file=flag.txt,format=raw \
     -snapshot \
     -append "console=ttyS0 loglevel=3 oops=panic panic=-1 pti=on kaslr root=/dev/sda" \
     -no-reboot \
     -cpu qemu64,+smap,+smep \
     -monitor /dev/null \
     -net nic,model=virtio \
     -net user \
     -gdb tcp::1234